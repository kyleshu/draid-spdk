#include "bdev_raid.h"

#include "spdk/config.h"
#include "spdk/env.h"
#include "spdk/thread.h"
#include "spdk/likely.h"
#include "spdk/string.h"
#include "spdk/util.h"

#include "spdk/log.h"

#include "isa-l/include/raid.h"
#include "isa-l/include/gf_vect_mul.h"
#include "isa-l/include/erasure_code.h"

#include <rte_hash.h>
#include <rte_memory.h>

struct stripe_request {
    /* The associated raid_bdev_io */
    struct raid_bdev_io *raid_io;

    /* The target stripe */
    struct stripe *stripe;

    /* Counter for remaining chunk requests */
    int remaining;

    /* Status of the request */
    enum spdk_bdev_io_status status;

    /* Function to call when all remaining chunk requests have completed */
    void (*chunk_requests_complete_cb)(struct stripe_request *);

    /* Offset into the parent bdev_io iovecs */
    uint64_t iov_offset;

    /* Initial iov_offset */
    uint64_t init_iov_offset;

    /* First data chunk applicable to this request */
    struct chunk *first_data_chunk;

    /* Last data chunk applicable to this request */
    struct chunk *last_data_chunk;

    /* The stripe's parity chunk */
    struct chunk *parity_chunk;

    /* The stripe's q chunk */
    struct chunk *q_chunk;

    /* degrade mode*/
    enum stripe_degraded_type {
        DEGRADED_D,
        DEGRADED_DP,
        DEGRADED_DD,
        NORMAL,
    } degraded_type;

    /* Degraded chunk */
    struct chunk *degraded_chunks[2];

    /* Link for the stripe's requests list */
    TAILQ_ENTRY(stripe_request) link;

    /* Array of chunks corresponding to base_bdevs */
    struct chunk {
        /* Corresponds to base_bdev index */
        uint8_t index;

        /* Request offset from chunk start */
        uint64_t req_offset;

        /* Request blocks count */
        uint64_t req_blocks;

        /* Preread offset from chunk start */
        uint64_t preread_offset;

        /* Preread blocks count */
        uint64_t preread_blocks;

        /* The iovecs associated with the chunk request */
        struct iovec *iovs;

        /* The number of iovecs */
        int iovcnt;

        /* A single iovec for non-SG buffer request cases */
        struct iovec iov;

        bool is_degraded;

        /* The type of chunk request */
        enum chunk_request_type {
            CHUNK_READ,
            CHUNK_WRITE,
            CHUNK_PREREAD,
        } request_type;

        /* For retrying base bdev IOs in case submit fails with -ENOMEM */
        struct spdk_bdev_io_wait_entry waitq_entry;
    } chunks[0];
};

struct stripe {
    /* The stripe's index in the raid array. Also a key for the hash table. */
    uint64_t index;

    /* Hashed key value */
    hash_sig_t hash;

    /* List of requests queued for this stripe */
    TAILQ_HEAD(requests_head, stripe_request) requests;

    /* Protects the requests list */
    pthread_spinlock_t requests_lock; // Note: acquire lock when accessing request queue

    /* Stripe can be reclaimed if this reaches 0 */
    unsigned int refs;

    /* Link for the active/free stripes lists */
    TAILQ_ENTRY(stripe) link;

    /* Array of buffers for chunk parity/preread data */
    void **chunk_buffers;

    void **tmp_buffers;
};

struct raid6_info {
    /* The parent raid bdev */
    struct raid_bdev *raid_bdev;

    /* Number of data blocks in a stripe (without parity) */
    uint64_t stripe_blocks;

    /* Number of stripes on this array */
    uint64_t total_stripes;

    /* Mempool for stripe_requests */
    struct spdk_mempool *stripe_request_mempool;

    /* Pointer to an array of all available stripes */
    struct stripe *stripes;

    /* Hash table containing currently active stripes */
    struct rte_hash *active_stripes_hash; // Note: DPDK's implementation of hash table

    unsigned char gf_const_tbl_arr[255][32];

    unsigned char gf_const_tbl_arr_a[255][32];

    unsigned char gf_const_tbl_arr_b[255][255][32];

    /* List of active stripes (in hash table) */
    TAILQ_HEAD(active_stripes_head, stripe) active_stripes;

    /* List of free stripes (not in hash table) */
    TAILQ_HEAD(, stripe) free_stripes;

    /* Lock protecting the stripes hash and lists */
    pthread_spinlock_t active_stripes_lock;
};

struct raid6_io_channel {
    TAILQ_HEAD(, spdk_bdev_io_wait_entry) retry_queue;
};

#define FOR_EACH_CHUNK(req, c) \
	for (c = req->chunks; \
	     c < req->chunks + req->raid_io->raid_bdev->num_base_bdevs; c++)

#define __NEXT_DATA_CHUNK(req, c) \
	c+1 == req->parity_chunk ? c+3 : (c+1 == req->q_chunk ? c+2 :c+1)

#define FOR_EACH_DATA_CHUNK(req, c) \
	for (c = __NEXT_DATA_CHUNK(req, req->chunks-1); \
	     c < req->chunks + req->raid_io->raid_bdev->num_base_bdevs; \
	     c = __NEXT_DATA_CHUNK(req, c))

static inline struct stripe_request *
raid6_chunk_stripe_req(struct chunk *chunk)
{
    return SPDK_CONTAINEROF((chunk - chunk->index), struct stripe_request, chunks);
}

static inline uint8_t
raid6_chunk_data_index(struct chunk *chunk)
{
    uint8_t diff = 0;
    if (chunk > raid6_chunk_stripe_req(chunk)->parity_chunk) {
        diff++;
    }
    if (chunk > raid6_chunk_stripe_req(chunk)->q_chunk) {
        diff++;
    }
    return chunk->index - diff;
}

static inline struct chunk *
raid6_get_data_chunk(struct stripe_request *stripe_req, uint8_t chunk_data_idx)
{
    uint8_t p_chunk_idx = stripe_req->parity_chunk - stripe_req->chunks;
    uint8_t q_chunk_idx = stripe_req->q_chunk - stripe_req->chunks;
    if (q_chunk_idx < p_chunk_idx) {
        return &stripe_req->chunks[chunk_data_idx + 1];
    } else {
        if (chunk_data_idx < p_chunk_idx) {
            return &stripe_req->chunks[chunk_data_idx];
        } else {
            return &stripe_req->chunks[chunk_data_idx + 2];
        }
    }
}

static inline uint8_t
raid6_stripe_data_chunks_num(const struct raid_bdev *raid_bdev)
{
    return raid_bdev->num_base_bdevs - raid_bdev->module->base_bdevs_max_degraded;
}

static void
raid6_xor_buf(void *restrict to, void *restrict from, size_t size)
{
    int ret;
    void *vects[3] = { from, to, to };

    ret = xor_gen(3, size, vects);
    if (ret) {
        SPDK_ERRLOG("xor_gen failed\n");
    }
}

static void
raid6_gf_mul(unsigned char *gf_const_tbl, void *to, void *from, size_t size) {
    gf_vect_mul(size, gf_const_tbl, from, to);
}

static void
raid6_q_gen(struct raid6_info* r6info, uint8_t index, void *to, void *from, size_t size) {
    unsigned char gf_const_tbl = r6info->gf_const_tbl_arr[index];
    gf_vect_mul(size, gf_const_tbl, from, to);
}

static void
raid6_gf_mul_iovs(struct iovec *iovs_dest, int iovs_dest_cnt, size_t iovs_dest_offset,
                 const struct iovec *iovs_src, int iovs_src_cnt, size_t iovs_src_offset,
                 size_t size, unsigned char *gf_const_tbl)
{
    struct iovec *v1;
    const struct iovec *v2;
    size_t off1, off2;
    size_t n;

    v1 = iovs_dest;
    v2 = iovs_src;

    n = 0;
    off1 = 0;
    while (v1 < iovs_dest + iovs_dest_cnt) {
        n += v1->iov_len;
        if (n > iovs_dest_offset) {
            off1 = v1->iov_len - (n - iovs_dest_offset);
            break;
        }
        v1++;
    }

    n = 0;
    off2 = 0;
    while (v2 < iovs_src + iovs_src_cnt) {
        n += v2->iov_len;
        if (n > iovs_src_offset) {
            off2 = v2->iov_len - (n - iovs_src_offset);
            break;
        }
        v2++;
    }

    while (v1 < iovs_dest + iovs_dest_cnt &&
           v2 < iovs_src + iovs_src_cnt &&
           size > 0) {
        n = spdk_min(v1->iov_len - off1, v2->iov_len - off2);

        if (n > size) {
            n = size;
        }

        size -= n;

        raid6_gf_mul(gf_const_tbl, v1->iov_base + off1, v2->iov_base + off2, n);

        off1 += n;
        off2 += n;

        if (off1 == v1->iov_len) {
            off1 = 0;
            v1++;
        }

        if (off2 == v2->iov_len) {
            off2 = 0;
            v2++;
        }
    }
}

static void
raid6_q_gen_iovs(struct iovec *iovs_dest, int iovs_dest_cnt, size_t iovs_dest_offset,
               const struct iovec *iovs_src, int iovs_src_cnt, size_t iovs_src_offset,
               size_t size, struct raid6_info* r6info, uint8_t index)
{
    struct iovec *v1;
    const struct iovec *v2;
    size_t off1, off2;
    size_t n;

    v1 = iovs_dest;
    v2 = iovs_src;

    n = 0;
    off1 = 0;
    while (v1 < iovs_dest + iovs_dest_cnt) {
        n += v1->iov_len;
        if (n > iovs_dest_offset) {
            off1 = v1->iov_len - (n - iovs_dest_offset);
            break;
        }
        v1++;
    }

    n = 0;
    off2 = 0;
    while (v2 < iovs_src + iovs_src_cnt) {
        n += v2->iov_len;
        if (n > iovs_src_offset) {
            off2 = v2->iov_len - (n - iovs_src_offset);
            break;
        }
        v2++;
    }

    while (v1 < iovs_dest + iovs_dest_cnt &&
           v2 < iovs_src + iovs_src_cnt &&
           size > 0) {
        n = spdk_min(v1->iov_len - off1, v2->iov_len - off2);

        if (n > size) {
            n = size;
        }

        size -= n;

        raid6_q_gen(r6info, index, v1->iov_base + off1, v2->iov_base + off2, n);

        off1 += n;
        off2 += n;

        if (off1 == v1->iov_len) {
            off1 = 0;
            v1++;
        }

        if (off2 == v2->iov_len) {
            off2 = 0;
            v2++;
        }
    }
}

static void
raid6_xor_iovs(struct iovec *iovs_dest, int iovs_dest_cnt, size_t iovs_dest_offset,
               const struct iovec *iovs_src, int iovs_src_cnt, size_t iovs_src_offset,
               size_t size)
{
    struct iovec *v1;
    const struct iovec *v2;
    size_t off1, off2;
    size_t n;

    v1 = iovs_dest;
    v2 = iovs_src;

    n = 0;
    off1 = 0;
    while (v1 < iovs_dest + iovs_dest_cnt) {
        n += v1->iov_len;
        if (n > iovs_dest_offset) {
            off1 = v1->iov_len - (n - iovs_dest_offset);
            break;
        }
        v1++;
    }

    n = 0;
    off2 = 0;
    while (v2 < iovs_src + iovs_src_cnt) {
        n += v2->iov_len;
        if (n > iovs_src_offset) {
            off2 = v2->iov_len - (n - iovs_src_offset);
            break;
        }
        v2++;
    }

    while (v1 < iovs_dest + iovs_dest_cnt &&
           v2 < iovs_src + iovs_src_cnt &&
           size > 0) {
        n = spdk_min(v1->iov_len - off1, v2->iov_len - off2);

        if (n > size) {
            n = size;
        }

        size -= n;

        raid6_xor_buf(v1->iov_base + off1, v2->iov_base + off2, n);

        off1 += n;
        off2 += n;

        if (off1 == v1->iov_len) {
            off1 = 0;
            v1++;
        }

        if (off2 == v2->iov_len) {
            off2 = 0;
            v2++;
        }
    }
}

static void
raid6_memset_iovs(struct iovec *iovs, int iovcnt, char c)
{
    struct iovec *iov;

    for (iov = iovs; iov < iovs + iovcnt; iov++) {
        memset(iov->iov_base, c, iov->iov_len);
    }
}

static void
raid6_memcpy_iovs(struct iovec *iovs_dest, int iovs_dest_cnt, size_t iovs_dest_offset,
                  const struct iovec *iovs_src, int iovs_src_cnt, size_t iovs_src_offset,
                  size_t size)
{
    struct iovec *v1;
    const struct iovec *v2;
    size_t off1, off2;
    size_t n;

    v1 = iovs_dest;
    v2 = iovs_src;

    n = 0;
    off1 = 0;
    while (v1 < iovs_dest + iovs_dest_cnt) {
        n += v1->iov_len;
        if (n > iovs_dest_offset) {
            off1 = v1->iov_len - (n - iovs_dest_offset);
            break;
        }
        v1++;
    }

    n = 0;
    off2 = 0;
    while (v2 < iovs_src + iovs_src_cnt) {
        n += v2->iov_len;
        if (n > iovs_src_offset) {
            off2 = v2->iov_len - (n - iovs_src_offset);
            break;
        }
        v2++;
    }

    while (v1 < iovs_dest + iovs_dest_cnt &&
           v2 < iovs_src + iovs_src_cnt &&
           size > 0) {
        n = spdk_min(v1->iov_len - off1, v2->iov_len - off2);

        if (n > size) {
            n = size;
        }

        size -= n;

        memcpy(v1->iov_base + off1, v2->iov_base + off2, n);

        off1 += n;
        off2 += n;

        if (off1 == v1->iov_len) {
            off1 = 0;
            v1++;
        }

        if (off2 == v2->iov_len) {
            off2 = 0;
            v2++;
        }
    }
}

static int
raid6_chunk_map_iov(struct chunk *chunk, const struct iovec *iov, int iovcnt,
                    uint64_t offset, uint64_t len)
{
    int i;
    size_t off = 0;
    int start_v = -1;
    size_t start_v_off;
    int new_iovcnt = 0;

    // Note: find the start iov
    for (i = 0; i < iovcnt; i++) {
        if (off + iov[i].iov_len > offset) {
            start_v = i;
            break;
        }
        off += iov[i].iov_len;
    }

    if (start_v == -1) {
        return -EINVAL;
    }

    start_v_off = off;

    // Note: find the end iov
    for (i = start_v; i < iovcnt; i++) {
        new_iovcnt++;

        if (off + iov[i].iov_len >= offset + len) {
            break;
        }
        off += iov[i].iov_len;
    }

    assert(start_v + new_iovcnt <= iovcnt);

    // Note: dynamically change size of iovs
    if (new_iovcnt > chunk->iovcnt) {
        void *tmp;

        if (chunk->iovs == &chunk->iov) {
            chunk->iovs = NULL;
        }
        tmp = realloc(chunk->iovs, new_iovcnt * sizeof(struct iovec));
        if (!tmp) {
            return -ENOMEM;
        }
        chunk->iovs = tmp;
    }
    chunk->iovcnt = new_iovcnt;

    off = start_v_off;
    iov += start_v;

    // Note: set up iovs from iovs from bdev_io
    for (i = 0; i < new_iovcnt; i++) {
        chunk->iovs[i].iov_base = iov->iov_base + (offset - off);
        chunk->iovs[i].iov_len = spdk_min(len, iov->iov_len - (offset - off));

        off += iov->iov_len;
        iov++;
        offset += chunk->iovs[i].iov_len;
        len -= chunk->iovs[i].iov_len;
    }

    if (len > 0) {
        return -EINVAL;
    }

    return 0;
}

static int
raid6_chunk_map_req_data(struct chunk *chunk)
{
    struct stripe_request *stripe_req = raid6_chunk_stripe_req(chunk);
    struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(stripe_req->raid_io);
    uint64_t len = chunk->req_blocks * bdev_io->bdev->blocklen;
    int ret;

    if (len == 0) {
        return 0;
    }

    ret = raid6_chunk_map_iov(chunk, bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
                              stripe_req->iov_offset, len);
    if (ret == 0) {
        stripe_req->iov_offset += len;
    }

    return ret;
}

static void
raid6_io_channel_retry_request(struct raid6_io_channel *r6ch)
{
    struct spdk_bdev_io_wait_entry *waitq_entry;

    waitq_entry = TAILQ_FIRST(&r6ch->retry_queue);
    assert(waitq_entry != NULL);
    TAILQ_REMOVE(&r6ch->retry_queue, waitq_entry, link);
    waitq_entry->cb_fn(waitq_entry->cb_arg);
}

static void
raid6_submit_stripe_request(struct stripe_request *stripe_req);

static void
_raid6_submit_stripe_request(void *_stripe_req)
{
    struct stripe_request *stripe_req = _stripe_req;

    raid6_submit_stripe_request(stripe_req);
}

static void
raid6_stripe_request_put(struct stripe_request *stripe_req)
{
    struct raid6_info *r6info = stripe_req->raid_io->raid_bdev->module_private;
    struct chunk *chunk;

    FOR_EACH_CHUNK(stripe_req, chunk) {
        if (chunk->iovs != &chunk->iov) {
            free(chunk->iovs);
        }
    }

    spdk_mempool_put(r6info->stripe_request_mempool, stripe_req);
}

static void
raid6_complete_stripe_request(struct stripe_request *stripe_req)
{
    struct stripe *stripe = stripe_req->stripe;
    struct raid_bdev_io *raid_io = stripe_req->raid_io;
    enum spdk_bdev_io_status status = stripe_req->status;
    struct raid6_io_channel *r6ch = raid_bdev_io_channel_get_resource(raid_io->raid_ch);
    struct stripe_request *next_req;
    struct chunk *chunk;
    uint64_t req_blocks;

    // Note: if next request available, submit it
    pthread_spin_lock(&stripe->requests_lock);
    next_req = TAILQ_NEXT(stripe_req, link);
    TAILQ_REMOVE(&stripe->requests, stripe_req, link);
    pthread_spin_unlock(&stripe->requests_lock);
    if (next_req) {
        spdk_thread_send_msg(spdk_io_channel_get_thread(spdk_io_channel_from_ctx(
                                     next_req->raid_io->raid_ch)),
                             _raid6_submit_stripe_request, next_req);
    }

    req_blocks = 0;
    FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
        req_blocks += chunk->req_blocks;
    }

    raid6_stripe_request_put(stripe_req);

    if (raid_bdev_io_complete_part(raid_io, req_blocks, status)) {
        __atomic_fetch_sub(&stripe->refs, 1, __ATOMIC_SEQ_CST);

        if (!TAILQ_EMPTY(&r6ch->retry_queue)) {
            raid6_io_channel_retry_request(r6ch);
        }
    }
}

static inline enum spdk_bdev_io_status errno_to_status(int err)
{
    err = abs(err);
    switch (err) {
        case 0:
            return SPDK_BDEV_IO_STATUS_SUCCESS;
        case ENOMEM:
            return SPDK_BDEV_IO_STATUS_NOMEM;
        default:
            return SPDK_BDEV_IO_STATUS_FAILED;
    }
}

static void
raid6_abort_stripe_request(struct stripe_request *stripe_req, enum spdk_bdev_io_status status)
{
    stripe_req->remaining = 0;
    stripe_req->status = status;
    raid6_complete_stripe_request(stripe_req);
}

static void
raid6_complete_stripe_read_request_d(struct stripe_request *stripe_req)
{
    struct chunk *chunk;
    int ret;
    struct chunk *d_chunk = stripe_req->degraded_chunks[0];
    struct chunk *q_chunk = stripe_req->q_chunk;
    uint32_t blocklen = stripe_req->raid_io->raid_bdev->bdev.blocklen;
    size_t src_offset;
    uint64_t len;
    struct iovec *preread_iovs;
    int preread_iovcnt;

    SPDK_NOTICELOG("reconstructed read complete\n");
    // Note: construct d_chunk
    raid6_memset_iovs(d_chunk->iovs, d_chunk->iovcnt, 0);
    FOR_EACH_CHUNK(stripe_req, chunk) {
        if (chunk != d_chunk && chunk != q_chunk) {
            if (chunk->request_type == CHUNK_PREREAD) {
                src_offset = (d_chunk->req_offset - chunk->preread_offset) * blocklen;
            } else {
                src_offset = (d_chunk->req_offset - chunk->req_offset) * blocklen;
            }
            raid6_xor_iovs(d_chunk->iovs, d_chunk->iovcnt, 0,
                           chunk->iovs, chunk->iovcnt, src_offset,
                           d_chunk->req_blocks * blocklen);
        }
    }

    // Note: copy data chunk if necessary
    stripe_req->iov_offset = stripe_req->init_iov_offset;
    FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
        len = chunk->req_blocks * blocklen;
        if (chunk->req_blocks > 0 && chunk != d_chunk && chunk->request_type == CHUNK_PREREAD) {
            preread_iovs = chunk->iovs;
            preread_iovcnt = chunk->iovcnt;
            ret = raid6_chunk_map_req_data(chunk);
            if (ret) {
                raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
            }
            src_offset = (chunk->req_offset - chunk->preread_offset) * blocklen;
            raid6_memcpy_iovs(chunk->iovs, chunk->iovcnt, 0,
                              preread_iovs, preread_iovcnt, src_offset,
                              chunk->req_blocks * blocklen);
        } else {
            stripe_req->iov_offset += len;
        }
    }

    // Note: all chunks are ready
    raid6_complete_stripe_request(stripe_req);
}

static void
raid6_complete_stripe_read_request_dp(struct stripe_request *stripe_req)
{
    struct chunk *chunk;
    int ret;
    struct chunk *d_chunk = stripe_req->degraded_chunks[0];
    struct chunk *q_chunk = stripe_req->q_chunk;
    struct chunk *p_chunk = stripe_req->parity_chunk;
    uint32_t blocklen = stripe_req->raid_io->raid_bdev->bdev.blocklen;
    struct raid6_info *r6info = stripe_req->raid_io->raid_bdev->module_private;
    void *d_chunk_buf = stripe_req->stripe->chunk_buffers[d_chunk->index];
    void *tmp_buf0 = stripe_req->stripe->tmp_buffers[0];
    size_t src_offset;
    uint64_t len;
    struct iovec *preread_iovs;
    int preread_iovcnt;
    struct iovec iov0 = {
            .iov_base = d_chunk_buf,
            .iov_len = raid_bdev->strip_size << raid_bdev->blocklen_shift,
    };
    struct iovec iov1 = {
            .iov_base = tmp_buf0,
            .iov_len = raid_bdev->strip_size << raid_bdev->blocklen_shift,
    };

    SPDK_NOTICELOG("reconstructed read complete\n");
    // Note: construct d_chunk
    raid6_memset_iovs(&iov0, 1, 0);
    FOR_EACH_CHUNK(stripe_req, chunk) {
        if (chunk != d_chunk && chunk != p_chunk) {
            if (chunk->request_type == CHUNK_PREREAD) {
                src_offset = (d_chunk->req_offset - chunk->preread_offset) * blocklen;
            } else {
                src_offset = (d_chunk->req_offset - chunk->req_offset) * blocklen;
            }
            if (chunk == q_chunk) {
                raid6_xor_iovs(&iov0, 1, 0,
                               chunk->iovs, chunk->iovcnt, src_offset,
                               d_chunk->req_blocks * blocklen);
            } else {
                raid6_q_gen_iovs(&iov1, 1, 0,
                                 chunk->iovs, chunk->iovcnt, src_offset,
                                 d_chunk->req_blocks * blocklen, r6info, raid6_chunk_data_index(chunk));
                raid6_xor_iovs(&iov0, 1, 0,
                               &iov1, 1, 0,
                               d_chunk->req_blocks * blocklen);
            }
        }
    }
    raid6_q_gen_iovs(d_chunk->iovs, d_chunk->iovcnt, 0,
                     &iov0, 1, 0,
                     d_chunk->req_blocks * blocklen, r6info, 255 - raid6_chunk_data_index(d_chunk));

    // Note: copy data chunk if necessary
    stripe_req->iov_offset = stripe_req->init_iov_offset;
    FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
        len = chunk->req_blocks * blocklen;
        if (chunk->req_blocks > 0 && chunk != d_chunk && chunk->request_type == CHUNK_PREREAD) {
            preread_iovs = chunk->iovs;
            preread_iovcnt = chunk->iovcnt;
            ret = raid6_chunk_map_req_data(chunk);
            if (ret) {
                raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
            }
            src_offset = (chunk->req_offset - chunk->preread_offset) * blocklen;
            raid6_memcpy_iovs(chunk->iovs, chunk->iovcnt, 0,
                              preread_iovs, preread_iovcnt, src_offset,
                              chunk->req_blocks * blocklen);
        } else {
            stripe_req->iov_offset += len;
        }
    }

    // Note: all chunks are ready
    raid6_complete_stripe_request(stripe_req);
}

static void
raid6_complete_stripe_read_request_dd(struct stripe_request *stripe_req)
{
    struct chunk *chunk;
    int ret;
    struct chunk *d_chunk_x;
    struct chunk *d_chunk_y;
    struct chunk *q_chunk = stripe_req->q_chunk;
    struct chunk *p_chunk = stripe_req->parity_chunk;
    uint32_t blocklen = stripe_req->raid_io->raid_bdev->bdev.blocklen;
    struct raid6_info *r6info = stripe_req->raid_io->raid_bdev->module_private;
    size_t src_offset;
    uint64_t len;
    struct iovec *preread_iovs;
    int preread_iovcnt;

    if (stripe_req->degraded_chunks[0]->index > stripe_req->degraded_chunks[1]->index) {
        d_chunk_y = stripe_req->degraded_chunks[0];
        d_chunk_x = stripe_req->degraded_chunks[1];
    } else {
        d_chunk_y = stripe_req->degraded_chunks[1];
        d_chunk_x = stripe_req->degraded_chunks[0];
    }
    uint64_t req_offset = spdk_min(d_chunk_x->req_offset, d_chunk_y->req_offset);
    uint64_t req_blocks = spdk_max(d_chunk_x->req_offset + d_chunk_x->req_blocks,
                                   d_chunk_y->req_offset + d_chunk_y->req_blocks) - req_offset;
    unsigned char *gf_const_tbl_a = r6info->gf_const_tbl_arr_a
            [raid6_chunk_data_index(d_chunk_y) - raid6_chunk_data_index(d_chunk_x)];
    unsigned char *gf_const_tbl_b = r6info->gf_const_tbl_arr_b
            [raid6_chunk_data_index(d_chunk_y) - raid6_chunk_data_index(d_chunk_x)]
            [255 - raid6_chunk_data_index(d_chunk_x)];

    void *d_chunk_buf_x = stripe_req->stripe->chunk_buffers[d_chunk_x->index];
    void *d_chunk_buf_y = stripe_req->stripe->chunk_buffers[d_chunk_y->index];
    void *tmp_buf0 = stripe_req->stripe->tmp_buffers[0];
    void *tmp_buf1 = stripe_req->stripe->tmp_buffers[1];
    struct iovec iov_x = {
            .iov_base = d_chunk_buf_x,
            .iov_len = raid_bdev->strip_size << raid_bdev->blocklen_shift,
    };
    struct iovec iov_y = {
            .iov_base = d_chunk_buf_y,
            .iov_len = raid_bdev->strip_size << raid_bdev->blocklen_shift,
    };
    struct iovec iov_tmp0 = {
            .iov_base = tmp_buf0,
            .iov_len = raid_bdev->strip_size << raid_bdev->blocklen_shift,
    };
    struct iovec iov_tmp1 = {
            .iov_base = tmp_buf1,
            .iov_len = raid_bdev->strip_size << raid_bdev->blocklen_shift,
    };

    SPDK_NOTICELOG("reconstructed read complete\n");
    // Note: construct d_chunk_x
    raid6_memset_iovs(&iov_y, 1, 0);
    raid6_memset_iovs(&iov_tmp0, 1, 0);
    FOR_EACH_CHUNK(stripe_req, chunk) {
        if (!chunk->is_degraded) {
            if (chunk->request_type == CHUNK_PREREAD) {
                src_offset = (req_offset - chunk->preread_offset) * blocklen;
            } else {
                src_offset = (req_offset - chunk->req_offset) * blocklen;
            }

            if (chunk == p_chunk) {
                raid6_xor_iovs(&iov_y, 1, 0,
                               chunk->iovs, chunk->iovcnt, src_offset,
                               req_blocks * blocklen);
            } else if (chunk == q_chunk) {
                raid6_xor_iovs(&iov_tmp0, 1, 0,
                               chunk->iovs, chunk->iovcnt, src_offset,
                               req_blocks * blocklen);
            } else {
                raid6_xor_iovs(&iov_y, 1, 0,
                               chunk->iovs, chunk->iovcnt, src_offset,
                               req_blocks * blocklen);
                raid6_q_gen_iovs(&iov_tmp1, 1, 0,
                                 chunk->iovs, chunk->iovcnt, src_offset,
                                 req_blocks * blocklen, r6info, raid6_chunk_data_index(chunk));
                raid6_xor_iovs(&iov_tmp0, 1, 0,
                               &iov_tmp1, 1, 0,
                               req_blocks * blocklen);
            }
        }
    }
    raid6_gf_mul_iovs(&iov_x, 1, 0,
                      &iov_y, 1, 0,
                      req_blocks * blocklen, gf_const_tbl_a);
    raid6_gf_mul_iovs(&iov_tmp1, 1, 0,
                      &iov_tmp0, 1, 0,
                      req_blocks * blocklen, gf_const_tbl_b);
    raid6_xor_iovs(&iov_x, 1, 0,
                   &iov_tmp1, 1, 0,
                   req_blocks * blocklen);

    // Note: construct d_chunk_y
    raid6_xor_iovs(&iov_y, 1, 0,
                   &iov_x, 1, 0,
                   req_blocks * blocklen);

    if (d_chunk_x->req_blocks > 0) {
        src_offset = (d_chunk_x->req_offset - req_offset) * blocklen;
        raid6_memcpy_iovs(d_chunk_x->iovs, d_chunk_x->iovcnt, 0,
                          &iov_x, 1, src_offset,
                          d_chunk_x->req_blocks * blocklen);
    }
    if (d_chunk_y->req_blocks > 0) {
        src_offset = (d_chunk_y->req_offset - req_offset) * blocklen;
        raid6_memcpy_iovs(d_chunk_y->iovs, d_chunk_y->iovcnt, 0,
                          &iov_y, 1, src_offset,
                          d_chunk_y->req_blocks * blocklen);
    }

    // Note: copy data chunk if necessary
    stripe_req->iov_offset = stripe_req->init_iov_offset;
    FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
        len = chunk->req_blocks * blocklen;
        if (chunk->req_blocks > 0 && !chunk->is_degraded && chunk->request_type == CHUNK_PREREAD) {
            preread_iovs = chunk->iovs;
            preread_iovcnt = chunk->iovcnt;
            ret = raid6_chunk_map_req_data(chunk);
            if (ret) {
                raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
            }
            src_offset = (chunk->req_offset - chunk->preread_offset) * blocklen;
            raid6_memcpy_iovs(chunk->iovs, chunk->iovcnt, 0,
                              preread_iovs, preread_iovcnt, src_offset,
                              chunk->req_blocks * blocklen);
        } else {
            stripe_req->iov_offset += len;
        }
    }

    // Note: all chunks are ready
    raid6_complete_stripe_request(stripe_req);
}

static void
raid6_complete_chunk_request(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
    struct chunk *chunk = cb_arg;
    struct stripe_request *stripe_req = raid6_chunk_stripe_req(chunk);

    spdk_bdev_free_io(bdev_io);

    if (!success) {
        stripe_req->status = SPDK_BDEV_IO_STATUS_FAILED;
    }

    if (--stripe_req->remaining == 0) {
        if (stripe_req->status == SPDK_BDEV_IO_STATUS_SUCCESS) {
            stripe_req->chunk_requests_complete_cb(stripe_req);
        } else {
            raid6_complete_stripe_request(stripe_req);
        }
    }
}

static void
_raid6_submit_chunk_request(void *_chunk)
{
    struct chunk *chunk = _chunk;
    struct stripe_request *stripe_req = raid6_chunk_stripe_req(chunk);
    struct raid_bdev_io *raid_io = stripe_req->raid_io;
    struct raid_bdev *raid_bdev = raid_io->raid_bdev;
    struct raid_base_bdev_info *base_info = &raid_bdev->base_bdev_info[chunk->index];
    struct spdk_io_channel *base_ch = raid_io->raid_ch->base_channel[chunk->index];
    uint64_t offset_blocks;
    uint64_t num_blocks;
    enum spdk_bdev_io_type io_type;
    uint64_t base_offset_blocks;
    int ret;

    if (chunk->request_type == CHUNK_PREREAD) {
        offset_blocks = chunk->preread_offset;
        num_blocks = chunk->preread_blocks;
        io_type = SPDK_BDEV_IO_TYPE_READ;
    } else {
        offset_blocks = chunk->req_offset;
        num_blocks = chunk->req_blocks;
        if (chunk->request_type == CHUNK_READ) {
            io_type = SPDK_BDEV_IO_TYPE_READ;
        } else if (chunk->request_type == CHUNK_WRITE) {
            io_type = SPDK_BDEV_IO_TYPE_WRITE;
        } else {
            assert(false);
        }
    }

    base_offset_blocks = (stripe_req->stripe->index << raid_bdev->strip_size_shift) + offset_blocks;

    if (io_type == SPDK_BDEV_IO_TYPE_READ) {
        ret = spdk_bdev_readv_blocks(base_info->desc, base_ch,
                                     chunk->iovs, chunk->iovcnt,
                                     base_offset_blocks, num_blocks,
                                     raid6_complete_chunk_request,
                                     chunk);
    } else {
        ret = spdk_bdev_writev_blocks(base_info->desc, base_ch,
                                      chunk->iovs, chunk->iovcnt,
                                      base_offset_blocks, num_blocks,
                                      raid6_complete_chunk_request,
                                      chunk);
    }

    if (spdk_unlikely(ret != 0)) {
        if (ret == -ENOMEM) {
            struct spdk_bdev_io_wait_entry *wqe = &chunk->waitq_entry;

            wqe->bdev = base_info->bdev;
            wqe->cb_fn = _raid6_submit_chunk_request;
            wqe->cb_arg = chunk;
            spdk_bdev_queue_io_wait(base_info->bdev, base_ch, wqe);
        } else {
            SPDK_ERRLOG("bdev io submit error not due to ENOMEM, it should not happen\n");
            assert(false);
        }
    }
}

static void
raid6_submit_chunk_request(struct chunk *chunk, enum chunk_request_type type)
{
    struct stripe_request *stripe_req = raid6_chunk_stripe_req(chunk);

    stripe_req->remaining++;

    chunk->request_type = type;

    _raid6_submit_chunk_request(chunk);
}

static void
raid6_stripe_write_submit(struct stripe_request *stripe_req)
{
    struct chunk *chunk;

    stripe_req->chunk_requests_complete_cb = raid6_complete_stripe_request;

    FOR_EACH_CHUNK(stripe_req, chunk) {
        if (chunk->req_blocks > 0) {
            raid6_submit_chunk_request(chunk, CHUNK_WRITE);
        }
    }
}

// Note: Read-Modify-Write
static void
raid6_stripe_write_preread_complete_rmw(struct stripe_request *stripe_req)
{
    struct chunk *chunk;
    struct chunk *p_chunk = stripe_req->parity_chunk;
    struct chunk *q_chunk = stripe_req->q_chunk;
    struct raid_bdev *raid_bdev = stripe_req->raid_io->raid_bdev;
    struct raid6_info *r6info = raid_bdev->module_private;
    void *tmp_buf = stripe_req->stripe->tmp_buffers[0];
    struct iovec iov = {
            .iov_base = tmp_buf,
            .iov_len = raid_bdev->strip_size << raid_bdev->blocklen_shift,
    };
    uint32_t blocklen = stripe_req->raid_io->raid_bdev->bdev.blocklen;
    int ret;

    FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
        size_t dest_offset;

        if (chunk->req_blocks == 0) {
            continue;
        }

        dest_offset = (chunk->req_offset - p_chunk->req_offset) * blocklen;

        /* xor old parity with old data... */
        raid6_xor_iovs(p_chunk->iovs, p_chunk->iovcnt, dest_offset,
                       chunk->iovs, chunk->iovcnt, 0,
                       chunk->req_blocks * blocklen);

        /* xor old q with partial q of old data... */
        raid6_q_gen_iovs(&iov, 1, 0,
                         chunk->iovs, chunk->iovcnt, 0,
                         chunk->req_blocks * blocklen, r6info, raid6_chunk_data_index(chunk));
        raid6_xor_iovs(q_chunk->iovs, q_chunk->iovcnt, dest_offset,
                       &iov, 1, 0,
                       chunk->req_blocks * blocklen);


        ret = raid6_chunk_map_req_data(chunk);
        if (ret) {
            raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
            return;
        }

        /* ...and with new data */
        raid6_xor_iovs(p_chunk->iovs, p_chunk->iovcnt, dest_offset,
                       chunk->iovs, chunk->iovcnt, 0,
                       chunk->req_blocks * blocklen);

        /* ...and with partial q of new data */
        raid6_q_gen_iovs(&iov, 1, 0,
                         chunk->iovs, chunk->iovcnt, 0,
                         chunk->req_blocks * blocklen, r6info, raid6_chunk_data_index(chunk));
        raid6_xor_iovs(q_chunk->iovs, q_chunk->iovcnt, dest_offset,
                       &iov, 1, 0,
                       chunk->req_blocks * blocklen);
    }

    raid6_stripe_write_submit(stripe_req);
}

// Note: Reconstruction-Writes + full stripe write
static void
raid6_stripe_write_preread_complete(struct stripe_request *stripe_req)
{
    struct chunk *chunk;
    struct chunk *p_chunk = stripe_req->parity_chunk;
    struct chunk *q_chunk = stripe_req->q_chunk;
    struct raid_bdev *raid_bdev = stripe_req->raid_io->raid_bdev;
    struct raid6_info *r6info = raid_bdev->module_private;
    void *tmp_buf = stripe_req->stripe->tmp_buffers[0];
    struct iovec iov = {
            .iov_base = tmp_buf,
            .iov_len = raid_bdev->strip_size << raid_bdev->blocklen_shift,
    };
    uint32_t blocklen = stripe_req->raid_io->raid_bdev->bdev.blocklen;
    int ret = 0;

    raid6_memset_iovs(p_chunk->iovs, p_chunk->iovcnt, 0);

    FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
        if (chunk->preread_blocks > 0) {
            raid6_xor_iovs(p_chunk->iovs, p_chunk->iovcnt,
                           (chunk->preread_offset - p_chunk->req_offset) * blocklen,
                           chunk->iovs, chunk->iovcnt, 0,
                           chunk->preread_blocks * blocklen);
            raid6_q_gen_iovs(&iov, 1, 0,
                             chunk->iovs, chunk->iovcnt, 0,
                             chunk->preread_blocks * blocklen, r6info, raid6_chunk_data_index(chunk));
            raid6_xor_iovs(q_chunk->iovs, q_chunk->iovcnt,
                           (chunk->preread_offset - q_chunk->req_offset) * blocklen,
                           &iov, 1, 0,
                           chunk->preread_blocks * blocklen);
        }

        if (chunk->req_blocks > 0) {
            ret = raid6_chunk_map_req_data(chunk);
            if (ret) {
                raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
                return;
            }

            raid6_xor_iovs(p_chunk->iovs, p_chunk->iovcnt,
                           (chunk->req_offset - p_chunk->req_offset) * blocklen,
                           chunk->iovs, chunk->iovcnt, 0,
                           chunk->req_blocks * blocklen);
            raid6_q_gen_iovs(&iov, 1, 0,
                             chunk->iovs, chunk->iovcnt, 0,
                             chunk->req_blocks * blocklen, r6info, raid6_chunk_data_index(chunk));
            raid6_xor_iovs(q_chunk->iovs, q_chunk->iovcnt,
                           (chunk->req_offset - q_chunk->req_offset) * blocklen,
                           &iov, 1, 0,
                           chunk->req_blocks * blocklen);
        }
    }

    raid6_stripe_write_submit(stripe_req);
}

static void
raid6_stripe_write(struct stripe_request *stripe_req)
{
    struct raid_bdev *raid_bdev = stripe_req->raid_io->raid_bdev;
    struct chunk *p_chunk = stripe_req->parity_chunk;
    struct chunk *q_chunk = stripe_req->q_chunk;
    struct chunk *chunk;
    int preread_balance = 0;

    // Note: single chunk -> partial parity update; > 1 chunk -> full parity update
    if (stripe_req->first_data_chunk == stripe_req->last_data_chunk) {
        p_chunk->req_offset = stripe_req->first_data_chunk->req_offset;
        p_chunk->req_blocks = stripe_req->first_data_chunk->req_blocks;
        q_chunk->req_offset = stripe_req->first_data_chunk->req_offset;
        q_chunk->req_blocks = stripe_req->first_data_chunk->req_blocks;
    } else {
        p_chunk->req_offset = 0;
        p_chunk->req_blocks = raid_bdev->strip_size;
        q_chunk->req_offset = 0;
        q_chunk->req_blocks = raid_bdev->strip_size;
    }

    // Note: This is the vote process
    // 1. req_blocks == 0: no update, favors rmw
    // 2. 0 < req_blocks < stripe_size: partial update, no preference
    // 3. req_blocks == stripe_size: full update, favors reconstruction write
    FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
        if (chunk->req_blocks < p_chunk->req_blocks) {
            preread_balance++;
        }

        if (chunk->req_blocks > 0) {
            preread_balance--;
        }
    }

    if (preread_balance > 0) {
        stripe_req->chunk_requests_complete_cb = raid6_stripe_write_preread_complete_rmw;
    } else {
        stripe_req->chunk_requests_complete_cb = raid6_stripe_write_preread_complete;
    }

    FOR_EACH_CHUNK(stripe_req, chunk) {
        if (preread_balance > 0) { // Note: for RMW, request chunks are the same as the preread chunks
            chunk->preread_offset = chunk->req_offset;
            chunk->preread_blocks = chunk->req_blocks;
        } else {
            if (chunk == p_chunk || chunk == q_chunk) { // Note: for reconstruction write, no need to read parity
                chunk->preread_offset = 0;
                chunk->preread_blocks = 0;
            } else if (stripe_req->first_data_chunk == stripe_req->last_data_chunk) {
                if (chunk->req_blocks) { // Note: don't read request chunks
                    chunk->preread_offset = 0;
                    chunk->preread_blocks = 0;
                } else { // Note: read non-request chunks
                    chunk->preread_offset = p_chunk->req_offset;
                    chunk->preread_blocks = p_chunk->req_blocks;
                }
            } else {
                if (chunk->req_offset) { // Note: if it's a request chunk and has offset, we need to make it complete
                    chunk->preread_offset = 0;
                    chunk->preread_blocks = chunk->req_offset;
                } else { // Note: if it's a request chunk without offset, we need to make it complete
                    // Note: for non-request chunks, read the full chunk
                    chunk->preread_offset = chunk->req_blocks;
                    chunk->preread_blocks = raid_bdev->strip_size - chunk->req_blocks;
                }
            }
        }

        if (chunk->preread_blocks || chunk == p_chunk || chunk == q_chunk) {
            size_t len;

            if (chunk == p_chunk || chunk == q_chunk) {
                len = chunk->req_blocks * raid_bdev->bdev.blocklen;
            } else {
                len = chunk->preread_blocks * raid_bdev->bdev.blocklen;
            }

            chunk->iov.iov_base = stripe_req->stripe->chunk_buffers[chunk->index];
            chunk->iov.iov_len = len;
        }

        if (chunk->preread_blocks) {
            raid6_submit_chunk_request(chunk, CHUNK_PREREAD);
        }
    }

    // Note: If no preread needs to be done (full stripe), complete immediately
    if (stripe_req->remaining == 0) {
        stripe_req->chunk_requests_complete_cb(stripe_req);
    }
}

static void
raid6_stripe_read(struct stripe_request *stripe_req)
{
    struct chunk *chunk;
    int ret;
    struct chunk *p_chunk = stripe_req->parity_chunk;
    struct chunk *q_chunk = stripe_req->q_chunk;
    struct raid_bdev_io *raid_io = stripe_req->raid_io;
    struct raid_bdev *raid_bdev = raid_io->raid_bdev;
    struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(raid_io);
    struct raid_base_bdev_info *base_info;
    uint8_t total_degraded = 0;
    uint8_t degraded_data_chunks = 0;
    enum stripe_degraded_type degraded_type;
    uint64_t len, req_offset, req_blocks;

    FOR_EACH_CHUNK(stripe_req, chunk) {
        chunk->is_degraded = false;
    }
    stripe_req->degraded_chunks[0] = NULL;
    stripe_req->degraded_chunks[1] = NULL;

    // Note: check how many degraded devices are involved
    FOR_EACH_CHUNK(stripe_req, chunk) {
        base_info = &raid_bdev->base_bdev_info[chunk->index];
        if (base_info->degraded) {
            total_degraded++;
            chunk->is_degraded = true;
            if (chunk->req_blocks > 0) {
                if (degraded_data_chunks < 2) {
                    stripe_req->degraded_chunks[degraded_data_chunks] = chunk;
                }
                degraded_data_chunks++;
            }
        }
    }

    if (degraded_data_chunks > raid_bdev->module->base_bdevs_max_degraded) {
        raid6_abort_stripe_request(stripe_req, SPDK_BDEV_IO_STATUS_FAILED);
    } else if (degraded_data_chunks == raid_bdev->module->base_bdevs_max_degraded) {
        req_offset = spdk_min(stripe_req->degraded_chunks[0]->req_offset,
                              stripe_req->degraded_chunks[1]->req_offset);
        req_blocks = spdk_max(stripe_req->degraded_chunks[0]->req_offset + stripe_req->degraded_chunks[0]->req_blocks,
                              stripe_req->degraded_chunks[1]->req_offset + stripe_req->degraded_chunks[1]->req_blocks)
                     - req_offset;
        if (total_degraded > raid_bdev->module->base_bdevs_max_degraded) {
            raid6_abort_stripe_request(stripe_req, SPDK_BDEV_IO_STATUS_FAILED);
        } else {
            stripe_req->degraded_type = degraded_type = DEGRADED_DD;
        }
    } else if (degraded_data_chunks == 1) {
        req_offset = stripe_req->degraded_chunks[0]->req_offset;
        req_blocks = stripe_req->degraded_chunks[0]->req_blocks;
        if (total_degraded > raid_bdev->module->base_bdevs_max_degraded) {
            raid6_abort_stripe_request(stripe_req, SPDK_BDEV_IO_STATUS_FAILED);
        } else if (total_degraded == raid_bdev->module->base_bdevs_max_degraded) {
            if (p_chunk->is_degraded) {
                stripe_req->degraded_type = degraded_type = DEGRADED_DP;
            } else if (q_chunk->is_degraded) {
                stripe_req->degraded_type = degraded_type = DEGRADED_D;
            } else {
                stripe_req->degraded_type = degraded_type = DEGRADED_DD;
                FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
                    if (chunk->is_degraded && chunk != stripe_req->degraded_chunks[0]) {
                        stripe_req->degraded_chunks[1] = chunk;
                    }
                }
            }
        } else {
            stripe_req->degraded_type = degraded_type = DEGRADED_D;
        }
    } else {
        stripe_req->degraded_type = degraded_type = NORMAL;
    }

    if (degraded_type == NORMAL) {
        stripe_req->chunk_requests_complete_cb = raid6_complete_stripe_request;
        FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
            if (chunk->req_blocks > 0) {
                ret = raid6_chunk_map_req_data(chunk);
                if (ret) {
                    raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
                    return;
                }
                raid6_submit_chunk_request(chunk, CHUNK_READ);
            }
        }
    } else if (degraded_type == DEGRADED_D) {
        stripe_req->chunk_requests_complete_cb = raid6_complete_stripe_read_request_d;
        FOR_EACH_CHUNK(stripe_req, chunk) {
            if (chunk == q_chunk) { // Note: do not request q chunk;
                chunk->preread_offset = 0;
                chunk->preread_blocks = 0;
            } else if (chunk->req_blocks == 0) { // Note: parity chunk or chunks which are not requested
                chunk->preread_offset = req_offset;
                chunk->preread_blocks = req_blocks;
                chunk->iov.iov_base = stripe_req->stripe->chunk_buffers[chunk->index];
                chunk->iov.iov_len = chunk->preread_blocks * raid_bdev->bdev.blocklen;
            } else if (chunk->is_degraded) { // Note: degraded data chunk, skip it
                chunk->preread_offset = 0;
                chunk->preread_blocks = 0;
                ret = raid6_chunk_map_req_data(chunk);
                if (ret) {
                    raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
                    return;
                }
            } else if ((chunk->req_offset > req_offset ||
                        chunk->req_offset + chunk->req_blocks < req_offset + req_blocks)) {
                // Note: requested chunks, but not enough
                chunk->preread_offset = spdk_min(chunk->req_offset, req_offset);
                chunk->preread_blocks = spdk_max(chunk->req_offset + chunk->req_blocks, req_offset + req_blocks)
                        - chunk->preread_offset;
                chunk->iov.iov_base = stripe_req->stripe->chunk_buffers[chunk->index];
                chunk->iov.iov_len = chunk->preread_blocks * raid_bdev->bdev.blocklen;
                len = chunk->req_blocks * bdev_io->bdev->blocklen;
                stripe_req->iov_offset += len;
            } else {
                chunk->preread_offset = 0;
                chunk->preread_blocks = 0;
                ret = raid6_chunk_map_req_data(chunk);
                if (ret) {
                    raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
                    return;
                }
            }
            if (chunk->preread_blocks) {
                raid6_submit_chunk_request(chunk, CHUNK_PREREAD);
            } else if (chunk->req_blocks && !chunk->is_degraded) {
                raid6_submit_chunk_request(chunk, CHUNK_READ);
            }
        }
    } else if (degraded_type == DEGRADED_DP) {
        stripe_req->chunk_requests_complete_cb = raid6_complete_stripe_read_request_dp;
        FOR_EACH_CHUNK(stripe_req, chunk) {
            if (chunk == p_chunk) { // Note: do not request p chunk;
                chunk->preread_offset = 0;
                chunk->preread_blocks = 0;
            } else if (chunk->req_blocks == 0) { // Note: q chunk or chunks which are not requested
                chunk->preread_offset = req_offset;
                chunk->preread_blocks = req_blocks;
                chunk->iov.iov_base = stripe_req->stripe->chunk_buffers[chunk->index];
                chunk->iov.iov_len = chunk->preread_blocks * raid_bdev->bdev.blocklen;
            } else if (chunk->is_degraded) { // Note: degraded data chunk, skip it
                chunk->preread_offset = 0;
                chunk->preread_blocks = 0;
                ret = raid6_chunk_map_req_data(chunk);
                if (ret) {
                    raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
                    return;
                }
            } else if ((chunk->req_offset > req_offset ||
                        chunk->req_offset + chunk->req_blocks < req_offset + req_blocks)) {
                // Note: requested chunks, but not enough
                chunk->preread_offset = spdk_min(chunk->req_offset, req_offset);
                chunk->preread_blocks = spdk_max(chunk->req_offset + chunk->req_blocks, req_offset + req_blocks)
                                        - chunk->preread_offset;
                chunk->iov.iov_base = stripe_req->stripe->chunk_buffers[chunk->index];
                chunk->iov.iov_len = chunk->preread_blocks * raid_bdev->bdev.blocklen;
                len = chunk->req_blocks * bdev_io->bdev->blocklen;
                stripe_req->iov_offset += len;
            } else {
                chunk->preread_offset = 0;
                chunk->preread_blocks = 0;
                ret = raid6_chunk_map_req_data(chunk);
                if (ret) {
                    raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
                    return;
                }
            }
            if (chunk->preread_blocks) {
                raid6_submit_chunk_request(chunk, CHUNK_PREREAD);
            } else if (chunk->req_blocks && !chunk->is_degraded) {
                raid6_submit_chunk_request(chunk, CHUNK_READ);
            }
        }
    } else { // Note: lose 2 data chunks
        stripe_req->chunk_requests_complete_cb = raid6_complete_stripe_read_request_dd;
        FOR_EACH_CHUNK(stripe_req, chunk) {
            if (chunk->is_degraded) { // Note: degraded data chunk, skip it
                chunk->preread_offset = 0;
                chunk->preread_blocks = 0;
                ret = raid6_chunk_map_req_data(chunk);
                if (ret) {
                    raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
                    return;
                }
            } else if (chunk->req_blocks == 0) { // Note: p chunk, q chunk or chunks which are not requested
                chunk->preread_offset = req_offset;
                chunk->preread_blocks = req_blocks;
                chunk->iov.iov_base = stripe_req->stripe->chunk_buffers[chunk->index];
                chunk->iov.iov_len = chunk->preread_blocks * raid_bdev->bdev.blocklen;
            } else if ((chunk->req_offset > req_offset ||
                        chunk->req_offset + chunk->req_blocks < req_offset + req_blocks)) {
                // Note: requested chunks, but not enough
                chunk->preread_offset = spdk_min(chunk->req_offset, req_offset);
                chunk->preread_blocks = spdk_max(chunk->req_offset + chunk->req_blocks, req_offset + req_blocks)
                                        - chunk->preread_offset;
                chunk->iov.iov_base = stripe_req->stripe->chunk_buffers[chunk->index];
                chunk->iov.iov_len = chunk->preread_blocks * raid_bdev->bdev.blocklen;
                len = chunk->req_blocks * bdev_io->bdev->blocklen;
                stripe_req->iov_offset += len;
            } else {
                chunk->preread_offset = 0;
                chunk->preread_blocks = 0;
                ret = raid6_chunk_map_req_data(chunk);
                if (ret) {
                    raid6_abort_stripe_request(stripe_req, errno_to_status(ret));
                    return;
                }
            }
            if (chunk->preread_blocks) {
                raid6_submit_chunk_request(chunk, CHUNK_PREREAD);
            } else if (chunk->req_blocks && !chunk->is_degraded) {
                raid6_submit_chunk_request(chunk, CHUNK_READ);
            }
        }
    }
}

static void
raid6_submit_stripe_request(struct stripe_request *stripe_req)
{
    struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(stripe_req->raid_io);

    if (bdev_io->type == SPDK_BDEV_IO_TYPE_READ) {
        raid6_stripe_read(stripe_req);
    } else if (bdev_io->type == SPDK_BDEV_IO_TYPE_WRITE) {
        raid6_stripe_write(stripe_req);
    } else {
        assert(false);
    }
}

static void
raid6_handle_stripe(struct raid_bdev_io *raid_io, struct stripe *stripe,
                    uint64_t stripe_offset, uint64_t blocks, uint64_t iov_offset)
{
    struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(raid_io);
    struct raid_bdev *raid_bdev = raid_io->raid_bdev;
    struct raid6_info *r6info = raid_bdev->module_private;
    struct stripe_request *stripe_req;
    struct chunk *chunk;
    uint64_t stripe_offset_from, stripe_offset_to;
    uint8_t first_chunk_data_idx, last_chunk_data_idx;
    bool do_submit;

    if (raid_io->base_bdev_io_remaining == blocks &&
        bdev_io->type == SPDK_BDEV_IO_TYPE_WRITE &&
        blocks < raid_bdev->strip_size) {
        /*
         * Split in 2 smaller requests if this request would require
         * a non-contiguous parity chunk update
         */
        uint64_t blocks_limit = raid_bdev->strip_size -
                                (stripe_offset % raid_bdev->strip_size);
        if (blocks > blocks_limit) {
            raid6_handle_stripe(raid_io, stripe, stripe_offset,
                                blocks_limit, iov_offset);
            blocks -= blocks_limit;
            stripe_offset += blocks_limit;
            iov_offset += blocks_limit * raid_bdev->bdev.blocklen;
        }
    }

    stripe_req = spdk_mempool_get(r6info->stripe_request_mempool);
    if (spdk_unlikely(!stripe_req)) {
        raid_bdev_io_complete_part(raid_io, blocks, SPDK_BDEV_IO_STATUS_NOMEM);
        return;
    }

    stripe_req->raid_io = raid_io;
    stripe_req->iov_offset = iov_offset;
    stripe_req->init_iov_offset = iov_offset;
    stripe_req->status = SPDK_BDEV_IO_STATUS_SUCCESS;
    stripe_req->remaining = 0;

    stripe_req->stripe = stripe;
    uint8_t p_idx = raid_bdev->num_base_bdevs - 1 - (stripe->index % raid_bdev->num_base_bdevs);
    uint8_t q_idx = (p_idx + 1) % raid_bdev->num_base_bdevs;
    stripe_req->parity_chunk = &stripe_req->chunks[p_idx];
    stripe_req->q_chunk = &stripe_req->chunks[q_idx];

    stripe_offset_from = stripe_offset;
    stripe_offset_to = stripe_offset_from + blocks;
    first_chunk_data_idx = stripe_offset_from >> raid_bdev->strip_size_shift;
    last_chunk_data_idx = (stripe_offset_to - 1) >> raid_bdev->strip_size_shift;

    stripe_req->first_data_chunk = raid6_get_data_chunk(stripe_req, first_chunk_data_idx);
    stripe_req->last_data_chunk = raid6_get_data_chunk(stripe_req, last_chunk_data_idx);

    FOR_EACH_CHUNK(stripe_req, chunk) {
        chunk->index = chunk - stripe_req->chunks;
        chunk->iovs = &chunk->iov;
        chunk->iovcnt = 1;

        if (chunk == stripe_req->parity_chunk ||
            chunk == stripe_req->q_chunk ||
            chunk < stripe_req->first_data_chunk ||
            chunk > stripe_req->last_data_chunk) {
            chunk->req_offset = 0;
            chunk->req_blocks = 0;
        } else {
            uint64_t chunk_offset_from = raid6_chunk_data_index(chunk) << raid_bdev->strip_size_shift;
            uint64_t chunk_offset_to = chunk_offset_from + raid_bdev->strip_size;

            if (stripe_offset_from > chunk_offset_from) {
                chunk->req_offset = stripe_offset_from - chunk_offset_from;
            } else {
                chunk->req_offset = 0;
            }

            if (stripe_offset_to < chunk_offset_to) {
                chunk->req_blocks = stripe_offset_to - chunk_offset_from;
            } else {
                chunk->req_blocks = raid_bdev->strip_size;
            }

            chunk->req_blocks -= chunk->req_offset;
        }
    }

    pthread_spin_lock(&stripe->requests_lock);
    do_submit = TAILQ_EMPTY(&stripe->requests);
    TAILQ_INSERT_TAIL(&stripe->requests, stripe_req, link);
    pthread_spin_unlock(&stripe->requests_lock);

    if (do_submit) {
        raid6_submit_stripe_request(stripe_req);
    }
}

static int
raid6_reclaim_stripes(struct raid6_info *r6info)
{
    struct stripe *stripe, *tmp;
    int reclaimed = 0;
    int ret;
    int to_reclaim = (RAID_MAX_STRIPES / 8) - RAID_MAX_STRIPES +
                     rte_hash_count(r6info->active_stripes_hash);

    TAILQ_FOREACH_REVERSE_SAFE(stripe, &r6info->active_stripes, active_stripes_head, link, tmp) {
        if (__atomic_load_n(&stripe->refs, __ATOMIC_SEQ_CST) > 0) {
            continue;
        }

        TAILQ_REMOVE(&r6info->active_stripes, stripe, link);
        TAILQ_INSERT_TAIL(&r6info->free_stripes, stripe, link);

        ret = rte_hash_del_key_with_hash(r6info->active_stripes_hash,
                                         &stripe->index, stripe->hash);
        if (spdk_unlikely(ret < 0)) {
            assert(false);
        }

        if (++reclaimed > to_reclaim) {
            break;
        }
    }

    return reclaimed;
}

static struct stripe *
raid6_get_stripe(struct raid6_info *r6info, uint64_t stripe_index)
{
    struct stripe *stripe;
    hash_sig_t hash;
    int ret;

    hash = rte_hash_hash(r6info->active_stripes_hash, &stripe_index);

    pthread_spin_lock(&r6info->active_stripes_lock);
    ret = rte_hash_lookup_with_hash_data(r6info->active_stripes_hash,
                                         &stripe_index, hash, (void **)&stripe);
    if (ret == -ENOENT) {
        stripe = TAILQ_FIRST(&r6info->free_stripes);
        if (!stripe) {
            if (raid6_reclaim_stripes(r6info) > 0) {
                stripe = TAILQ_FIRST(&r6info->free_stripes);
                assert(stripe != NULL);
            } else {
                pthread_spin_unlock(&r6info->active_stripes_lock);
                return NULL;
            }
        }
        TAILQ_REMOVE(&r6info->free_stripes, stripe, link);

        stripe->index = stripe_index;
        stripe->hash = hash;

        ret = rte_hash_add_key_with_hash_data(r6info->active_stripes_hash,
                                              &stripe_index, hash, stripe);
        if (spdk_unlikely(ret < 0)) {
            assert(false);
        }
    } else {
        TAILQ_REMOVE(&r6info->active_stripes, stripe, link);
    }
    TAILQ_INSERT_HEAD(&r6info->active_stripes, stripe, link);

    __atomic_fetch_add(&stripe->refs, 1, __ATOMIC_SEQ_CST);

    pthread_spin_unlock(&r6info->active_stripes_lock);

    return stripe;
}

static void
raid6_submit_rw_request(struct raid_bdev_io *raid_io);

static void
_raid6_submit_rw_request(void *_raid_io)
{
    struct raid_bdev_io *raid_io = _raid_io;

    raid6_submit_rw_request(raid_io);
}

static void
raid6_submit_rw_request(struct raid_bdev_io *raid_io)
{
    struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(raid_io);
    struct raid6_info *r6info = raid_io->raid_bdev->module_private;
    uint64_t offset_blocks = bdev_io->u.bdev.offset_blocks;
    uint64_t num_blocks = bdev_io->u.bdev.num_blocks;
    uint64_t stripe_index = offset_blocks / r6info->stripe_blocks;
    uint64_t stripe_offset = offset_blocks % r6info->stripe_blocks;
    struct stripe *stripe;

    stripe = raid6_get_stripe(r6info, stripe_index);
    if (spdk_unlikely(stripe == NULL)) {
        struct raid6_io_channel *r6ch = raid_bdev_io_channel_get_resource(raid_io->raid_ch);
        struct spdk_bdev_io_wait_entry *wqe = &raid_io->waitq_entry;

        wqe->cb_fn = _raid6_submit_rw_request;
        wqe->cb_arg = raid_io;
        TAILQ_INSERT_TAIL(&r6ch->retry_queue, wqe, link);
        return;
    }

    raid_io->base_bdev_io_remaining = num_blocks;

    raid6_handle_stripe(raid_io, stripe, stripe_offset, num_blocks, 0);
}

static int
raid6_stripe_init(struct stripe *stripe, struct raid_bdev *raid_bdev)
{
    uint8_t i, j;
    void *buf;

    stripe->chunk_buffers = calloc(raid_bdev->num_base_bdevs, sizeof(void *));
    if (!stripe->chunk_buffers) {
        SPDK_ERRLOG("Failed to allocate chunk buffers array\n");
        return -ENOMEM;
    }

    for (i = 0; i < raid_bdev->num_base_bdevs; i++) {
        buf = spdk_dma_malloc(raid_bdev->strip_size * raid_bdev->bdev.blocklen,
                              spdk_max(spdk_bdev_get_buf_align(raid_bdev->base_bdev_info[i].bdev), 32),
                              NULL);
        if (!buf) {
            SPDK_ERRLOG("Failed to allocate chunk buffer\n");
            for (; i > 0; --i) {
                spdk_dma_free(stripe->chunk_buffers[i]);
            }
            free(stripe->chunk_buffers);
            return -ENOMEM;
        }

        stripe->chunk_buffers[i] = buf;
    }

    stripe->tmp_buffers = calloc(3, sizeof(void *));
    if (!stripe->tmp_buffers) {
        SPDK_ERRLOG("Failed to allocate tmp buffers array\n");
        return -ENOMEM;
    }

    for (i = 0; i < 3; i++) {
        buf = spdk_dma_malloc(raid_bdev->strip_size * raid_bdev->bdev.blocklen, 32, NULL);
        if (!buf) {
            SPDK_ERRLOG("Failed to allocate tmp buffer\n");
            for (; i > 0; --i) {
                spdk_dma_free(stripe->tmp_buffers[i]);
            }
            free(stripe->tmp_buffers);
            for (j = 0; j < raid_bdev->num_base_bdevs; j++) {
                spdk_dma_free(stripe->chunk_buffers[j]);
            }
            free(stripe->chunk_buffers);
            return -ENOMEM;
        }

        stripe->tmp_buffers[i] = buf;
    }

    TAILQ_INIT(&stripe->requests);
    pthread_spin_init(&stripe->requests_lock, PTHREAD_PROCESS_PRIVATE);

    return 0;
}

static void
raid6_stripe_deinit(struct stripe *stripe, struct raid_bdev *raid_bdev)
{
    uint8_t i;

    for (i = 0; i < raid_bdev->num_base_bdevs; i++) {
        spdk_dma_free(stripe->chunk_buffers[i]);
    }
    free(stripe->chunk_buffers);

    for (i = 0; i < 3; i++) {
        spdk_dma_free(stripe->chunk_buffers[i]);
    }
    free(stripe->tmp_buffers);

    pthread_spin_destroy(&stripe->requests_lock);
}

static void
raid6_free(struct raid6_info *r6info)
{
    unsigned int i;

    pthread_spin_destroy(&r6info->active_stripes_lock);

    if (r6info->active_stripes_hash) {
        rte_hash_free(r6info->active_stripes_hash);
    }

    if (r6info->stripe_request_mempool) {
        spdk_mempool_free(r6info->stripe_request_mempool);
    }

    if (r6info->stripes) {
        for (i = 0; i < RAID_MAX_STRIPES; i++) {
            raid6_stripe_deinit(&r6info->stripes[i], r6info->raid_bdev);
        }
        free(r6info->stripes);
    }

    free(r6info);
}

static int
raid6_start(struct raid_bdev *raid_bdev)
{
    uint64_t min_blockcnt = UINT64_MAX;
    struct raid_base_bdev_info *base_info;
    struct raid6_info *r6info;
    char name_buf[32];
    struct rte_hash_parameters hash_params = { 0 };
    unsigned int i;
    int ret = 0;

    r6info = calloc(1, sizeof(*r6info));
    if (!r6info) {
        SPDK_ERRLOG("Failed to allocate r6info\n");
        return -ENOMEM;
    }

    for (int i = 0; i < 256; i++) {
        unsigned char c = 1;
        unsigned char a;
        for (int j = 0; j < i; j++) {
            c = gf_mul(c, 2);
        }
        a = gf_mul(c, gf_inv(c ^ 1));
        for (int l = 0; l < 256; l++) {
            unsigned char c1 = 1;
            unsigned char b;
            for (int m = 0; m < l; m++) {
                c1 = gf_mul(c1, 2);
            }
            b = gf_mul(c1, gf_inv(c ^ 1));
            gf_vect_mul_init(b, r6info->gf_const_tbl_arr_b[i][l]);
        }
        gf_vect_mul_init(c, r6info->gf_const_tbl_arr[i]);
        gf_vect_mul_init(a, r6info->gf_const_tbl_arr_a[i]);

    }

    r6info->raid_bdev = raid_bdev;

    pthread_spin_init(&r6info->active_stripes_lock, PTHREAD_PROCESS_PRIVATE);

    RAID_FOR_EACH_BASE_BDEV(raid_bdev, base_info) {
        min_blockcnt = spdk_min(min_blockcnt, base_info->bdev->blockcnt);
    }

    r6info->total_stripes = min_blockcnt / raid_bdev->strip_size;
    r6info->stripe_blocks = raid_bdev->strip_size * raid6_stripe_data_chunks_num(raid_bdev);

    raid_bdev->bdev.blockcnt = r6info->stripe_blocks * r6info->total_stripes;
    raid_bdev->bdev.optimal_io_boundary = r6info->stripe_blocks;
    raid_bdev->bdev.split_on_optimal_io_boundary = true;

    r6info->stripes = calloc(RAID_MAX_STRIPES, sizeof(*r6info->stripes));
    if (!r6info->stripes) {
        SPDK_ERRLOG("Failed to allocate stripes array\n");
        ret = -ENOMEM;
        goto out;
    }

    TAILQ_INIT(&r6info->free_stripes);

    for (i = 0; i < RAID_MAX_STRIPES; i++) {
        struct stripe *stripe = &r6info->stripes[i];

        ret = raid6_stripe_init(stripe, raid_bdev);
        if (ret) {
            for (; i > 0; --i) {
                raid6_stripe_deinit(&r6info->stripes[i], raid_bdev);
            }
            free(r6info->stripes);
            r6info->stripes = NULL;
            goto out;
        }

        TAILQ_INSERT_TAIL(&r6info->free_stripes, stripe, link);
    }

    snprintf(name_buf, sizeof(name_buf), "raid6_sreq_%p", raid_bdev);

    r6info->stripe_request_mempool = spdk_mempool_create(name_buf,
                                                         RAID_MAX_STRIPES * 4,
                                                         sizeof(struct stripe_request) + sizeof(struct chunk) * raid_bdev->num_base_bdevs,
                                                         SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
                                                         SPDK_ENV_SOCKET_ID_ANY);
    if (!r6info->stripe_request_mempool) {
        SPDK_ERRLOG("Failed to allocate stripe_request_mempool\n");
        ret = -ENOMEM;
        goto out;
    }

    snprintf(name_buf, sizeof(name_buf), "raid6_hash_%p", raid_bdev);

    hash_params.name = name_buf;
    hash_params.entries = RAID_MAX_STRIPES * 2;
    hash_params.key_len = sizeof(uint64_t);

    r6info->active_stripes_hash = rte_hash_create(&hash_params);
    if (!r6info->active_stripes_hash) {
        SPDK_ERRLOG("Failed to allocate active_stripes_hash\n");
        ret = -ENOMEM;
        goto out;
    }

    TAILQ_INIT(&r6info->active_stripes);

    raid_bdev->module_private = r6info;
    out:
    if (ret) {
        raid6_free(r6info);
    }
    return ret;
}

static void
raid6_stop(struct raid_bdev *raid_bdev)
{
    struct raid6_info *r6info = raid_bdev->module_private;

    raid6_free(r6info);
}

static int
raid6_io_channel_resource_init(struct raid_bdev *raid_bdev, void *resource)
{
    struct raid6_io_channel *r6ch = resource;

    TAILQ_INIT(&r6ch->retry_queue);

    return 0;
}

static void
raid6_io_channel_resource_deinit(void *resource)
{
    struct raid6_io_channel *r6ch = resource;

    assert(TAILQ_EMPTY(&r6ch->retry_queue));
}

static struct raid_bdev_module g_raid6_module = {
        .level = RAID6,
        .base_bdevs_min = 4,
        .base_bdevs_max_degraded = 2,
        .io_channel_resource_size = sizeof(struct raid6_io_channel),
        .start = raid6_start,
        .stop = raid6_stop,
        .submit_rw_request = raid6_submit_rw_request,
        .io_channel_resource_init = raid6_io_channel_resource_init,
        .io_channel_resource_deinit = raid6_io_channel_resource_deinit,
};
RAID_MODULE_REGISTER(&g_raid6_module)

SPDK_LOG_REGISTER_COMPONENT(bdev_raid6)
