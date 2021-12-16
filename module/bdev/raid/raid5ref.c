/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "bdev_raid.h"

#include "spdk/config.h"
#include "spdk/env.h"
#include "spdk/thread.h"
#include "spdk/likely.h"
#include "spdk/string.h"
#include "spdk/util.h"

#include "spdk/log.h"

/* Maximum concurrent full stripe writes per io channel */
#define RAID5_MAX_STRIPES 128

struct stripe_request {
	struct raid5_io_channel *r5ch;

	/* The stripe's index in the raid array. */
	uint64_t stripe_index;

	/* Buffer for stripe parity */
	struct iovec parity_iov;

	/* Counter for remaining chunk requests */
	int remaining;

	/* Status of the request */
	enum spdk_bdev_io_status status;

	/* The stripe's parity chunk */
	struct chunk *parity_chunk;

	/* Array of chunks corresponding to base_bdevs */
	struct chunk {
		/* Corresponds to base_bdev index */
		uint8_t index;

		/* The associated raid_bdev_io */
		struct raid_bdev_io *raid_io;

		/* For retrying base bdev IOs in case submit fails with -ENOMEM */
		struct spdk_bdev_io_wait_entry waitq_entry;
	} chunks[0];
};

struct raid5_info {
	/* The parent raid bdev */
	struct raid_bdev *raid_bdev;

	/* Number of data blocks in a stripe (without parity) */
	uint64_t stripe_blocks;

	/* Number of stripes on this array */
	uint64_t total_stripes;
};

struct raid5_io_channel {
	struct raid5_info *r5info;

	/* Mempool of all available stripe requests */
	struct spdk_mempool *stripe_request_mempool;

	/* For assembling split full stripe writes */
	struct stripe_request *current_stripe_request;

	/* Array of parity buffers for every available stripe request */
	void **stripe_parity_buffers;

	/* Array of iovec iterators for each data chunk */
	struct iov_iter {
		int index;
		size_t offset;
	} *chunk_iov_iters;

	/* Array of source and destination buffer pointers for parity calculation */
	void **chunk_xor_buffers;
};

#define FOR_EACH_CHUNK(req, c) \
	for (c = req->chunks; c < req->chunks + req->r5ch->r5info->raid_bdev->num_base_bdevs; c++)

#define __NEXT_DATA_CHUNK(req, c) \
	c+1 == req->parity_chunk ? c+2 : c+1

#define FOR_EACH_DATA_CHUNK(req, c) \
	for (c = __NEXT_DATA_CHUNK(req, req->chunks-1); \
	     c < req->chunks + req->r5ch->r5info->raid_bdev->num_base_bdevs; c = __NEXT_DATA_CHUNK(req, c))

static inline struct stripe_request *
raid5_chunk_stripe_req(struct chunk *chunk)
{
	return SPDK_CONTAINEROF((chunk - chunk->index), struct stripe_request, chunks);
}

static inline uint8_t
raid5_stripe_data_chunks_num(const struct raid_bdev *raid_bdev)
{
	return raid_bdev->num_base_bdevs - raid_bdev->module->base_bdevs_max_degraded;
}

static inline uint8_t
raid5_stripe_parity_chunk_index(const struct raid_bdev *raid_bdev, uint64_t stripe_index)
{
	return raid5_stripe_data_chunks_num(raid_bdev) - stripe_index % raid_bdev->num_base_bdevs;
}

#ifdef SPDK_CONFIG_ISAL

#include "isa-l/include/raid.h"

static inline int
raid5_xor_gen(int vects, int len, void **array)
{
	return xor_gen(vects, len, array);
}

#else

static int
raid5_xor_gen(int vects, int len, void **array)
{
	long *dest;
	int v;

	assert(len % sizeof(*dest) == 0);
	len /= sizeof(*dest);

	dest = array[vects - 1];

	for (v = vects - 1; v >= 0; v--) {
		int i;

		for (i = 0; i < len; i++) {
			dest[i] ^= ((long *)array[v])[i];
		}
	}

	return 0;
}

#endif

static int
raid5_xor_stripe(struct stripe_request *stripe_req)
{
	struct raid5_io_channel *r5ch = stripe_req->r5ch;
	struct raid_bdev *raid_bdev = r5ch->r5info->raid_bdev;
	struct chunk *chunk;
	size_t remaining = stripe_req->parity_iov.iov_len;
	int ret;

	memset(r5ch->chunk_iov_iters, 0,
	       sizeof(*r5ch->chunk_iov_iters) * raid5_stripe_data_chunks_num(raid_bdev));
	r5ch->chunk_xor_buffers[raid5_stripe_data_chunks_num(raid_bdev)] = stripe_req->parity_iov.iov_base;

	while (remaining > 0) {
		size_t n = remaining;
		uint8_t i;

		i = 0;
		FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
			struct iov_iter *iov_iter = &r5ch->chunk_iov_iters[i];
			struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(chunk->raid_io);
			struct iovec *iov = &bdev_io->u.bdev.iovs[iov_iter->index];
			size_t iov_off = iov_iter->offset;

			n = spdk_min(n, iov->iov_len - iov_off);
			r5ch->chunk_xor_buffers[i] = iov->iov_base + iov_off;
			i++;
		}

		assert(n > 0);

		ret = raid5_xor_gen(raid_bdev->num_base_bdevs, n, r5ch->chunk_xor_buffers);
		if (ret) {
			SPDK_ERRLOG("stripe xor failed\n");
			return ret;
		}

		i = 0;
		FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
			struct iov_iter *iov_iter = &r5ch->chunk_iov_iters[i];
			struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(chunk->raid_io);
			struct iovec *iov = &bdev_io->u.bdev.iovs[iov_iter->index];

			iov_iter->offset += n;
			if (iov_iter->offset == iov->iov_len) {
				iov_iter->offset = 0;
				iov_iter->index++;
			}
			i++;
		}
		r5ch->chunk_xor_buffers[i] += n;

		remaining -= n;
	}

	return 0;
}

static void
raid5_stripe_write_complete(struct stripe_request *stripe_req)
{
	struct chunk *chunk;
	struct raid5_io_channel *r5ch = stripe_req->r5ch;

	FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
		raid_bdev_io_complete(chunk->raid_io, stripe_req->status);
		chunk->raid_io = NULL;
	}

	spdk_mempool_put(r5ch->stripe_request_mempool, stripe_req);
}

static void
raid5_chunk_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct chunk *chunk = cb_arg;
	struct stripe_request *stripe_req = raid5_chunk_stripe_req(chunk);

	if (bdev_io) {
		spdk_bdev_free_io(bdev_io);
	}

	if (!success) {
		stripe_req->status = SPDK_BDEV_IO_STATUS_FAILED;
	}

	if (--stripe_req->remaining == 0) {
		raid5_stripe_write_complete(stripe_req);
	}
}

static void
raid5_chunk_write(struct chunk *chunk);

static void
_raid5_chunk_write(void *_chunk)
{
	struct chunk *chunk = _chunk;

	raid5_chunk_write(chunk);
}

static void
raid5_chunk_write(struct chunk *chunk)
{
	struct stripe_request *stripe_req = raid5_chunk_stripe_req(chunk);
	struct raid_bdev *raid_bdev = stripe_req->r5ch->r5info->raid_bdev;
	struct raid_base_bdev_info *base_info = &raid_bdev->base_bdev_info[chunk->index];
	struct raid_bdev_io_channel *raid_ch = (void *)((uint8_t *)stripe_req->r5ch - sizeof(*raid_ch));
	struct spdk_io_channel *base_ch = raid_ch->base_channel[chunk->index];
	uint64_t base_offset_blocks = (stripe_req->stripe_index << raid_bdev->strip_size_shift);
	struct iovec *iovs;
	int iovcnt;
	int ret;

	if (chunk == stripe_req->parity_chunk) {
		iovs = &stripe_req->parity_iov;
		iovcnt = 1;
	} else {
		struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(chunk->raid_io);

		iovs = bdev_io->u.bdev.iovs;
		iovcnt = bdev_io->u.bdev.iovcnt;
	}

	ret = spdk_bdev_writev_blocks(base_info->desc, base_ch, iovs, iovcnt,
				      base_offset_blocks, raid_bdev->strip_size,
				      raid5_chunk_write_complete, chunk);

	if (spdk_unlikely(ret != 0)) {
		if (ret == -ENOMEM) {
			struct spdk_bdev_io_wait_entry *wqe = &chunk->waitq_entry;

			wqe->bdev = base_info->bdev;
			wqe->cb_fn = _raid5_chunk_write;
			wqe->cb_arg = chunk;
			spdk_bdev_queue_io_wait(base_info->bdev, base_ch, wqe);
		} else {
			raid5_chunk_write_complete(NULL, false, chunk);
		}
	}
}

static void
raid5_stripe_write(struct stripe_request *stripe_req)
{
	struct chunk *chunk;

	if (raid5_xor_stripe(stripe_req) != 0) {
		stripe_req->status = SPDK_BDEV_IO_STATUS_FAILED;
		stripe_req->remaining = 0;
		raid5_stripe_write_complete(stripe_req);
		return;
	}

	FOR_EACH_CHUNK(stripe_req, chunk) {
		raid5_chunk_write(chunk);
	}
}

static void
raid5_submit_rw_request(struct raid_bdev_io *raid_io);

static void
_raid5_submit_rw_request(void *_raid_io)
{
	struct raid_bdev_io *raid_io = _raid_io;

	raid5_submit_rw_request(raid_io);
}

static int
raid5_submit_write_request(struct raid_bdev_io *raid_io, uint64_t stripe_index,
			   uint64_t stripe_offset)
{
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	struct raid5_io_channel *r5ch = raid_bdev_io_channel_get_resource(raid_io->raid_ch);
	struct stripe_request *stripe_req;
	struct chunk *chunk;

	if (r5ch->current_stripe_request == NULL) {
		struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(raid_io);
		struct spdk_bdev_io *parent_bdev_io = spdk_bdev_io_get_split_parent(bdev_io);

		/* check if this is a split request and that the parent request spans the entire stripe */
		if (parent_bdev_io == NULL ||
		    parent_bdev_io->u.bdev.offset_blocks > stripe_index * r5ch->r5info->stripe_blocks ||
		    parent_bdev_io->u.bdev.offset_blocks + parent_bdev_io->u.bdev.num_blocks <
		    (stripe_index + 1) * r5ch->r5info->stripe_blocks) {
			return -EINVAL;
		}

		stripe_req = spdk_mempool_get(r5ch->stripe_request_mempool);
		assert(stripe_req != NULL); /* TODO: handle this */

		stripe_req->stripe_index = stripe_index;
		stripe_req->status = SPDK_BDEV_IO_STATUS_SUCCESS;
		stripe_req->parity_chunk = &stripe_req->chunks[raid5_stripe_parity_chunk_index(raid_bdev,
					   stripe_index)];
		r5ch->current_stripe_request = stripe_req;
	} else {
		stripe_req = r5ch->current_stripe_request;
	}

	chunk = &stripe_req->chunks[stripe_offset >> raid_bdev->strip_size_shift];
	if (chunk >= stripe_req->parity_chunk) {
		chunk++;
	}

	assert(chunk->raid_io == NULL);
	chunk->raid_io = raid_io;
	stripe_req->remaining++;

	if (stripe_req->remaining == raid5_stripe_data_chunks_num(raid_bdev)) {
		r5ch->current_stripe_request = NULL;
		stripe_req->remaining++; /* parity */
		raid5_stripe_write(stripe_req);
	}

	return 0;
}

static void
raid5_chunk_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct raid_bdev_io *raid_io = cb_arg;

	spdk_bdev_free_io(bdev_io);

	if (success) {
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	} else {
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
	}
}

static int
raid5_submit_read_request(struct raid_bdev_io *raid_io, uint64_t stripe_index,
			  uint64_t stripe_offset)
{
	struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(raid_io);
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	int ret;

	uint8_t chunk_data_idx = stripe_offset >> raid_bdev->strip_size_shift;
	uint8_t p_idx = raid5_stripe_parity_chunk_index(raid_bdev, stripe_index);
	uint8_t chunk_idx = chunk_data_idx < p_idx ? chunk_data_idx : chunk_data_idx + 1;
	struct raid_base_bdev_info *base_info = &raid_bdev->base_bdev_info[chunk_idx];
	struct spdk_io_channel *base_ch = raid_io->raid_ch->base_channel[chunk_idx];
	uint64_t chunk_offset = stripe_offset - (chunk_data_idx << raid_bdev->strip_size_shift);
	uint64_t base_offset_blocks = (stripe_index << raid_bdev->strip_size_shift) + chunk_offset;

	ret = spdk_bdev_readv_blocks(base_info->desc, base_ch,
				     bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
				     base_offset_blocks, bdev_io->u.bdev.num_blocks,
				     raid5_chunk_read_complete, raid_io);

	if (spdk_unlikely(ret != 0)) {
		if (ret == -ENOMEM) {
			raid_bdev_queue_io_wait(raid_io, base_info->bdev, base_ch, _raid5_submit_rw_request);
			return 0;
		}
	}

	return ret;
}

static void
raid5_submit_rw_request(struct raid_bdev_io *raid_io)
{
	struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(raid_io);
	struct raid5_info *r5info = raid_io->raid_bdev->module_private;
	uint64_t offset_blocks = bdev_io->u.bdev.offset_blocks;
	uint64_t num_blocks = bdev_io->u.bdev.num_blocks;
	uint64_t stripe_index = offset_blocks / r5info->stripe_blocks;
	uint64_t stripe_offset = offset_blocks % r5info->stripe_blocks;
	int ret;

	assert(bdev_io->u.bdev.num_blocks <= r5info->raid_bdev->strip_size);

	if (bdev_io->type == SPDK_BDEV_IO_TYPE_READ) {
		ret = raid5_submit_read_request(raid_io, stripe_index, stripe_offset);
	} else if (bdev_io->type == SPDK_BDEV_IO_TYPE_WRITE &&
		   num_blocks == r5info->raid_bdev->strip_size) {
		ret = raid5_submit_write_request(raid_io, stripe_index, stripe_offset);
	} else {
		ret = -EINVAL;
	}

	if (ret != 0) {
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
	}
}

static void
raid5_io_channel_resource_deinit(void *resource)
{
	struct raid5_io_channel *r5ch = resource;

	free(r5ch->chunk_xor_buffers);
	free(r5ch->chunk_iov_iters);

	spdk_mempool_free(r5ch->stripe_request_mempool);

	if (r5ch->stripe_parity_buffers) {
		unsigned int i;

		for (i = 0; i < RAID5_MAX_STRIPES; i++) {
			if (!r5ch->stripe_parity_buffers[i]) {
				break;
			}
			spdk_dma_free(r5ch->stripe_parity_buffers[i]);
		}

		free(r5ch->stripe_parity_buffers);
	}
}

static void
raid5_stripe_req_ctor(struct spdk_mempool *mp, void *opaque, void *obj, unsigned obj_idx)
{
	struct stripe_request *stripe_req = obj;
	struct raid5_io_channel *r5ch = opaque;
	struct raid_bdev *raid_bdev = r5ch->r5info->raid_bdev;
	struct chunk *chunk;

	stripe_req->r5ch = r5ch;
	stripe_req->remaining = 0;
	stripe_req->parity_iov.iov_len = raid_bdev->strip_size * raid_bdev->bdev.blocklen;
	stripe_req->parity_iov.iov_base = r5ch->stripe_parity_buffers[obj_idx];
	FOR_EACH_CHUNK(stripe_req, chunk) {
		chunk->index = chunk - stripe_req->chunks;
		chunk->raid_io = NULL;
	}
}

static int
raid5_io_channel_resource_init(struct raid_bdev *raid_bdev, void *resource)
{
	struct raid5_io_channel *r5ch = resource;
	char name_buf[32];
	struct raid_base_bdev_info *base_info;
	size_t alignment;
	unsigned int i;

	r5ch->r5info = raid_bdev->module_private;

	r5ch->stripe_parity_buffers = calloc(RAID5_MAX_STRIPES, sizeof(void *));
	if (!r5ch->stripe_parity_buffers) {
		goto err;
	}

#ifdef SPDK_CONFIG_ISAL
	alignment = 32;
#else
	alignment = sizeof(long);
#endif
	RAID_FOR_EACH_BASE_BDEV(raid_bdev, base_info) {
		alignment = spdk_max(alignment, spdk_bdev_get_buf_align(base_info->bdev));
	}

	for (i = 0; i < RAID5_MAX_STRIPES; i++) {
		void *buf = spdk_dma_malloc(raid_bdev->strip_size * raid_bdev->bdev.blocklen, alignment, NULL);
		if (!buf) {
			goto err;
		}
		r5ch->stripe_parity_buffers[i] = buf;
	}

	snprintf(name_buf, sizeof(name_buf), "r5ch_sreq_%p", r5ch);

	r5ch->stripe_request_mempool = spdk_mempool_create_ctor(name_buf, RAID5_MAX_STRIPES,
				       sizeof(struct stripe_request) + sizeof(struct chunk) * raid_bdev->num_base_bdevs,
				       0, SPDK_ENV_SOCKET_ID_ANY, raid5_stripe_req_ctor, r5ch);
	if (!r5ch->stripe_request_mempool) {
		goto err;
	}

	r5ch->chunk_iov_iters = calloc(raid5_stripe_data_chunks_num(raid_bdev),
				       sizeof(*r5ch->chunk_iov_iters));
	if (!r5ch->chunk_iov_iters) {
		goto err;
	}

	r5ch->chunk_xor_buffers = calloc(raid_bdev->num_base_bdevs, sizeof(*r5ch->chunk_xor_buffers));
	if (!r5ch->chunk_xor_buffers) {
		goto err;
	}
	return 0;
err:
	SPDK_ERRLOG("Failed to allocate raid5 io channel\n");
	raid5_io_channel_resource_deinit(r5ch);
	return -ENOMEM;
}

static int
raid5_start(struct raid_bdev *raid_bdev)
{
	uint64_t min_blockcnt = UINT64_MAX;
	struct raid_base_bdev_info *base_info;
	struct raid5_info *r5info;

	r5info = calloc(1, sizeof(*r5info));
	if (!r5info) {
		SPDK_ERRLOG("Failed to allocate r5info\n");
		return -ENOMEM;
	}
	r5info->raid_bdev = raid_bdev;

	RAID_FOR_EACH_BASE_BDEV(raid_bdev, base_info) {
		min_blockcnt = spdk_min(min_blockcnt, base_info->bdev->blockcnt);
	}

	r5info->total_stripes = min_blockcnt / raid_bdev->strip_size;
	r5info->stripe_blocks = raid_bdev->strip_size * raid5_stripe_data_chunks_num(raid_bdev);

	raid_bdev->bdev.blockcnt = r5info->stripe_blocks * r5info->total_stripes;
	raid_bdev->bdev.optimal_io_boundary = raid_bdev->strip_size;
	raid_bdev->bdev.split_on_optimal_io_boundary = true;
	raid_bdev->bdev.write_unit_size = r5info->stripe_blocks;

	raid_bdev->module_private = r5info;

	return 0;
}

static void
raid5_stop(struct raid_bdev *raid_bdev)
{
	struct raid5_info *r5info = raid_bdev->module_private;

	free(r5info);
}

static struct raid_bdev_module g_raid5_module = {
	.level = RAID5,
	.base_bdevs_min = 3,
	.base_bdevs_max_degraded = 1,
	.io_channel_resource_size = sizeof(struct raid5_io_channel),
	.start = raid5_start,
	.stop = raid5_stop,
	.submit_rw_request = raid5_submit_rw_request,
	.io_channel_resource_init = raid5_io_channel_resource_init,
	.io_channel_resource_deinit = raid5_io_channel_resource_deinit,
};
RAID_MODULE_REGISTER(&g_raid5_module)

SPDK_LOG_REGISTER_COMPONENT(bdev_raid5)
