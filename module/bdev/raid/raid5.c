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
#include "spdk/string.h"
#include "spdk/util.h"
#include "spdk/log.h"
#include "spdk/likely.h"

#include "isa-l/include/raid.h"

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

	/* To retry in case of running out of stripe requests */
	TAILQ_HEAD(, spdk_bdev_io_wait_entry) retry_queue;
};

struct raid5_info {
	/* The parent raid bdev */
	struct raid_bdev *raid_bdev;

	/* Number of data blocks in a stripe (without parity) */
	uint64_t stripe_blocks;

	/* Number of stripes on this array */
	uint64_t total_stripes;
};

#define FOR_EACH_CHUNK(req, c) \
	for (c = req->chunks; c < req->chunks + req->r5ch->r5info->raid_bdev->num_base_bdevs; c++)

#define __NEXT_DATA_CHUNK(req, c) \
	c+1 == req->parity_chunk ? c+2 : c+1

#define FOR_EACH_DATA_CHUNK(req, c) \
	for (c = __NEXT_DATA_CHUNK(req, req->chunks-1); \
	     c < req->chunks + req->r5ch->r5info->raid_bdev->num_base_bdevs; c = __NEXT_DATA_CHUNK(req, c))

/* Find the corresponding stripe request of a chunk */
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

/* calculate which disk parity is on. TODO: only works for raid5 */
static inline uint8_t
raid5_stripe_parity_chunk_index(const struct raid_bdev *raid_bdev, uint64_t stripe_index)
{
	return raid5_stripe_data_chunks_num(raid_bdev) - stripe_index % raid_bdev->num_base_bdevs;
}

static inline int
raid5_xor_gen(int vects, int len, void **array)
{
	return xor_gen(vects, len, array);
}

/* generate the xor chunk. TODO: only do it for full stripe in dRAID */
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

/* free bdev io when a request is completed 
TODO: for our implementation, we will need something similar which is invoked
when RPC response is received
 */
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
raid5_submit_rw_request(struct raid_bdev_io *raid_io)
{
	raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
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
	raid_bdev->bdev.optimal_io_boundary = r5info->stripe_blocks;
	raid_bdev->bdev.split_on_optimal_io_boundary = true;

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
	.start = raid5_start,
	.stop = raid5_stop,
	.submit_rw_request = raid5_submit_rw_request,
};
RAID_MODULE_REGISTER(&g_raid5_module)

SPDK_LOG_REGISTER_COMPONENT(bdev_raid5)
