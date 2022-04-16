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
#include "../../../dRaid/src/common/common.h"
#include "../../../dRaid/src/common/readerwriterqueue.h"

#include "rocksdb/env.h"
#include <set>
#include <iostream>
#include <stdexcept>

extern "C" {
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/blob.h"
#include "spdk/blobfs.h"
#include "spdk/blob_bdev.h"
#include "spdk/log.h"
#include "spdk/thread.h"
#include "spdk/bdev.h"
}

static erpc::Nexus *g_nexus;
static char *g_addr_file = "/users/kyleshu/artifacts/ip_addrs_100g.txt";
static uint8_t g_phy_port = 2;
static std::string g_host_ip_addr;

erpc::Nexus *
erpc_get_nexus(void)
{
    return g_nexus;
}

uint8_t
erpc_get_phy_port(void)
{
    return g_phy_port;
}

std::string
get_host_ip_addr(void)
{
    return g_host_ip_addr;
}

namespace rocksdb
{

struct spdk_filesystem *g_fs = NULL;
struct spdk_bs_dev *g_bs_dev;
uint32_t g_lcore = 0;
std::string g_bdev_name;
volatile bool g_spdk_ready = false;
volatile bool g_spdk_start_failure = false;

void SpdkInitializeThread(void);

class SpdkThreadCtx
{
public:
	struct spdk_fs_thread_ctx *channel;

	SpdkThreadCtx(void) : channel(NULL)
	{
		SpdkInitializeThread();
	}

	~SpdkThreadCtx(void)
	{
		if (channel) {
			spdk_fs_free_thread_ctx(channel);
			channel = NULL;
		}
	}

private:
	SpdkThreadCtx(const SpdkThreadCtx &);
	SpdkThreadCtx &operator=(const SpdkThreadCtx &);
};

thread_local SpdkThreadCtx g_sync_args;

static void
set_channel()
{
	struct spdk_thread *thread;

	if (g_fs != NULL && g_sync_args.channel == NULL) {
		thread = spdk_thread_create("spdk_rocksdb", NULL);
		spdk_set_thread(thread);
		g_sync_args.channel = spdk_fs_alloc_thread_ctx(g_fs);
	}
}

static void
__call_fn(void *arg1, void *arg2)
{
	fs_request_fn fn;

	fn = (fs_request_fn)arg1;
	fn(arg2);
}

static void
__send_request(fs_request_fn fn, void *arg)
{
	struct spdk_event *event;

	event = spdk_event_allocate(g_lcore, __call_fn, (void *)fn, arg);
	spdk_event_call(event);
}

static std::string
sanitize_path(const std::string &input, const std::string &mount_directory)
{
	int index = 0;
	std::string name;
	std::string input_tmp;

	input_tmp = input.substr(mount_directory.length(), input.length());
	for (const char &c : input_tmp) {
		if (index == 0) {
			if (c != '/') {
				name = name.insert(index, 1, '/');
				index++;
			}
			name = name.insert(index, 1, c);
			index++;
		} else {
			if (name[index - 1] == '/' && c == '/') {
				continue;
			} else {
				name = name.insert(index, 1, c);
				index++;
			}
		}
	}

	if (name[name.size() - 1] == '/') {
		name = name.erase(name.size() - 1, 1);
	}
	return name;
}

class SpdkSequentialFile : public SequentialFile
{
	struct spdk_file *mFile;
	uint64_t mOffset;
public:
	SpdkSequentialFile(struct spdk_file *file) : mFile(file), mOffset(0) {}
	virtual ~SpdkSequentialFile();

	virtual Status Read(size_t n, Slice *result, char *scratch) override;
	virtual Status Skip(uint64_t n) override;
	virtual Status InvalidateCache(size_t offset, size_t length) override;
};

SpdkSequentialFile::~SpdkSequentialFile(void)
{
	set_channel();
	spdk_file_close(mFile, g_sync_args.channel);
}

Status
SpdkSequentialFile::Read(size_t n, Slice *result, char *scratch)
{
	int64_t ret;

	set_channel();
	// SPDK_NOTICELOG("spdk seq read %d\n", n);
	ret = spdk_file_read(mFile, g_sync_args.channel, scratch, mOffset, n);
	if (ret >= 0) {
		mOffset += ret;
		*result = Slice(scratch, ret);
		return Status::OK();
	} else {
		errno = -ret;
		return Status::IOError(spdk_file_get_name(mFile), strerror(errno));
	}
}

Status
SpdkSequentialFile::Skip(uint64_t n)
{
	mOffset += n;
	return Status::OK();
}

Status
SpdkSequentialFile::InvalidateCache(__attribute__((unused)) size_t offset,
				    __attribute__((unused)) size_t length)
{
	return Status::OK();
}

class SpdkRandomAccessFile : public RandomAccessFile
{
	struct spdk_file *mFile;
public:
	SpdkRandomAccessFile(struct spdk_file *file) : mFile(file) {}
	virtual ~SpdkRandomAccessFile();

	virtual Status Read(uint64_t offset, size_t n, Slice *result, char *scratch) const override;
	virtual Status InvalidateCache(size_t offset, size_t length) override;
};

SpdkRandomAccessFile::~SpdkRandomAccessFile(void)
{
	set_channel();
	spdk_file_close(mFile, g_sync_args.channel);
}

Status
SpdkRandomAccessFile::Read(uint64_t offset, size_t n, Slice *result, char *scratch) const
{
	int64_t rc;

	set_channel();
	// SPDK_NOTICELOG("spdk rand read %d\n", n);
	rc = spdk_file_read(mFile, g_sync_args.channel, scratch, offset, n);
	if (rc >= 0) {
		*result = Slice(scratch, n);
		return Status::OK();
	} else {
		errno = -rc;
		return Status::IOError(spdk_file_get_name(mFile), strerror(errno));
	}
}

Status
SpdkRandomAccessFile::InvalidateCache(__attribute__((unused)) size_t offset,
				      __attribute__((unused)) size_t length)
{
	return Status::OK();
}

class SpdkWritableFile : public WritableFile
{
	struct spdk_file *mFile;
	uint64_t mSize;

public:
	SpdkWritableFile(struct spdk_file *file) : mFile(file), mSize(0) {}
	~SpdkWritableFile()
	{
		if (mFile != NULL) {
			Close();
		}
	}

	virtual void SetIOPriority(Env::IOPriority pri)
	{
		if (pri == Env::IO_HIGH) {
			spdk_file_set_priority(mFile, SPDK_FILE_PRIORITY_HIGH);
		}
	}

	virtual Status Truncate(uint64_t size) override
	{
		int rc;

		set_channel();
		rc = spdk_file_truncate(mFile, g_sync_args.channel, size);
		if (!rc) {
			mSize = size;
			return Status::OK();
		} else {
			errno = -rc;
			return Status::IOError(spdk_file_get_name(mFile), strerror(errno));
		}
	}
	virtual Status Close() override
	{
		set_channel();
		spdk_file_close(mFile, g_sync_args.channel);
		mFile = NULL;
		return Status::OK();
	}
	virtual Status Append(const Slice &data) override;
	virtual Status Flush() override
	{
		return Status::OK();
	}
	virtual Status Sync() override
	{
		int rc;

		set_channel();
		rc = spdk_file_sync(mFile, g_sync_args.channel);
		if (!rc) {
			return Status::OK();
		} else {
			errno = -rc;
			return Status::IOError(spdk_file_get_name(mFile), strerror(errno));
		}
	}
	virtual Status Fsync() override
	{
		int rc;

		set_channel();
		rc = spdk_file_sync(mFile, g_sync_args.channel);
		if (!rc) {
			return Status::OK();
		} else {
			errno = -rc;
			return Status::IOError(spdk_file_get_name(mFile), strerror(errno));
		}
	}
	virtual bool IsSyncThreadSafe() const override
	{
		return true;
	}
	virtual uint64_t GetFileSize() override
	{
		return mSize;
	}
	virtual Status InvalidateCache(__attribute__((unused)) size_t offset,
				       __attribute__((unused)) size_t length) override
	{
		return Status::OK();
	}
	virtual Status Allocate(uint64_t offset, uint64_t len) override
	{
		int rc;

		set_channel();
		rc = spdk_file_truncate(mFile, g_sync_args.channel, offset + len);
		if (!rc) {
			return Status::OK();
		} else {
			errno = -rc;
			return Status::IOError(spdk_file_get_name(mFile), strerror(errno));
		}
	}
	virtual Status RangeSync(__attribute__((unused)) uint64_t offset,
				 __attribute__((unused)) uint64_t nbytes) override
	{
		int rc;

		/*
		 * SPDK BlobFS does not have a range sync operation yet, so just sync
		 *  the whole file.
		 */
		set_channel();
		rc = spdk_file_sync(mFile, g_sync_args.channel);
		if (!rc) {
			return Status::OK();
		} else {
			errno = -rc;
			return Status::IOError(spdk_file_get_name(mFile), strerror(errno));
		}
	}
	virtual size_t GetUniqueId(char *id, size_t max_size) const override
	{
		int rc;

		rc = spdk_file_get_id(mFile, id, max_size);
		if (rc < 0) {
			return 0;
		} else {
			return rc;
		}
	}
};

Status
SpdkWritableFile::Append(const Slice &data)
{
	int64_t rc;

	set_channel();
	// SPDK_NOTICELOG("spdk write to file %d\n", data.size());
	rc = spdk_file_write(mFile, g_sync_args.channel, (void *)data.data(), mSize, data.size());
	if (rc >= 0) {
		mSize += data.size();
		return Status::OK();
	} else {
		errno = -rc;
		return Status::IOError(spdk_file_get_name(mFile), strerror(errno));
	}
}

class SpdkDirectory : public Directory
{
public:
	SpdkDirectory() {}
	~SpdkDirectory() {}
	Status Fsync() override
	{
		return Status::OK();
	}
};

class SpdkAppStartException : public std::runtime_error
{
public:
	SpdkAppStartException(std::string mess): std::runtime_error(mess) {}
};

class SpdkEnv : public EnvWrapper
{
private:
	pthread_t mSpdkTid;
	std::string mDirectory;
	std::string mConfig;
	std::string mBdev;

public:
	SpdkEnv(Env *base_env, const std::string &dir, const std::string &conf,
		const std::string &bdev, uint64_t cache_size_in_mb);

	virtual ~SpdkEnv();

	virtual Status NewSequentialFile(const std::string &fname,
					 std::unique_ptr<SequentialFile> *result,
					 const EnvOptions &options) override
	{
		if (fname.compare(0, mDirectory.length(), mDirectory) == 0) {
			struct spdk_file *file;
			int rc;

			std::string name = sanitize_path(fname, mDirectory);
			set_channel();
			rc = spdk_fs_open_file(g_fs, g_sync_args.channel,
					       name.c_str(), 0, &file);
			if (rc == 0) {
				result->reset(new SpdkSequentialFile(file));
				return Status::OK();
			} else {
				/* Myrocks engine uses errno(ENOENT) as one
				 * special condition, for the purpose to
				 * support MySQL, set the errno to right value.
				 */
				errno = -rc;
				return Status::IOError(name, strerror(errno));
			}
		} else {
			return EnvWrapper::NewSequentialFile(fname, result, options);
		}
	}

	virtual Status NewRandomAccessFile(const std::string &fname,
					   std::unique_ptr<RandomAccessFile> *result,
					   const EnvOptions &options) override
	{
		if (fname.compare(0, mDirectory.length(), mDirectory) == 0) {
			std::string name = sanitize_path(fname, mDirectory);
			struct spdk_file *file;
			int rc;

			set_channel();
			// printf("new random file\n");
			rc = spdk_fs_open_file(g_fs, g_sync_args.channel,
					       name.c_str(), 0, &file);
			if (rc == 0) {
				result->reset(new SpdkRandomAccessFile(file));
				return Status::OK();
			} else {
				errno = -rc;
				return Status::IOError(name, strerror(errno));
			}
		} else {
			return EnvWrapper::NewRandomAccessFile(fname, result, options);
		}
	}

	virtual Status NewWritableFile(const std::string &fname,
				       std::unique_ptr<WritableFile> *result,
				       const EnvOptions &options) override
	{
		if (fname.compare(0, mDirectory.length(), mDirectory) == 0) {
			std::string name = sanitize_path(fname, mDirectory);
			struct spdk_file *file;
			int rc;

			set_channel();
			rc = spdk_fs_open_file(g_fs, g_sync_args.channel, name.c_str(),
					       SPDK_BLOBFS_OPEN_CREATE, &file);
			if (rc == 0) {
				result->reset(new SpdkWritableFile(file));
				return Status::OK();
			} else {
				errno = -rc;
				return Status::IOError(name, strerror(errno));
			}
		} else {
			return EnvWrapper::NewWritableFile(fname, result, options);
		}
	}

	virtual Status ReuseWritableFile(const std::string &fname,
					 const std::string &old_fname,
					 std::unique_ptr<WritableFile> *result,
					 const EnvOptions &options) override
	{
		return EnvWrapper::ReuseWritableFile(fname, old_fname, result, options);
	}

	virtual Status NewDirectory(__attribute__((unused)) const std::string &name,
				    std::unique_ptr<Directory> *result) override
	{
		result->reset(new SpdkDirectory());
		return Status::OK();
	}
	virtual Status FileExists(const std::string &fname) override
	{
		struct spdk_file_stat stat;
		int rc;
		std::string name = sanitize_path(fname, mDirectory);

		set_channel();
		rc = spdk_fs_file_stat(g_fs, g_sync_args.channel, name.c_str(), &stat);
		if (rc == 0) {
			return Status::OK();
		}
		return EnvWrapper::FileExists(fname);
	}
	virtual Status RenameFile(const std::string &src, const std::string &t) override
	{
		int rc;
		std::string src_name = sanitize_path(src, mDirectory);
		std::string target_name = sanitize_path(t, mDirectory);

		set_channel();
		rc = spdk_fs_rename_file(g_fs, g_sync_args.channel,
					 src_name.c_str(), target_name.c_str());
		if (rc == -ENOENT) {
			return EnvWrapper::RenameFile(src, t);
		}
		return Status::OK();
	}
	virtual Status LinkFile(__attribute__((unused)) const std::string &src,
				__attribute__((unused)) const std::string &t) override
	{
		return Status::NotSupported("SpdkEnv does not support LinkFile");
	}
	virtual Status GetFileSize(const std::string &fname, uint64_t *size) override
	{
		struct spdk_file_stat stat;
		int rc;
		std::string name = sanitize_path(fname, mDirectory);

		set_channel();
		rc = spdk_fs_file_stat(g_fs, g_sync_args.channel, name.c_str(), &stat);
		if (rc == -ENOENT) {
			return EnvWrapper::GetFileSize(fname, size);
		}
		*size = stat.size;
		return Status::OK();
	}
	virtual Status DeleteFile(const std::string &fname) override
	{
		int rc;
		std::string name = sanitize_path(fname, mDirectory);

		set_channel();
		rc = spdk_fs_delete_file(g_fs, g_sync_args.channel, name.c_str());
		if (rc == -ENOENT) {
			return EnvWrapper::DeleteFile(fname);
		}
		return Status::OK();
	}
	virtual Status LockFile(const std::string &fname, FileLock **lock) override
	{
		std::string name = sanitize_path(fname, mDirectory);
		int64_t rc;

		set_channel();
		rc = spdk_fs_open_file(g_fs, g_sync_args.channel, name.c_str(),
				       SPDK_BLOBFS_OPEN_CREATE, (struct spdk_file **)lock);
		if (!rc) {
			return Status::OK();
		} else {
			errno = -rc;
			return Status::IOError(name, strerror(errno));
		}
	}
	virtual Status UnlockFile(FileLock *lock) override
	{
		set_channel();
		spdk_file_close((struct spdk_file *)lock, g_sync_args.channel);
		return Status::OK();
	}
	virtual Status GetChildren(const std::string &dir,
				   std::vector<std::string> *result) override
	{
		std::string::size_type pos;
		std::set<std::string> dir_and_file_set;
		std::string full_path;
		std::string filename;
		std::string dir_name;

		if (dir.find("archive") != std::string::npos) {
			return Status::OK();
		}
		if (dir.compare(0, mDirectory.length(), mDirectory) == 0) {
			spdk_fs_iter iter;
			struct spdk_file *file;
			dir_name = sanitize_path(dir, mDirectory);

			iter = spdk_fs_iter_first(g_fs);
			while (iter != NULL) {
				file = spdk_fs_iter_get_file(iter);
				full_path = spdk_file_get_name(file);
				if (strncmp(dir_name.c_str(), full_path.c_str(), dir_name.length())) {
					iter = spdk_fs_iter_next(iter);
					continue;
				}
				pos = full_path.find("/", dir_name.length() + 1);

				if (pos != std::string::npos) {
					filename = full_path.substr(dir_name.length() + 1, pos - dir_name.length() - 1);
				} else {
					filename = full_path.substr(dir_name.length() + 1);
				}
				dir_and_file_set.insert(filename);
				iter = spdk_fs_iter_next(iter);
			}

			for (auto &s : dir_and_file_set) {
				result->push_back(s);
			}

			result->push_back(".");
			result->push_back("..");

			return Status::OK();
		}
		return EnvWrapper::GetChildren(dir, result);
	}
};

/* The thread local constructor doesn't work for the main thread, since
 * the filesystem hasn't been loaded yet.  So we break out this
 * SpdkInitializeThread function, so that the main thread can explicitly
 * call it after the filesystem has been loaded.
 */
void SpdkInitializeThread(void)
{
	struct spdk_thread *thread;

	if (g_fs != NULL) {
		if (g_sync_args.channel) {
			spdk_fs_free_thread_ctx(g_sync_args.channel);
		}
		thread = spdk_thread_create("spdk_rocksdb", NULL);
		spdk_set_thread(thread);
		g_sync_args.channel = spdk_fs_alloc_thread_ctx(g_fs);
	}
}

static void
fs_load_cb(__attribute__((unused)) void *ctx,
	   struct spdk_filesystem *fs, int fserrno)
{
	if (fserrno == 0) {
		g_fs = fs;
	}
	g_spdk_ready = true;
}

static void
base_bdev_event_cb(enum spdk_bdev_event_type type, __attribute__((unused)) struct spdk_bdev *bdev,
		   __attribute__((unused)) void *event_ctx)
{
	printf("Unsupported bdev event: type %d\n", type);
}

static void
rocksdb_run(__attribute__((unused)) void *arg1)
{
	int rc;

	rc = spdk_bdev_create_bs_dev_ext(g_bdev_name.c_str(), base_bdev_event_cb, NULL,
					 &g_bs_dev);
	if (rc != 0) {
		printf("Could not create blob bdev\n");
		spdk_app_stop(0);
		exit(1);
	}

	g_lcore = spdk_env_get_first_core();

	printf("using bdev %s\n", g_bdev_name.c_str());
	spdk_fs_load(g_bs_dev, __send_request, fs_load_cb, NULL);
}

static void
fs_unload_cb(__attribute__((unused)) void *ctx,
	     __attribute__((unused)) int fserrno)
{
	assert(fserrno == 0);

	spdk_app_stop(0);
}

static void
rocksdb_shutdown(void)
{
	if (g_fs != NULL) {
		spdk_fs_unload(g_fs, fs_unload_cb, NULL);
	} else {
		fs_unload_cb(NULL, 0);
	}
}

static void *
initialize_spdk(void *arg)
{
	struct spdk_app_opts *opts = (struct spdk_app_opts *)arg;
	int rc;

	rc = spdk_app_start(opts, rocksdb_run, NULL);
	/*
	 * TODO:  Revisit for case of internal failure of
	 * spdk_app_start(), itself.  At this time, it's known
	 * the only application's use of spdk_app_stop() passes
	 * a zero; i.e. no fail (non-zero) cases so here we
	 * assume there was an internal failure and flag it
	 * so we can throw an exception.
	 */
	if (rc) {
		g_spdk_start_failure = true;
	} else {
		spdk_app_fini();
		delete opts;
	}
	pthread_exit(NULL);

}

SpdkEnv::SpdkEnv(Env *base_env, const std::string &dir, const std::string &conf,
		 const std::string &bdev, uint64_t cache_size_in_mb)
	: EnvWrapper(base_env), mDirectory(dir), mConfig(conf), mBdev(bdev)
{
	struct spdk_app_opts *opts = new struct spdk_app_opts;

	spdk_app_opts_init(opts, sizeof(*opts));
	opts->name = "rocksdb";
	opts->json_config_file = mConfig.c_str();
	opts->shutdown_cb = rocksdb_shutdown;
	opts->tpoint_group_mask = "0x1000";
	opts->reactor_mask = "0x6000";

	spdk_fs_set_cache_size(cache_size_in_mb);
	g_bdev_name = mBdev;

	pthread_create(&mSpdkTid, NULL, &initialize_spdk, opts);
	while (!g_spdk_ready && !g_spdk_start_failure)
		;
	if (g_spdk_start_failure) {
		delete opts;
		throw SpdkAppStartException("spdk_app_start() unable to start rocksdb_run()");
	}

	SpdkInitializeThread();
}

SpdkEnv::~SpdkEnv()
{
	/* This is a workaround for rocksdb test, we close the files if the rocksdb not
	 * do the work before the test quit.
	 */
	if (g_fs != NULL) {
		spdk_fs_iter iter;
		struct spdk_file *file;

		if (!g_sync_args.channel) {
			SpdkInitializeThread();
		}

		iter = spdk_fs_iter_first(g_fs);
		while (iter != NULL) {
			file = spdk_fs_iter_get_file(iter);
			spdk_file_close(file, g_sync_args.channel);
			iter = spdk_fs_iter_next(iter);
		}
	}

	spdk_app_start_shutdown();
	pthread_join(mSpdkTid, NULL);
}

Env *NewSpdkEnv(Env *base_env, const std::string &dir, const std::string &conf,
		const std::string &bdev, uint64_t cache_size_in_mb)
{
    std::ifstream addrs(g_addr_file, std::ios::in);
  	std::string ip_addr;
	addrs>>ip_addr;
	addrs.close();

    g_host_ip_addr = ip_addr;
	std::string client_uri = ip_addr + ":" + std::to_string(kUDPPort);
    g_nexus = new erpc::Nexus(client_uri, 0, numOfThreads);
	try {
		SpdkEnv *spdk_env = new SpdkEnv(base_env, dir, conf, bdev, cache_size_in_mb);
		if (g_fs != NULL) {
			return spdk_env;
		} else {
			delete spdk_env;
			return NULL;
		}
	} catch (SpdkAppStartException &e) {
		SPDK_ERRLOG("NewSpdkEnv: exception caught: %s", e.what());
		return NULL;
	} catch (...) {
		SPDK_ERRLOG("NewSpdkEnv: default exception caught");
		return NULL;
	}
}


class spdk_KVStore: public KVStore {
public:

    void Write(void* src, uint64_t offset, uint64_t length);

    void Read(void* dst, uint64_t offset, uint64_t length);

    spdk_KVStore(const std::string &conf, const std::string &bdev_name);
};


struct hello_context_t {
	struct spdk_bdev *bdev;
	struct spdk_bdev_desc *bdev_desc;
	struct spdk_io_channel *bdev_io_channel;
	char *buff;
	const char *bdev_name;
	struct spdk_bdev_io_wait_entry bdev_io_wait;
	size_t buff_len;
    size_t blk_size;
    size_t buf_align;
	uint64_t offset;
	uint64_t length;
    sem_t sem;
};

static constexpr size_t kCtxPoolSize = 512;
static constexpr size_t span_length = 1024;
static hello_context_t* g_hello_context = nullptr;
static struct spdk_thread *g_spdk_thread = nullptr;
static moodycamel::ReaderWriterQueue<hello_context_t*>* g_context_mempool = nullptr;

hello_context_t* alloc_context() {
    hello_context_t* tmp = (hello_context_t*) malloc(sizeof(hello_context_t));
    tmp->bdev = g_hello_context->bdev;
    tmp->bdev_desc = g_hello_context->bdev_desc;
    tmp->bdev_io_channel = g_hello_context->bdev_io_channel;
    tmp->bdev_name = g_hello_context->bdev_name;
    tmp->buff_len = g_hello_context->buff_len;
    tmp->blk_size = g_hello_context->blk_size;
    tmp->buf_align = g_hello_context->buf_align;
    tmp->buff = (char*) spdk_dma_zmalloc(g_hello_context->buff_len, g_hello_context->buf_align, NULL);
    if (!tmp->buff) {
        free(tmp);
        return nullptr;
    }
    sem_init(&tmp->sem, 0, 0);
    return tmp;
}


static void read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
    struct hello_context_t *hello_context = (struct hello_context_t*) cb_arg;

    if (success) {
        SPDK_NOTICELOG("Read string from bdev\n");
    } else {
        SPDK_ERRLOG("bdev io read error\n");
    }

    sem_post(&hello_context->sem);
}

static void hello_read(void *arg)
{
    struct hello_context_t *hello_context = (struct hello_context_t*) arg;
    int rc = 0;

    SPDK_NOTICELOG("Reading io\n");
    rc = spdk_bdev_read_blocks(hello_context->bdev_desc, hello_context->bdev_io_channel,
                hello_context->buff, hello_context->offset, hello_context->length, read_complete, hello_context);

    if (rc == -ENOMEM) {
        SPDK_NOTICELOG("Queueing io\n");
        /* In case we cannot perform I/O now, queue I/O */
        hello_context->bdev_io_wait.bdev = hello_context->bdev;
        hello_context->bdev_io_wait.cb_fn = hello_read;
        hello_context->bdev_io_wait.cb_arg = hello_context;
        spdk_bdev_queue_io_wait(hello_context->bdev, hello_context->bdev_io_channel,
                    &hello_context->bdev_io_wait);
    } else if (rc) {
        SPDK_ERRLOG("%s error while reading from bdev: %d\n", spdk_strerror(-rc), rc);
        spdk_put_io_channel(hello_context->bdev_io_channel);
        spdk_bdev_close(hello_context->bdev_desc);
        spdk_app_stop(-1);
    }
}

static void write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
    struct hello_context_t *hello_context = (struct hello_context_t*) cb_arg;
    uint32_t length;

    /* Complete the I/O */
    spdk_bdev_free_io(bdev_io);

    if (success) {
        SPDK_NOTICELOG("bdev io write completed successfully\n");
    } else {
        SPDK_ERRLOG("bdev io write error: %d\n", EIO);
        spdk_put_io_channel(hello_context->bdev_io_channel);
        spdk_bdev_close(hello_context->bdev_desc);
        spdk_app_stop(-1);
        return;
    }

    /* Zero the buffer so that we can use it for reading */
    length = spdk_bdev_get_block_size(hello_context->bdev);
    memset(hello_context->buff, 0, length);

    sem_post(&hello_context->sem);
}

static void hello_write(void *arg) {
    struct hello_context_t *hello_context = (struct hello_context_t*) arg;
    int rc = 0;

    SPDK_NOTICELOG("Writing to the bdev\n");
    rc = spdk_bdev_write_blocks(hello_context->bdev_desc, hello_context->bdev_io_channel,
                hello_context->buff, hello_context->offset, hello_context->length, write_complete, hello_context);

    if (rc == -ENOMEM) {
        SPDK_NOTICELOG("Queueing io\n");
        /* In case we cannot perform I/O now, queue I/O */
        hello_context->bdev_io_wait.bdev = hello_context->bdev;
        hello_context->bdev_io_wait.cb_fn = hello_write;
        hello_context->bdev_io_wait.cb_arg = hello_context;
        spdk_bdev_queue_io_wait(hello_context->bdev, hello_context->bdev_io_channel,
                    &hello_context->bdev_io_wait);
    } else if (rc) {
        SPDK_ERRLOG("%s error while writing to bdev: %d\n", spdk_strerror(-rc), rc);
        spdk_put_io_channel(hello_context->bdev_io_channel);
        spdk_bdev_close(hello_context->bdev_desc);
        spdk_app_stop(-1);
    }
}

static void
hello_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
		    void *event_ctx)
{
	SPDK_NOTICELOG("Unsupported bdev event: type %d\n", type);
}

static void kvstore_start(void* arg) {
    struct hello_context_t *hello_context = (hello_context_t*) arg;
    uint32_t blk_size, buf_align;
    int rc = 0;
    hello_context->bdev = NULL;
    hello_context->bdev_desc = NULL;

    g_spdk_thread = spdk_get_thread();

    SPDK_NOTICELOG("Successfully started the application\n");

    /*
    * There can be many bdevs configured, but this application will only use
    * the one input by the user at runtime.
    *
    * Open the bdev by calling spdk_bdev_open_ext() with its name.
    * The function will return a descriptor
    */
    SPDK_NOTICELOG("Opening the bdev %s\n", hello_context->bdev_name);
    rc = spdk_bdev_open_ext(hello_context->bdev_name, true, hello_bdev_event_cb, NULL,
                &hello_context->bdev_desc);
    if (rc) {
        SPDK_ERRLOG("Could not open bdev: %s\n", hello_context->bdev_name);
        spdk_app_stop(-1);
        return;
    }

    /* A bdev pointer is valid while the bdev is opened. */
    hello_context->bdev = spdk_bdev_desc_get_bdev(hello_context->bdev_desc);


    SPDK_NOTICELOG("Opening io channel\n");
    /* Open I/O channel */
    hello_context->bdev_io_channel = spdk_bdev_get_io_channel(hello_context->bdev_desc);
    if (hello_context->bdev_io_channel == NULL) {
        SPDK_ERRLOG("Could not create bdev I/O channel!!\n");
        spdk_bdev_close(hello_context->bdev_desc);
        spdk_app_stop(-1);
        return;
    }

    /* Allocate memory for the write buffer.
    * Initialize the write buffer with the string "Hello World!"
    */
    blk_size = spdk_bdev_get_block_size(hello_context->bdev);
    buf_align = spdk_bdev_get_buf_align(hello_context->bdev);
    hello_context->buff_len = blk_size * span_length;
    hello_context->blk_size = blk_size;
    hello_context->buf_align = buf_align;
    hello_context->buff = (char*) spdk_dma_zmalloc(hello_context->buff_len, buf_align, NULL);
    if (!hello_context->buff) {
        SPDK_ERRLOG("Failed to allocate buffer\n");
        spdk_put_io_channel(hello_context->bdev_io_channel);
        spdk_bdev_close(hello_context->bdev_desc);
        spdk_app_stop(-1);
        return;
    }

    for(int i = 0; i < kCtxPoolSize; ++i) {
        hello_context_t* hello_context = alloc_context();
        g_context_mempool->enqueue(hello_context);

    }
}

void spdk_KVStore::Write(void* src, uint64_t offset, uint64_t length) {
    hello_context_t* hello_context;
    bool found;
    do {
        found = g_context_mempool->try_dequeue(hello_context);
        if (!found) {
            SPDK_ERRLOG("run out of bdev_context");
        }
    } while (!found);
    hello_context->offset = offset;
    hello_context->length = length;
    memcpy(hello_context->buff, src, length * hello_context->blk_size);

    spdk_thread_send_msg(g_spdk_thread, hello_write, hello_context);
    sem_wait(&hello_context->sem);
}


void spdk_KVStore::Read(void* dst, uint64_t offset, uint64_t length) {
    hello_context_t* hello_context;
    bool found;
    do {
        found = g_context_mempool->try_dequeue(hello_context);
        if (!found) {
            SPDK_ERRLOG("run out of bdev_context");
        }
    } while (!found);
    hello_context->offset = offset;
    hello_context->length = length;

    spdk_thread_send_msg(g_spdk_thread, hello_read, hello_context);
    sem_wait(&hello_context->sem);
    memcpy(dst, hello_context->buff, length * hello_context->blk_size);
}


spdk_KVStore::spdk_KVStore(const std::string &_conf, const std::string &_bdev_name): KVStore(_conf, _bdev_name) {
    g_hello_context = new hello_context_t();
    g_context_mempool = new moodycamel::ReaderWriterQueue<hello_context_t*>(kCtxPoolSize);
    int rc;

    struct spdk_app_opts *opts = new struct spdk_app_opts;

    sem_init(&g_hello_context->sem, 0, 0);

    spdk_app_opts_init(opts, sizeof(*opts));
    opts->name = "kvstore";
    opts->json_config_file = _conf.c_str();
    opts->reactor_mask = "0x3000";

    g_hello_context->bdev_name = _bdev_name.c_str();

	SPDK_NOTICELOG("before start, conf: %s\n", _conf.c_str());

    rc = spdk_app_start(opts, kvstore_start, g_hello_context);

    if (rc) {
        delete opts;
        SPDK_ERRLOG("cannot start kvstore\n");
    }
}

KVStore* NewSpdkKVStore(const std::string &conf, const std::string &bdev_name) {
	return new spdk_KVStore(conf, bdev_name);
}

}
