#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "libcryptsetup.h"
#include "internal.h"

static char *error=NULL;

void set_error_va(const char *fmt, va_list va)
{
	int r;

	if(error) {
		free(error);
		error = NULL;
	}

	if(!fmt) return;

	r = vasprintf(&error, fmt, va);
	if (r < 0) {
		free(error);
		error = NULL;
		return;
	}

	if (r && error[r - 1] == '\n')
		error[r - 1] = '\0';
}

void set_error(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	set_error_va(fmt, va);
	va_end(va);
}

const char *get_error(void)
{
	return error;
}

static int get_alignment(int fd)
{
	int alignment = DEFAULT_MEM_ALIGNMENT;

#ifdef _PC_REC_XFER_ALIGN
	alignment = fpathconf(fd, _PC_REC_XFER_ALIGN);
	if (alignment < 0)
		alignment = DEFAULT_MEM_ALIGNMENT;
#endif
	return alignment;
}

static void *aligned_malloc(void **base, int size, int alignment)
{
#ifdef HAVE_POSIX_MEMALIGN
	return posix_memalign(base, alignment, size) ? NULL : *base;
#else
/* Credits go to Michal's padlock patches for this alignment code */
	char *ptr;

	ptr  = malloc(size + alignment);
	if(ptr == NULL) return NULL;

	*base = ptr;
	if(alignment > 1 && ((long)ptr & (alignment - 1))) {
		ptr += alignment - ((long)(ptr) & (alignment - 1));
	}
	return ptr;
#endif
}
static int sector_size(int fd) 
{
	int bsize;
	if (ioctl(fd,BLKSSZGET, &bsize) < 0)
		return -EINVAL;
	else
		return bsize;
}

int sector_size_for_device(const char *device)
{
	int fd = open(device, O_RDONLY);
	int r;
	if(fd < 0)
		return -EINVAL;
	r = sector_size(fd);
	close(fd);
	return r;
}

ssize_t write_blockwise(int fd, const void *orig_buf, size_t count)
{
	void *hangover_buf, *hangover_buf_base = NULL;
	void *buf, *buf_base = NULL;
	int r, hangover, solid, bsize, alignment;
	ssize_t ret = -1;

	if ((bsize = sector_size(fd)) < 0)
		return bsize;

	hangover = count % bsize;
	solid = count - hangover;
	alignment = get_alignment(fd);

	if ((long)orig_buf & (alignment - 1)) {
		buf = aligned_malloc(&buf_base, count, alignment);
		if (!buf)
			goto out;
		memcpy(buf, orig_buf, count);
	} else
		buf = (void *)orig_buf;

	r = write(fd, buf, solid);
	if (r < 0 || r != solid)
		goto out;

	if (hangover) {
		hangover_buf = aligned_malloc(&hangover_buf_base, bsize, alignment);
		if (!hangover_buf)
			goto out;

		r = read(fd, hangover_buf, bsize);
		if(r < 0 || r != bsize) goto out;

		r = lseek(fd, -bsize, SEEK_CUR);
		if (r < 0)
			goto out;
		memcpy(hangover_buf, buf + solid, hangover);

		r = write(fd, hangover_buf, bsize);
		if(r < 0 || r != bsize) goto out;
		free(hangover_buf_base);
	}
	ret = count;
 out:
	if (buf != orig_buf)
		free(buf_base);
	return ret;
}

ssize_t read_blockwise(int fd, void *orig_buf, size_t count) {
	void *hangover_buf, *hangover_buf_base;
	void *buf, *buf_base = NULL;
	int r, hangover, solid, bsize, alignment;
	ssize_t ret = -1;

	if ((bsize = sector_size(fd)) < 0)
		return bsize;

	hangover = count % bsize;
	solid = count - hangover;
	alignment = get_alignment(fd);

	if ((long)orig_buf & (alignment - 1)) {
		buf = aligned_malloc(&buf_base, count, alignment);
		if (!buf)
			goto out;
	} else
		buf = orig_buf;

	r = read(fd, buf, solid);
	if(r < 0 || r != solid)
		goto out;

	if (hangover) {
		hangover_buf = aligned_malloc(&hangover_buf_base, bsize, alignment);
		if (!hangover_buf)
			goto out;
		r = read(fd, hangover_buf, bsize);
		if (r <  0 || r != bsize)
			goto out;

		memcpy(buf + solid, hangover_buf, hangover);
		free(hangover_buf_base);
	}
	ret = count;
 out:
	if (buf != orig_buf) {
		memcpy(orig_buf, buf, count);
		free(buf_base);
	}
	return ret;
}

/* 
 * Combines llseek with blockwise write. write_blockwise can already deal with short writes
 * but we also need a function to deal with short writes at the start. But this information
 * is implicitly included in the read/write offset, which can not be set to non-aligned 
 * boundaries. Hence, we combine llseek with write.
 */

ssize_t write_lseek_blockwise(int fd, const char *buf, size_t count, off_t offset) {
	int bsize = sector_size(fd);
	const char *orig_buf = buf;
	char frontPadBuf[bsize];
	int frontHang = offset % bsize;
	int r;
	int innerCount = count < bsize ? count : bsize;

	if (bsize < 0)
		return bsize;

	lseek(fd, offset - frontHang, SEEK_SET);
	if(offset % bsize) {
		r = read(fd,frontPadBuf,bsize);
		if(r < 0) return -1;

		memcpy(frontPadBuf+frontHang, buf, innerCount);

		lseek(fd, offset - frontHang, SEEK_SET);
		r = write(fd,frontPadBuf,bsize);
		if(r < 0) return -1;

		buf += innerCount;
		count -= innerCount;
	}
	if(count <= 0) return buf - orig_buf;

	return write_blockwise(fd, buf, count) + innerCount;
}

int device_ready(struct crypt_device *cd, const char *device, int mode)
{
	int devfd, r = 1;
	ssize_t s;
	struct stat st;
	char buf[512];

	if(stat(device, &st) < 0) {
		log_err(cd, _("Device %s doesn't exist or access denied.\n"), device);
		return 0;
	}

	log_dbg("Trying to open and read device %s.", device);
	devfd = open(device, mode | O_DIRECT | O_SYNC);
	if(devfd < 0) {
		log_err(cd, _("Cannot open device %s for %s%s access.\n"), device,
			(mode & O_EXCL) ? _("exclusive ") : "",
			(mode & O_RDWR) ? _("writable") : _("read-only"));
		return 0;
	}

	 /* Try to read first sector */
	s = read_blockwise(devfd, buf, sizeof(buf));
	if (s < 0 || s != sizeof(buf)) {
		log_err(cd, _("Cannot read device %s.\n"), device);
		r = 0;
	}

	memset(buf, 0, sizeof(buf));
	close(devfd);

	return r;
}

int get_device_infos(const char *device, struct device_infos *infos, struct crypt_device *cd)
{
	uint64_t size;
	unsigned long size_small;
	int readonly = 0;
	int ret = -1;
	int fd;

	/* Try to open read-write to check whether it is a read-only device */
	fd = open(device, O_RDWR);
	if (fd < 0) {
		if (errno == EROFS) {
			readonly = 1;
			fd = open(device, O_RDONLY);
		}
	} else {
		close(fd);
		fd = open(device, O_RDONLY);
	}
	if (fd < 0) {
		log_err(cd, _("Cannot open device: %s\n"), device);
		return -1;
	}

#ifdef BLKROGET
	/* If the device can be opened read-write, i.e. readonly is still 0, then
	 * check whether BKROGET says that it is read-only. E.g. read-only loop
	 * devices may be openend read-write but are read-only according to BLKROGET
	 */
	if (readonly == 0 && ioctl(fd, BLKROGET, &readonly) < 0) {
		log_err(cd, _("BLKROGET failed on device %s.\n"), device);
		goto out;
	}
#else
#error BLKROGET not available
#endif

#ifdef BLKGETSIZE64
	if (ioctl(fd, BLKGETSIZE64, &size) >= 0) {
		size >>= SECTOR_SHIFT;
		ret = 0;
		goto out;
	}
#endif

#ifdef BLKGETSIZE
	if (ioctl(fd, BLKGETSIZE, &size_small) >= 0) {
		size = (uint64_t)size_small;
		ret = 0;
		goto out;
	}
#else
#	error Need at least the BLKGETSIZE ioctl!
#endif

	log_err(cd, _("BLKGETSIZE failed on device %s.\n"), device);
out:
	if (ret == 0) {
		infos->size = size;
		infos->readonly = readonly;
	}
	close(fd);
	return ret;
}

int wipe_device_header(const char *device, int sectors)
{
	char *buffer;
	int size = sectors * SECTOR_SIZE;
	int r = -1;
	int devfd;

	devfd = open(device, O_RDWR | O_DIRECT | O_SYNC);
	if(devfd == -1)
		return -EINVAL;

	buffer = malloc(size);
	if (!buffer) {
		close(devfd);
		return -ENOMEM;
	}
	memset(buffer, 0, size);

	r = write_blockwise(devfd, buffer, size) < size ? -EIO : 0;

	free(buffer);
	close(devfd);

	return r;
}

/* MEMLOCK */
#define DEFAULT_PROCESS_PRIORITY -18

static int _priority;
static int _memlock_count = 0;

// return 1 if memory is locked
int crypt_memlock_inc(struct crypt_device *ctx)
{
	if (!_memlock_count++) {
		log_dbg("Locking memory.");
		if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
			log_err(ctx, _("WARNING!!! Possibly insecure memory. Are you root?\n"));
			_memlock_count--;
			return 0;
		}
		errno = 0;
		if (((_priority = getpriority(PRIO_PROCESS, 0)) == -1) && errno)
			log_err(ctx, _("Cannot get process priority.\n"));
		else
			if (setpriority(PRIO_PROCESS, 0, DEFAULT_PROCESS_PRIORITY))
				log_err(ctx, _("setpriority %u failed: %s"),
					DEFAULT_PROCESS_PRIORITY, strerror(errno));
	}
	return _memlock_count ? 1 : 0;
}

int crypt_memlock_dec(struct crypt_device *ctx)
{
	if (_memlock_count && (!--_memlock_count)) {
		log_dbg("Unlocking memory.");
		if (munlockall())
			log_err(ctx, _("Cannot unlock memory."));
		if (setpriority(PRIO_PROCESS, 0, _priority))
			log_err(ctx, _("setpriority %u failed: %s"), _priority, strerror(errno));
	}
	return _memlock_count ? 1 : 0;
}

/* DEVICE TOPOLOGY */

/* block device topology ioctls, introduced in 2.6.32 */
#ifndef BLKIOMIN
#define BLKIOMIN    _IO(0x12,120)
#define BLKIOOPT    _IO(0x12,121)
#define BLKALIGNOFF _IO(0x12,122)
#endif

void get_topology_alignment(const char *device,
			    unsigned long *required_alignment, /* bytes */
			    unsigned long *alignment_offset,   /* bytes */
			    unsigned long default_alignment)
{
	int dev_alignment_offset = 0;
	unsigned int min_io_size = 0, opt_io_size = 0;
	unsigned long temp_alignment = 0;
	int fd;

	*required_alignment = default_alignment;
	*alignment_offset = 0;

	fd = open(device, O_RDONLY);
	if (fd == -1)
		return;

	/* minimum io size */
	if (ioctl(fd, BLKIOMIN, &min_io_size) == -1) {
		log_dbg("Topology info for %s not supported, using default offset %lu bytes.",
			device, default_alignment);
		goto out;
	}

	/* optimal io size */
	if (ioctl(fd, BLKIOOPT, &opt_io_size) == -1)
		opt_io_size = min_io_size;

	/* alignment offset, bogus -1 means misaligned/unknown */
	if (ioctl(fd, BLKALIGNOFF, &dev_alignment_offset) == -1 || dev_alignment_offset < 0)
		dev_alignment_offset = 0;
	*alignment_offset = (unsigned long)dev_alignment_offset;

	temp_alignment = (unsigned long)min_io_size;

	if (temp_alignment < (unsigned long)opt_io_size)
		temp_alignment = (unsigned long)opt_io_size;

	/* If calculated alignment is multiple of default, keep default */
	if (temp_alignment && (default_alignment % temp_alignment))
		*required_alignment = temp_alignment;

	log_dbg("Topology: IO (%u/%u), offset = %lu; Required alignment is %lu bytes.",
		min_io_size, opt_io_size, *alignment_offset, *required_alignment);
out:
	(void)close(fd);
}
