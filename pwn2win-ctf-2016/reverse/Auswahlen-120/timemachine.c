#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(ENABLE_TRACE)
#define TRACE(...) printf(__VA_ARGS__)
#else
#define TRACE(...) do{}while(0)
#endif

typedef int (*select_fn)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
typedef int (*clock_gettime_fn)(clockid_t clk_id, struct timespec *tp);
typedef ssize_t (*write_fn)(int fd, const void *buf, size_t count);
typedef ssize_t (*read_fn)(int fd, void *buf, size_t count);

static select_fn real_select = NULL;
static clock_gettime_fn real_clock_gettime = NULL;
static write_fn real_write = NULL;
static read_fn real_read = NULL;


static struct timespec last_time;
static struct timespec next_time;

typedef enum {
	LAST_TIME_INVALID,
	NEXT_TIME_INVALID,
	WAIT_STARCROSS,
	GOT_STARCROSS,
} state_t;

static state_t state = LAST_TIME_INVALID;


int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
	if (real_select == NULL) {
		real_select = (select_fn)dlsym(RTLD_NEXT,"select");
	}

	if (state == GOT_STARCROSS) {
		FD_SET(STDIN_FILENO, readfds);
		return 1;
	}

	int res;

	if (timeout != NULL && (timeout->tv_sec || timeout->tv_usec)) {
		struct timeval tm = {.tv_sec = 0, .tv_usec = 1};
		res = real_select(nfds, readfds, writefds, exceptfds, &tm);
	}
	else {
		res = real_select(nfds, readfds, writefds, exceptfds, timeout);
	}

	if (res >= 0 && timeout != NULL) {
		TRACE("select: res=%d, timeout = %ld s + %ld usec\n", res, timeout->tv_sec, timeout->tv_usec);
		if (state != LAST_TIME_INVALID) {
			next_time.tv_sec = last_time.tv_sec + timeout->tv_sec;
			next_time.tv_nsec = last_time.tv_nsec + 1000*timeout->tv_usec + 500;
			if (state == NEXT_TIME_INVALID)
				state = WAIT_STARCROSS;
		}
	}
	else {
		TRACE("select: res=%d, timeout=NULL\n", res);
	}

	return res;
}


int clock_gettime(clockid_t clk_id, struct timespec *tp) {
	if (real_clock_gettime == NULL) {
		real_clock_gettime = (clock_gettime_fn)dlsym(RTLD_NEXT,"clock_gettime");
	}

	int res = real_clock_gettime(clk_id, tp);

	if (res == 0 && (state == WAIT_STARCROSS || state == GOT_STARCROSS)) {
		memcpy(tp, &next_time, sizeof(next_time));
	}

	if (res == 0 && tp != NULL && clk_id == CLOCK_MONOTONIC) {
		TRACE("clock_gettime: %ld s + %ld nsec\n", tp->tv_sec, tp->tv_nsec);
		memcpy(&last_time, tp, sizeof(last_time));
		if (state == LAST_TIME_INVALID)
			state = NEXT_TIME_INVALID;
	}

	return res;
}


ssize_t read(int fd, void *buf, size_t count) {
	if (real_read == NULL) {
		real_read = (read_fn)dlsym(RTLD_NEXT,"read");
	}
	if (fd == STDIN_FILENO && state == GOT_STARCROSS && count >= 1) {
		TRACE("read: replying to starcross\n");
		*(char*)buf = '\n';
		state = WAIT_STARCROSS;
		return 1;
	}
	return real_read(fd, buf, count);
}


ssize_t write(int fd, const void *buf, size_t count) {
	if (real_write == NULL) {
		real_write = (write_fn)dlsym(RTLD_NEXT,"write");
	}
	if (fd == STDOUT_FILENO && count >= 1 && *(char*)buf=='*') {
		TRACE("write: got starcross\n");
		if (state != WAIT_STARCROSS)
			TRACE("WARNING: write: state != WAIT_STARCROSS\n");
		state = GOT_STARCROSS;
	}
	return real_write(fd, buf, count);
}


