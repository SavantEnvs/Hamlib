/*
 * Virtual-time mock of libc, linked into every harness with
 *   -Wl,--wrap=usleep -Wl,--wrap=nanosleep -Wl,--wrap=clock_gettime   (see build.sh).
 * The dummy backend simulates radio latency with usleep(20 ms) and the real backends pause between retries
 * through hl_usleep(), which sleeps and then spins on CLOCK_MONOTONIC until the time has passed. A sleep here
 * just advances a virtual offset that clock_gettime() adds, so waiting costs nothing and hl_usleep() still
 * sees its deadline pass. The offset is reset at the start of every input.
 */
#include <time.h>
#include <unistd.h>

int __real_clock_gettime(clockid_t clk, struct timespec *ts);
int __wrap_clock_gettime(clockid_t clk, struct timespec *ts);
int __wrap_usleep(useconds_t usec);
int __wrap_nanosleep(const struct timespec *req, struct timespec *rem);
void mayhem_clock_reset(void);

static long long virtual_ns;

void mayhem_clock_reset(void)
{
    virtual_ns = 0;
}

int __wrap_clock_gettime(clockid_t clk, struct timespec *ts)
{
    int ret = __real_clock_gettime(clk, ts);

    if (ret == 0 && virtual_ns != 0)
    {
        long long ns = ts->tv_nsec + virtual_ns % 1000000000LL;
        ts->tv_sec += virtual_ns / 1000000000LL + ns / 1000000000LL;
        ts->tv_nsec = ns % 1000000000LL;
    }

    return ret;
}

int __wrap_usleep(useconds_t usec)
{
    virtual_ns += (long long) usec * 1000;
    return 0;
}

int __wrap_nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void) rem;
    virtual_ns += (long long) req->tv_sec * 1000000000LL + req->tv_nsec;
    return 0;
}
