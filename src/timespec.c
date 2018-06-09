#include <time.h>

#define BILLION 1000000000l
struct timespec timeAdd(struct timespec *t1, struct timespec *t2)
{
    long sec = t2->tv_sec + t1->tv_sec;
    long nsec = t2->tv_nsec + t1->tv_nsec;
    if (nsec >= BILLION) {
        nsec -= BILLION;
        sec++;
    }
    return (struct timespec){ .tv_sec = sec, .tv_nsec = nsec };
}

int timespec_cmp(struct timespec a, struct timespec b) {
	if      (a.tv_sec  < b.tv_sec )	return -1;
	else if (a.tv_sec  > b.tv_sec )	return +1;
	else if (a.tv_nsec < b.tv_nsec)	return -1;
	else if (a.tv_nsec > b.tv_nsec)	return +1;

	return 0 ;
}
