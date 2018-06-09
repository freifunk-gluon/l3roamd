#pragma once
#include <time.h>

struct timespec timeAdd(struct timespec *t1, struct timespec *t2);
int timespec_cmp(struct timespec a, struct timespec b);
