#ifndef CREATE_POOL_H
#define CREATE_POOL_H value

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

#define NUM_PRIMES 74
#define POOL_SIZE 10000

extern int32_t pool[10000*NUM_PRIMES];

void reduce(int8_t *vec, int trials, int pool_vectors);

#endif