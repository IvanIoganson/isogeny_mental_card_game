#ifndef _PROTOCOLS_H_
#define _PROTOCOLS_H_

#include "defines.h"
#include "../faster-csidh/csidh.h"

#define CARD_NUM 36
#define THREAD_NUM CARD_NUM
//#define N (num_primes + 1) / 2

typedef public_key card_t;

void gen_rand_card(card_t *out);
void gen_rand_card_stack(card_t *out);
void randomize_stack(card_t *out);
void mask_and_shuffle_stack(card_t *out_stack, private_key* out_mask, int* out_permut, const card_t *in_stack);

void gen_rand_permut(int *rand_permut);
private_key inv_mask(const private_key *mask);
void mask_card(card_t *out, const card_t *in, const private_key *mask);
void unmask_card(card_t *out, const card_t *in, const private_key *mask);

#endif /* _PROTOCOLS_H_ */