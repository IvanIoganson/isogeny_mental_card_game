#ifndef _PROTOCOLS_H_
#define _PROTOCOLS_H_

#include "defines.h"
#include "../faster-csidh/csidh.h"

//#define CARD_NUM 36
#define THREAD_NUM 16
//#define N (num_primes + 1) / 2

typedef public_key card_t;

typedef struct {
    size_t size;
    card_t *cards;
} stack_t;

void create_stack(stack_t *stack, size_t new_size);
void delete_stack(stack_t *stack);
void gen_rand_card(card_t *out);
void gen_rand_card_stack(stack_t *out_stack);
void randomize_card(card_t *out, private_key* out_mask);
void randomize_stack(stack_t *out_stack, private_key* out_masks);
void mask_card(card_t *out, const card_t *in, const private_key *mask);
private_key inv_mask(const private_key *mask);
void unmask_card(card_t *out, const card_t *in, const private_key *mask);
void gen_rand_permut(int *rand_permut, size_t stack_size);
void shuffle_stack(stack_t *out_stack, int* out_permut);
void mask_and_shuffle_stack(stack_t *out_stack, private_key* out_mask, int* out_permut, const stack_t *in_stack);

#endif /* _PROTOCOLS_H_ */