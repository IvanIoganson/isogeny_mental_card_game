#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocols.h"

// Generate random stack /////////////////////////////////////////////////////////////////////////

void gen_rand_card(card_t *out)
{
    private_key sk;
 
    csidh_private(&sk);

    action(out, &base, &sk);
}

typedef struct {
    card_t *stack;
    int start;
    int end;
} card_stack_part;

void *thread_gen_rand_card_stack(void *arg)
{
    card_stack_part *stack_part = (card_stack_part*) arg;
    int i;

    if (arg == NULL) {
        return NULL;
    }

    //LOG("START Thread gen_rand_card_stack %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    for (i = stack_part->start; i <= stack_part->end; i++)
    {
        gen_rand_card(&stack_part->stack[i]);
        //LOG("%d\n", i);
    }

    //LOG("END Thread gen_rand_card_stack %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    return NULL;
}

void gen_rand_card_stack(card_t *out)
{
    pthread_t threads[THREAD_NUM];
    card_stack_part parts[THREAD_NUM];

    int i = 0;
    float card_ind = 0.f;
    for (; i < THREAD_NUM; i++) {
        parts[i].stack = out;
        parts[i].start = (int)card_ind;
        card_ind += (float)CARD_NUM / THREAD_NUM - 1.f;
        parts[i].end = (i == THREAD_NUM-1 ? CARD_NUM-1 : (int)card_ind);
        card_ind += 1.f;
        pthread_create(&threads[i], NULL, thread_gen_rand_card_stack, (void *)&parts[i]);
    }
    for (i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
    }
}

// Randomize Stack /////////////////////////////////////////////////////////////////////////

void randomize_card(card_t *out)
{
    private_key sk;
    csidh_private(&sk);

    card_t in;
    memcpy(&in, out, sizeof(in));

    action(out, &in, &sk);
}

void *thread_randomize_stack(void *arg)
{
    card_stack_part *stack_part = (card_stack_part*) arg;
    int i;

    if (arg == NULL) {
        return NULL;
    }

    //LOG("START Thread randomize_card %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    for (i = stack_part->start; i <= stack_part->end; i++)
    {
        randomize_card(&stack_part->stack[i]);
        //LOG("%d\n", i);
    }

    //LOG("END Thread randomize_card %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    return NULL;
}

void randomize_stack(card_t *out)
{
    pthread_t threads[THREAD_NUM];
    card_stack_part parts[THREAD_NUM];

    int i = 0;
    float card_ind = 0.f;
    for (; i < THREAD_NUM; i++) {
        parts[i].stack = out;
        parts[i].start = (int)card_ind;
        card_ind += (float)CARD_NUM / THREAD_NUM - 1.f;
        parts[i].end = (i == THREAD_NUM-1 ? CARD_NUM-1 : (int)card_ind);
        card_ind += 1.f;
        pthread_create(&threads[i], NULL, thread_randomize_stack, (void *)&parts[i]);
    }
    for (i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
    }
}

// Mask and Shuffle /////////////////////////////////////////////////////////////////////////

void mask_card(card_t *out, const card_t *in, const private_key *mask)
{
    action(out, in, mask);    
}

private_key inv_mask(const private_key *mask)
{
    private_key res = {0};
    int8_t buf[num_primes];

    int i = 0;
    for (; i < num_primes; i++){
        buf[i] = -((int8_t) (mask->e[i / 2] << i % 2 * 4) >> 4);  
    } 

    for (i = 0; i < num_primes; i++) {
        res.e[i / 2] |= (buf[i] & 0xf) << (i + 1) % 2 * 4;
    }

    return res;
}

void unmask_card(card_t *out, const card_t *in, const private_key *mask)
{
    private_key unmask = inv_mask(mask);
    
    action(out, in, &unmask);    
}

typedef struct {
    card_t *out_stack;
    const card_t *in_stack;
    int start;
    int end;
    const private_key* mask;
} card_stack_part_mask;

void *thread_mask_stack(void *arg)
{
    card_stack_part_mask *stack_part = (card_stack_part_mask*) arg;
    int i;

    if (arg == NULL) {
        return NULL;
    }

    //LOG("START Thread mask_stack %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    for (i = stack_part->start; i <= stack_part->end; i++)
    {
        mask_card(&stack_part->out_stack[i], &stack_part->in_stack[i], stack_part->mask);
        //LOG("%d\n", i);
    }

    //LOG("END Thread mask_stack %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    return NULL;
}

void gen_rand_permut(int *rand_permut)
{
    int i;
    for (i = 0; i < CARD_NUM; i++){
        rand_permut[i] = i;
    }
    for (i = 0; i < CARD_NUM; i++){
        int j = rand() % CARD_NUM;
        int ttt = rand_permut[i];
        rand_permut[i] = rand_permut[j];
        rand_permut[j] = ttt;
    }
}

void shuffle_stack(card_t *out_stack, int* out_permut)
{
    int i;
    card_t _stack[CARD_NUM];

    for (i = 0; i < CARD_NUM; i++){
        memcpy(&_stack[i].A, &out_stack[i].A, sizeof(fp)); //fp_copy(_stack[i], out_stack[i]);
    }

    gen_rand_permut(out_permut);
    LOG("Rand permutation: [");
    for (i = 0; i < CARD_NUM; i++){
        LOG("%d%s" , out_permut[i], (i == CARD_NUM - 1 ? "]\n" : ", "));
        memcpy(&out_stack[i].A, &_stack[out_permut[i]].A, sizeof(fp)); //fp_copy(out_stack[i], _stack[out_permut[i]]);
    }
}

void mask_and_shuffle_stack(card_t *out_stack, private_key* out_mask, int* out_permut, const card_t *in_stack)
{
    pthread_t threads[THREAD_NUM];
    card_stack_part_mask parts[THREAD_NUM];

    csidh_private(out_mask);

    int i = 0;
    float card_ind = 0.f;
    for (; i < THREAD_NUM; i++) {
        parts[i].out_stack = out_stack;
        parts[i].in_stack = in_stack;
        parts[i].start = (int)card_ind;
        card_ind += (float)CARD_NUM / THREAD_NUM - 1.f;
        parts[i].end = (i == THREAD_NUM-1 ? CARD_NUM-1 : (int)card_ind);
        card_ind += 1.f;
        parts[i].mask = out_mask;
        pthread_create(&threads[i], NULL, thread_mask_stack, (void *)&parts[i]);
    }
    for (i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
    }  

    shuffle_stack(out_stack, out_permut);
}