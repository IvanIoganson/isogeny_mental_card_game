#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocols.h"

void create_stack(stack_t *stack, size_t new_size)
{
    stack->size = new_size;
    stack->cards = calloc(new_size, sizeof(*stack->cards));
}

void delete_stack(stack_t *stack)
{
    stack->size = 0;
    free(stack->cards);
    stack->cards = NULL;
}

// Generate random stack /////////////////////////////////////////////////////////////////////////

void gen_rand_card(card_t *out)
{
    private_key sk;
 
    csidh_private(&sk);

    action(out, &base, &sk);
}

typedef struct {
    stack_t *stack;
    size_t start;
    size_t end;
} card_stack_part;

void *thread_gen_rand_card_stack(void *arg)
{
    card_stack_part *stack_part = (card_stack_part*) arg;
    size_t i;

    if (arg == NULL) {
        return NULL;
    }

    //LOG("START Thread gen_rand_card_stack %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    for (i = stack_part->start; i <= stack_part->end; i++)
    {
        gen_rand_card(&stack_part->stack->cards[i]);
        //LOG("%d\n", i);
    }

    //LOG("END Thread gen_rand_card_stack %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    return NULL;
}

void gen_rand_card_stack(stack_t *out_stack)
{
    pthread_t threads[THREAD_NUM];
    card_stack_part parts[THREAD_NUM];

    int i = 0;
    float card_ind = 0.f;
    for (; i < THREAD_NUM; i++) {
        parts[i].stack = out_stack;
        parts[i].start = (size_t)card_ind;
        card_ind += (float)out_stack->size / THREAD_NUM - 1.f;
        parts[i].end = (i == THREAD_NUM-1 ? out_stack->size-1 : (size_t)card_ind);
        card_ind += 1.f;
        pthread_create(&threads[i], NULL, thread_gen_rand_card_stack, (void *)&parts[i]);
    }
    for (i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
    }
}

// Randomize Stack /////////////////////////////////////////////////////////////////////////

void randomize_card(card_t *out, private_key* out_mask)
{
    csidh_private(out_mask);

    card_t in;
    memcpy(&in, out, sizeof(in));

    action(out, &in, out_mask);
}

typedef struct {
    stack_t *stack;
    private_key* out_masks;
    size_t start;
    size_t end;
} card_mask_stack_part;

void *thread_randomize_stack(void *arg)
{
    card_mask_stack_part *stack_part = (card_mask_stack_part*) arg;
    size_t i;

    if (arg == NULL) {
        return NULL;
    }

    //LOG("START Thread randomize_card %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    for (i = stack_part->start; i <= stack_part->end; i++)
    {
        if (stack_part->out_masks) {
            randomize_card(&stack_part->stack->cards[i], &stack_part->out_masks[i]);
        } else {
            private_key _pk;
            randomize_card(&stack_part->stack->cards[i], &_pk);
        }
        //LOG("%d\n", i);
    }

    //LOG("END Thread randomize_card %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    return NULL;
}

void randomize_stack(stack_t *out_stack, private_key* out_masks)
{
    pthread_t threads[THREAD_NUM];
    card_mask_stack_part parts[THREAD_NUM];

    int i = 0;
    float card_ind = 0.f;
    for (; i < THREAD_NUM; i++) {
        parts[i].stack = out_stack;
        parts[i].out_masks = out_masks;
        parts[i].start = (size_t)card_ind;
        card_ind += (float)out_stack->size / THREAD_NUM - 1.f;
        parts[i].end = (i == THREAD_NUM-1 ? out_stack->size-1 : (size_t)card_ind);
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
    stack_t *out_stack;
    const stack_t *in_stack;
    size_t start;
    size_t end;
    const private_key* mask;
} card_stack_part_mask;

void *thread_mask_stack(void *arg)
{
    card_stack_part_mask *stack_part = (card_stack_part_mask*) arg;
    size_t i;

    if (arg == NULL) {
        return NULL;
    }

    //LOG("START Thread mask_stack %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    for (i = stack_part->start; i <= stack_part->end; i++)
    {
        mask_card(&stack_part->out_stack->cards[i], &stack_part->in_stack->cards[i], stack_part->mask);
        //LOG("%d\n", i);
    }

    //LOG("END Thread mask_stack %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    return NULL;
}

void gen_rand_permut(int *rand_permut, size_t stack_size)
{
    size_t i;
    for (i = 0; i < stack_size; i++){
        rand_permut[i] = i;
    }
    for (i = 0; i < stack_size; i++){
        int j = rand() % stack_size;
        int ttt = rand_permut[i];
        rand_permut[i] = rand_permut[j];
        rand_permut[j] = ttt;
    }
}

void shuffle_stack(stack_t *out_stack, int* out_permut)
{
    size_t i;
    stack_t _stack;

    create_stack(&_stack, out_stack->size);

    for (i = 0; i < out_stack->size; i++){
        memcpy(&_stack.cards[i].A, &out_stack->cards[i].A, sizeof(fp)); //fp_copy(_stack[i], out_stack[i]);
    }

    gen_rand_permut(out_permut, out_stack->size);
    //LOG("Rand permutation: [");
    for (i = 0; i < out_stack->size; i++){
        //LOG("%d%s" , out_permut[i], (i == out_stack->size - 1 ? "]\n" : ", "));
        memcpy(&out_stack->cards[i].A, &_stack.cards[out_permut[i]].A, sizeof(fp)); //fp_copy(out_stack[i], _stack[out_permut[i]]);
    }

    delete_stack(&_stack);
}

void mask_and_shuffle_stack(stack_t *out_stack, private_key* out_mask, int* out_permut, const stack_t *in_stack)
{
    pthread_t threads[THREAD_NUM];
    card_stack_part_mask parts[THREAD_NUM];

    csidh_private(out_mask);

    int i = 0;
    float card_ind = 0.f;
    for (; i < THREAD_NUM; i++) {
        parts[i].out_stack = out_stack;
        parts[i].in_stack = in_stack;
        parts[i].start = (size_t)card_ind;
        card_ind += (float)out_stack->size / THREAD_NUM - 1.f;
        parts[i].end = (i == THREAD_NUM-1 ? out_stack->size-1 : (size_t)card_ind);
        card_ind += 1.f;
        parts[i].mask = out_mask;
        pthread_create(&threads[i], NULL, thread_mask_stack, (void *)&parts[i]);
    }
    for (i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
    }  

    shuffle_stack(out_stack, out_permut);
}