#include <stdio.h>
#include <time.h>
#include <string.h>

#include "benchmarks.h"
#include "ZKP.h"

void stack_gen_open_stack(stack_t *open_stack, size_t stack_size, size_t player_num)
{
    stack_t _stack;
    create_stack(&_stack, stack_size);

    size_t i;
    for (i = 0; i < player_num; i++)
    {
        private_key *_masks = malloc(stack_size * sizeof(private_key));
        randomize_stack(&_stack, _masks);
        free(_masks);
    }

    memcpy(open_stack->cards, _stack.cards, stack_size * sizeof(*_stack.cards));
    delete_stack(&_stack);
}

void stack_gen_close_stack(stack_t *close_stack, private_key *player_masks, const stack_t *open_stack, size_t stack_size, size_t player_num)
{    
    stack_t _stack;
    create_stack(&_stack, stack_size);

    size_t i;
    memcpy(_stack.cards, open_stack->cards, stack_size * sizeof(*_stack.cards));

    for (i = 0; i < player_num; i++)
    {
        stack_t _next_stack;
        create_stack(&_next_stack, stack_size);
        int permit[stack_size];

        mask_and_shuffle_stack(&_next_stack, &player_masks[i], permit, &_stack);
        memcpy(_stack.cards, _next_stack.cards, stack_size * sizeof(*_stack.cards));

        delete_stack(&_next_stack);
    }

    memcpy(close_stack->cards, _stack.cards, stack_size * sizeof(*_stack.cards));

    delete_stack(&_stack);
}

uint8_t stack_gen_open_stack_validate(stack_t *open_stack, card_t *control_cards, 
                                    size_t stack_size, size_t player_num, size_t lambda)
{
    stack_t _stack;
    create_stack(&_stack, stack_size);

    memset(&control_cards[0], 0, sizeof(*control_cards));

    size_t i;
    for (i = 0; i < player_num; i++)
    {
        stack_t _next_stack;
        create_stack(&_next_stack, stack_size);
        memcpy(_next_stack.cards, _stack.cards, stack_size * sizeof(*_stack.cards));

        private_key *_masks = malloc(stack_size * sizeof(private_key));
        randomize_stack(&_next_stack, _masks);

        card_t _next_control_card;
        private_key contr_mask;
        memcpy(&_next_control_card, &control_cards[0], sizeof(_next_control_card));
        randomize_card(&_next_control_card, &contr_mask);

        private_key *_masks_commit = malloc(stack_size * lambda * sizeof(private_key));
        stack_t *_stack_commit = malloc(lambda * sizeof(stack_t));

        size_t j;
        for (j = 0; j < lambda; j++) {
            create_stack(&_stack_commit[j], stack_size);
        }

        stack_randomize_commit(_masks_commit, _stack_commit, &_stack, lambda);
        
        private_key *b = malloc(lambda * sizeof(private_key));
        card_t *Eb = malloc(lambda * sizeof(card_t));
        csi_fish_commit(b, Eb, &control_cards[0], lambda);

        int8_t *challenge = malloc(lambda * sizeof(int8_t));
        private_key_int8 *response = malloc(lambda * stack_size * sizeof(private_key_int8));;

        //printf("Challenge: ");
        for (j = 0; j < lambda; j++) {
            challenge[j] = rand() % 2;
            //printf("%d ", challenge[j]);
        }
        //printf("\n");

        stack_randomize_response(response, challenge, _masks_commit, _masks, stack_size, lambda);
        
        private_key_int8 *contr_response = malloc(lambda * sizeof(private_key_int8));;
        csi_fish_response(contr_response, challenge, b, &contr_mask, lambda);

        int8_t flag = stack_randomize_validate(response, challenge, _stack_commit, &_stack, &_next_stack, lambda);
        if (!flag)
        {
            LOG("Failed to validate randomization of Player %ld\n", i);
            return 0;
        }

        flag = csi_fish_validate(contr_response, challenge, Eb, &control_cards[0], &_next_control_card, lambda);
        if (!flag)
        {
            LOG("Failed to validate randomization of Player %ld\n", i);
            return 0;
        }

        memcpy(_stack.cards, _next_stack.cards, stack_size * sizeof(*_stack.cards));
        memcpy(&control_cards[0], &_next_control_card, sizeof(_next_control_card));

        for (j = 0; j < lambda; j++) {
            delete_stack(&_stack_commit[j]);
        }

        delete_stack(&_next_stack);
        free(contr_response);
        free(_stack_commit);
        free(_masks_commit);
        free(_masks);
        free(response);
        free(challenge);
        free(b);
        free(Eb);
        LOG("Player %ld randomize stack\n", i);
    }

    memcpy(open_stack->cards, _stack.cards, stack_size * sizeof(*_stack.cards));
    LOG("open_stack done!\n");

    delete_stack(&_stack);

    return 1;
}

uint8_t stack_gen_close_stack_validate(stack_t *close_stack, card_t *control_cards,
                                    private_key* player_masks, const stack_t *open_stack, 
                                    size_t stack_size, size_t player_num, size_t lambda)
{
    stack_t _stack;
    create_stack(&_stack, stack_size);
    memcpy(_stack.cards, open_stack->cards, _stack.size * sizeof(*_stack.cards));
        
    size_t i;
    for (i = 0; i < player_num; i++)
    {
        stack_t _next_stack;
        create_stack(&_next_stack, stack_size);
        private_key mask;
        int permit[stack_size];

        mask_and_shuffle_stack(&_next_stack, &mask, permit, &_stack);
        mask_card(&control_cards[i+1], &control_cards[i], &mask);

        memcpy(&player_masks[i], &mask, sizeof(mask));

        private_key *commit_mask = malloc(lambda * sizeof(private_key));
        int *commit_pemut = malloc(stack_size * lambda * sizeof(int));
        stack_t *commit_stack = malloc(lambda * sizeof(stack_t));

        size_t j;
        for (j = 0; j < lambda; j++) {
            create_stack(&commit_stack[j], stack_size);	
        }

        shuffle_stack_commit(commit_mask, commit_pemut, commit_stack, &_stack, lambda);
        private_key *b = malloc(lambda * sizeof(private_key));
        card_t *Eb = malloc(lambda * sizeof(card_t));
        csi_fish_commit(b, Eb, &control_cards[i], lambda);

        private_key_int8 *responce_mask = malloc(lambda * sizeof(private_key_int8));
        int8_t *challenge = malloc(lambda * sizeof(int8_t));
        int *responce_pemut = malloc(lambda * stack_size * sizeof(int));
        
        for (j = 0; j < lambda; j++) {
            challenge[j] = rand() % 2;
        }

        shuffle_stack_response(responce_mask, responce_pemut, challenge, commit_mask, commit_pemut, &mask, permit, stack_size, lambda);
        private_key_int8 *contr_response = malloc(lambda * sizeof(private_key_int8));
        csi_fish_response(contr_response, challenge, b, &mask, lambda);

        int8_t flag = shuffle_stack_validate(responce_mask, responce_pemut, challenge, commit_stack, &_stack, &_next_stack, lambda);
        if (!flag)
        {
            LOG("Failed to validate shuffle of Player %ld\n", i);
            return 0;
        }
        flag = csi_fish_validate(contr_response, challenge, Eb, &control_cards[i], &control_cards[i+1], lambda);
        if (!flag)
        {
            LOG("Failed to validate shuffle of Player %ld\n", i);
            return 0;
        }

        memcpy(_stack.cards, _next_stack.cards, stack_size * sizeof(*_stack.cards));

        for (j = 0; j < lambda; j++) {
            delete_stack(&commit_stack[j]);	
        }
        delete_stack(&_next_stack);
        free(contr_response);
        free(b);
        free(Eb);
        free(responce_pemut);
        free(challenge);
        free(responce_mask);
        free(commit_stack);
        free(commit_pemut);
        free(commit_mask);
        LOG("Player %ld shuffle stack\n", i);
    }

    memcpy(close_stack->cards, _stack.cards, stack_size * sizeof(*_stack.cards));
    LOG("close_stack done!\n");

    delete_stack(&_stack);

    return 1;
}

void pickup_card(card_t *out_card, const card_t *in_card, const private_key* player_masks, size_t player_num, size_t player_id)
{
    card_t _card;
    memcpy(&_card, in_card, sizeof(_card));

    size_t i;
    for (i = 0; i < player_num; i++)
    {
        if (i == player_id) {
            continue;
        }

        card_t _next_card;
        unmask_card(&_next_card, &_card, &player_masks[i]);
        memcpy(&_card, &_next_card, sizeof(_card));
    }

    unmask_card(out_card, &_card, &player_masks[player_id]);
}


uint8_t pickup_card_validate(card_t *out_card, const card_t *in_card, 
                        const private_key* player_masks, const card_t *control_cards, size_t player_num, 
                        size_t player_id, size_t lambda)
{
    card_t _card;
    memcpy(&_card, in_card, sizeof(_card));

    size_t i;
    for (i = 0; i < player_num; i++)
    {
        if (i == player_id) {
            continue;
        }

        card_t _next_card;
        unmask_card(&_next_card, &_card, &player_masks[i]);

        private_key *commit_priv_key = malloc(lambda * sizeof(private_key));
        card_t *commit_card1 = malloc(lambda * sizeof(card_t));
        card_t *commit_card2 = malloc(lambda * sizeof(card_t));
        class_action_eq_commit(commit_priv_key, commit_card1, commit_card2, &_next_card, &control_cards[i], lambda);

        private_key_int8 *responce = malloc(lambda * sizeof(private_key_int8));
        int8_t *challenge = malloc(lambda * sizeof(int8_t));
        
        size_t j;
        for (j = 0; j < lambda; j++) {
            challenge[j] = rand() % 2;
        }
        
        class_action_eq_response(responce, challenge, commit_priv_key, &player_masks[i], lambda);

        int8_t flag = class_action_eq_validate(responce, challenge, commit_card1, commit_card2, &_next_card, &control_cards[i], 
            &_card, &control_cards[i+1], lambda);

        if (!flag)
        {
            LOG("Failed to validate opening card of Player %ld\n", i);
            return 0;
        }

        memcpy(&_card, &_next_card, sizeof(_card));
        free(challenge);
        free(responce);
        free(commit_card2);
        free(commit_card1);
        free(commit_priv_key);
        LOG("Player %ld open card\n", i);
    }

    {
        unmask_card(out_card, &_card, &player_masks[player_id]);

        private_key *commit_priv_key = malloc(lambda * sizeof(private_key));
        card_t *commit_card1 = malloc(lambda * sizeof(card_t));
        card_t *commit_card2 = malloc(lambda * sizeof(card_t));
        class_action_eq_commit(commit_priv_key, commit_card1, commit_card2, out_card, &control_cards[player_id], lambda);

        private_key_int8 *responce = malloc(lambda * sizeof(private_key_int8));
        int8_t *challenge = malloc(lambda * sizeof(int8_t));
        
        size_t j;
        for (j = 0; j < lambda; j++) {
            challenge[j] = rand() % 2;
        }
        
        class_action_eq_response(responce, challenge, commit_priv_key, &player_masks[player_id], lambda);

        int8_t flag = class_action_eq_validate(responce, challenge, 
            commit_card1, commit_card2, out_card, &control_cards[player_id], 
            &_card, &control_cards[player_id+1], lambda);

        if (!flag)
        {
            LOG("Failed to validate opening card of Player %ld\n", player_id);
            return 0;
        }

        free(challenge);
        free(responce);
        free(commit_card2);
        free(commit_card1);
        free(commit_priv_key);
        LOG("Player %ld open card\n", player_id);
    }
    
    LOG("card opened!\n");
    return 1;
}