#ifndef _BENCHMARKS_H_
#define _BENCHMARKS_H_

#include <stdlib.h>
#include "protocols.h"

void stack_gen_open_stack(stack_t *open_stack, size_t stack_size, size_t player_num);
void stack_gen_close_stack(stack_t *close_stack, private_key *player_masks, const stack_t *open_stack, size_t stack_size, size_t player_num);
uint8_t stack_gen_open_stack_validate(stack_t *open_stack, card_t *control_cards, 
                                    size_t stack_size, size_t player_num, size_t lambda);
uint8_t stack_gen_close_stack_validate(stack_t *close_stack, card_t *control_cards,
                                    private_key* player_masks, const stack_t *open_stack, 
                                    size_t stack_size, size_t player_num, size_t lambda);
void pickup_card(card_t *out_card, const card_t *in_card, const private_key* player_masks, size_t player_num, size_t player_id);
uint8_t pickup_card_validate(card_t *out_card, const card_t *in_card, 
                        const private_key* player_masks, const card_t *control_cards, size_t player_num, 
                        size_t player_id, size_t lambda);

#endif /* _BENCHMARKS_H_ */