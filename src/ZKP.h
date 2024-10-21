#ifndef _ZKP_H_
#define _ZKP_H_

//#define SECURITY_PARAM 20

#include "../CSI-Fish/reduce.h"

typedef struct {
    int8_t e[num_primes]; 
} private_key_int8;

void private_key_to_int8(private_key_int8 *out, const private_key *in);
void addvec8( int8_t *vec1, const int8_t *vec2 );
void subvec8( int8_t *vec1, const int8_t *vec2 );
void addvec8_32( int8_t *vec1, const int32_t *vec2 );
void subvec8_32( int8_t *vec1, const int32_t *vec2 );
void action_int8(public_key *out, public_key const *in, private_key_int8 const *priv);
void randomize_vec(int8_t *vec, int sample_num);


void csi_fish_commit(private_key *b, card_t *Eb, const card_t *E1, size_t lambda);
void csi_fish_response(private_key_int8 *responce, const int8_t *challenge, 
                    const private_key *b, const private_key *mask, size_t lambda);
int8_t csi_fish_validate(const private_key_int8 *responce, const int8_t *challenge,  
                        const card_t *Eb, const card_t *E1, const card_t *E2, size_t lambda);

void stack_randomize_commit(private_key *mask_commit, stack_t *stack_commit, const stack_t *stack1, size_t lambda);
void stack_randomize_response(private_key_int8 *responce, const int8_t *challenge, 
                                const private_key *mask_commit, const private_key *masks, 
                                size_t stack_size, size_t lambda);
int8_t stack_randomize_validate(const private_key_int8 *responce, const int8_t *challenge,  
                            const stack_t *commit_stack, const stack_t *stack1, const stack_t *stack2, size_t lambda);

void shuffle_stack_commit(private_key *b, int *rand_permut, stack_t *Eb, const stack_t *E1, size_t lambda);
void shuffle_stack_response(private_key_int8 *responce_mask, int *responce_permut, 
                            const int8_t *challenge, const private_key *b, 
                            const int *commit_permut, const private_key *mask, 
                            const int *mask_permut, size_t stack_size, size_t lambda);
int8_t shuffle_stack_validate(const private_key_int8 *responce_mask, const int *responce_permut, 
                        const int8_t *challenge, const stack_t *Eb,  
                        const stack_t *E1, const stack_t *E2, size_t lambda);


void class_action_eq_commit(private_key *commit_priv_key, card_t *commit_card1, card_t *commit_card2, 
                            const card_t *E1, const card_t *E2, size_t lambda);
void class_action_eq_response(private_key_int8 *responce, const int8_t *challenge, 
                            const private_key *commit_priv_key, const private_key *mask,
                            size_t lambda);
int8_t class_action_eq_validate(const private_key_int8 *responce, const int8_t *challenge,  
                        const card_t *commit_card1, const card_t *commit_card2, 
                        const card_t *E11, const card_t *E21,
                        const card_t *E12, const card_t *E22, 
                        size_t lambda);


void fp_print(fp const *x);

#endif /* _ZKP_H_ */