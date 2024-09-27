#ifndef _ZKP_H_
#define _ZKP_H_

#define SECURITY_PARAM 20

#include "../CSI-Fish/reduce.h"

void private_key_to_int8(int8_t *out, const struct private_key *in);
void addvec8( int8_t *vec1, const int8_t *vec2 );
void subvec8( int8_t *vec1, const int8_t *vec2 );
void action_int8(struct public_key *out, struct public_key const *in, int8_t const *priv);
void randomize_vec(int8_t *vec, int sample_num);

void csi_fish_commit(private_key *b, card_t *Eb, const card_t *E1);
void csi_fish_response(int8_t *responce, const int8_t *challenge, const private_key *b, const private_key *mask);
int8_t csi_fish_validate(const int8_t *responce, const int8_t *challenge,  
                        const card_t *Eb, const card_t *E1, const card_t *E2);

void shuffle_stack_commit(private_key *b, int *rand_permut, card_t *Eb, const card_t *E1);
void shuffle_stack_response(int8_t *responce_mask, int *responce_permut, const int8_t *challenge, const private_key *b, const int *commit_permut, const private_key *mask, const int *mask_permut);
int8_t shuffle_stack_validate(const int8_t *responce_mask, const int *responce_permut, 
                        const int8_t *challenge, const card_t *Eb,  
                        const card_t *E1, const card_t *E2);

void class_action_eq_commit(private_key *commit_priv_key, card_t *commit_card1, card_t *commit_card2, const card_t *E1, const card_t *E2);
void class_action_eq_response(int8_t *responce, const int8_t *challenge, const private_key *commit_priv_key, const private_key *mask);
int8_t class_action_eq_validate(const int8_t *responce, const int8_t *challenge,  
                        const card_t *commit_card1, const card_t *commit_card2, 
                        const card_t *E11, const card_t *E21,
                        const card_t *E12, const card_t *E22);

void fp_print(fp const *x);

#endif /* _ZKP_H_ */