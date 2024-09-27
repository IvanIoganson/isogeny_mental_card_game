#include <pthread.h>
#include <assert.h>
#include <stdio.h>

#include "../faster-csidh/mont.h"
#include "protocols.h"

#include "ZKP.h"

void private_key_to_int8(int8_t *out, const private_key *in)
{
    int i = 0;
	for (;i < num_primes; i++){
        //LOG("%d\n", i);
		out[i] = (int8_t) (in->e[i / 2] << i % 2 * 4) >> 4;
    }
}

void addvec8( int8_t *vec1, const int8_t *vec2 ){
	for(int i=0; i<num_primes ; i++){
		vec1[i]+=vec2[i];
	}
}

void subvec8( int8_t *vec1, const int8_t *vec2 ){
	for(int i=0; i<num_primes ; i++){
		vec1[i]-=vec2[i];
	}
}

void addvec8_32( int8_t *vec1, const int32_t *vec2 ){
	for(int i=0; i<num_primes ; i++){
		vec1[i]+=(int8_t)vec2[i];
	}
}

void subvec8_32( int8_t *vec1, const int32_t *vec2 ){
	for(int i=0; i<num_primes ; i++){
		vec1[i]-=(int8_t)vec2[i];
	}
}

/* compute x^3 + Ax^2 + x */
static void montgomery_rhs(fp *rhs, fp const *A, fp const *x)
{
    fp tmp;
    *rhs = *x;
    fp_sq1(rhs);
    fp_mul3(&tmp, A, x);
    fp_add2(rhs, &tmp);
    fp_add2(rhs, &fp_1);
    fp_mul2(rhs, x);
}

void action_int8(public_key *out, public_key const *in, int8_t const *priv)
{
    u512 k[2];
    u512_set(&k[0], 4); /* maximal 2-power in p+1 */
    u512_set(&k[1], 4); /* maximal 2-power in p+1 */

    uint8_t e[2][num_primes];

    for (size_t i = 0; i < num_primes; ++i) {

        int8_t t = priv[i];

        if (t > 0) {
            e[0][i] = t;
            e[1][i] = 0;
            u512_mul3_64(&k[1], &k[1], primes[i]);
        }
        else if (t < 0) {
            e[1][i] = -t;
            e[0][i] = 0;
            u512_mul3_64(&k[0], &k[0], primes[i]);
        }
        else {
            e[0][i] = 0;
            e[1][i] = 0;
            u512_mul3_64(&k[0], &k[0], primes[i]);
            u512_mul3_64(&k[1], &k[1], primes[i]);
        }
    }

    proj A = {in->A, fp_1};

    bool done[2] = {false, false};

    do {

        assert(!memcmp(&A.z, &fp_1, sizeof(fp)));

        proj P;
        fp_random(&P.x);
        P.z = fp_1;

        fp rhs;
        montgomery_rhs(&rhs, &A.x, &P.x);
        bool sign = !fp_issquare(&rhs);

        if (done[sign])
            continue;

        xMUL(&P, &A, &P, &k[sign]);

        done[sign] = true;

        for (size_t i = num_primes-1; i < num_primes; --i) {  //changed loop direction

            if (e[sign][i]) {

                u512 cof = u512_1;
                for (size_t j = i - 1; j < num_primes; --j)   //changed loop direction
                    if (e[sign][j])
                        u512_mul3_64(&cof, &cof, primes[j]);

                proj K;
                xMUL(&K, &A, &P, &cof);

                if (memcmp(&K.z, &fp_0, sizeof(fp))) {

                    xISOG(&A, &P, &K, primes[i]);

                    if (!--e[sign][i])
                        u512_mul3_64(&k[sign], &k[sign], primes[i]);

                }

            }

            done[sign] &= !e[sign][i];
        }

        fp_inv(&A.z);
        fp_mul2(&A.x, &A.z);
        A.z = fp_1;

    } while (!(done[0] && done[1]));

    out->A = A.x;
}

void randomize_vec(int8_t *vec, int sample_num)
{
    int i = 0;
    for (;i < sample_num; i++)
    {
        int pool_sample = rand()%POOL_SIZE;
        if (rand()%2) {
            addvec8_32(vec, pool + pool_sample * num_primes);
        } else {
            subvec8_32(vec, pool + pool_sample * num_primes);
        } 
    }
    reduce(vec, 100, 100);
}

void csi_fish_commit(private_key *b, card_t *Eb, const card_t *E1)
{
    int i;
    for (i = 0; i < SECURITY_PARAM; i++)
    {
        csidh_private(&b[i]);
        action(&Eb[i], E1, &b[i]);
    }
}

void csi_fish_response(int8_t *responce, const int8_t *challenge, const private_key *b, const private_key *mask)
{
    int i;
    for (i = 0; i < SECURITY_PARAM; i++)
    {
        private_key_to_int8(responce + i * num_primes, &b[i]);
        if (challenge[i] != 0)
        {
            int8_t _t[num_primes];
            private_key_to_int8(_t, mask);
            subvec8(responce + i * num_primes, _t);
        }
        randomize_vec(responce + i * num_primes, 3);
    }
}

int8_t csi_fish_validate(const int8_t *responce, const int8_t *challenge,  
                        const card_t *Eb, const card_t *E1, const card_t *E2)
{
    int i;
    for (i = 0; i < SECURITY_PARAM; i++)
    {
        card_t _E;
        if (challenge[i] != 0) {
            action_int8(&_E, E2, responce + i * num_primes);
        } else {
            action_int8(&_E, E1, responce + i * num_primes);
        }

        int flag = memcmp(&_E, &Eb[i], sizeof(_E));
        //LOG("%d ", flag);
        if (flag) {
            return 0;
        }
    }

    return 1;
}

///////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    card_t *out_commit;
    const card_t *in_stack;
    int start;
    int end;
    const private_key* masks;
    int *rand_permut;
} shuffle_stack_commit_part;

void *thread_shuffle_stack_commit(void *arg)
{
    shuffle_stack_commit_part *stack_part = (shuffle_stack_commit_part*) arg;
    int i;

    if (arg == NULL) {
        return NULL;
    }

    //LOG("START Thread thread_shuffle_stack_commit %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    for (i = 0; i < SECURITY_PARAM; i++)
    {
        int j;
        for (j = stack_part->start; j <= stack_part->end; j++)
        {
            mask_card(&stack_part->out_commit[i * CARD_NUM + j], 
                &stack_part->in_stack[stack_part->rand_permut[i * CARD_NUM + j]], 
                &stack_part->masks[i]);
            //LOG("%d\n", i);
        }
    }

    //LOG("END Thread thread_shuffle_stack_commit %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    return NULL;
}

void gen_id_permut(int *permut)
{
    int i;
    for (i = 0; i < CARD_NUM; i++) {
        permut[i] = i;
    }
}

void shuffle_stack_commit(private_key *b, int *rand_permut, card_t *Eb, const card_t *E1)
{
    pthread_t threads[THREAD_NUM];
    shuffle_stack_commit_part parts[THREAD_NUM];
    int i;

    for (i = 0; i < SECURITY_PARAM; i++)
    {
        csidh_private(&b[i]);
        gen_rand_permut(&rand_permut[i * CARD_NUM]);
    }

    float card_ind = 0.f;
    for (i = 0; i < THREAD_NUM; i++) {
        parts[i].out_commit = Eb;
        parts[i].in_stack = E1;
        parts[i].start = (int)card_ind;
        card_ind += (float)CARD_NUM / THREAD_NUM - 1.f;
        parts[i].end = (i == THREAD_NUM-1 ? CARD_NUM-1 : (int)card_ind);
        card_ind += 1.f;
        parts[i].masks = b;
        parts[i].rand_permut = rand_permut;
        pthread_create(&threads[i], NULL, thread_shuffle_stack_commit, (void *)&parts[i]);
    }
    for (i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
    }  
}

int *inv_permut(int *out_permut, const int *permut)
{
    int i;

    for (i = 0; i < CARD_NUM; i++) {
        out_permut[permut[i]] = i;
    }

    return out_permut;
}

int *composite_permuts(int *out_permut, const int *permut1, const int *permut2)
{
    int i;
    for (i = 0; i < CARD_NUM; i++) {
        out_permut[i] = permut1[permut2[i]];
    }
    return out_permut;
}

void shuffle_stack_response(int8_t *responce_mask, int *responce_permut, const int8_t *challenge, const private_key *b, const int *commit_permut, const private_key *mask, const int *mask_permut)
{
    int i;
    for (i = 0; i < SECURITY_PARAM; i++)
    {
        private_key_to_int8(responce_mask + i * num_primes, &b[i]);
        if (challenge[i] != 0)
        {
            int8_t _t[num_primes];
            private_key_to_int8(_t, mask);
            subvec8(responce_mask + i * num_primes, _t);
        }
        randomize_vec(responce_mask + i * num_primes, 3);

        int _inv_p[CARD_NUM];
        if (challenge[i] != 0) {
            composite_permuts(responce_permut + i * CARD_NUM, inv_permut(_inv_p, mask_permut), commit_permut + i * CARD_NUM);
        } else {
            memcpy(responce_permut + i * CARD_NUM, commit_permut + i * CARD_NUM, CARD_NUM * sizeof(*responce_permut));
        }
    }
}

typedef struct {
    const int8_t *responce_mask;
    const int *responce_permut; 
    const int8_t *challenge;
    const card_t *Eb;  
    const card_t *E1; 
    const card_t *E2;
    int start;
    int end;
} shuffle_stack_validate_part;


void *thread_shuffle_stack_validate(void *arg)
{
    shuffle_stack_validate_part *stack_part = (shuffle_stack_validate_part*) arg;
    int i;

    if (arg == NULL) {
        return (void *)0;
    }

    //LOG("START Thread thread_shuffle_stack_validate %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    for (i = 0; i < SECURITY_PARAM; i++)
    {
        int j;
        for (j = stack_part->start; j <= stack_part->end; j++)
        {
            card_t _E;
            if (stack_part->challenge[i] != 0) {
                action_int8(&_E, &stack_part->E2[stack_part->responce_permut[i * CARD_NUM + j]], 
                    stack_part->responce_mask + i * num_primes);
            } else {
                action_int8(&_E, &stack_part->E1[stack_part->responce_permut[i * CARD_NUM + j]], 
                    stack_part->responce_mask + i * num_primes);
            }

            /*LOG("%d.", i);
            LOG("%d ", j);
            fp_print(&_E.A);*/
            int flag = memcmp(&_E, &stack_part->Eb[i * CARD_NUM + j], sizeof(_E));
            if (flag) {
                return (void *)0;
            }
        }
    }

    //LOG("END Thread thread_shuffle_stack_validate %ld: %d->%d\n", pthread_self(), stack_part->start, stack_part->end);

    return (void *)1;
}

int8_t shuffle_stack_validate(const int8_t *responce_mask, const int *responce_permut, 
                        const int8_t *challenge, const card_t *Eb,  
                        const card_t *E1, const card_t *E2)
{
    pthread_t threads[THREAD_NUM];
    shuffle_stack_validate_part parts[THREAD_NUM];
    int i;

    float card_ind = 0.f;
    for (i = 0; i < THREAD_NUM; i++) {
        parts[i].E1 = E1;
        parts[i].E2 = E2;
        parts[i].Eb = Eb;
        parts[i].challenge = challenge;
        parts[i].start = (int)card_ind;
        card_ind += (float)CARD_NUM / THREAD_NUM - 1.f;
        parts[i].end = (i == THREAD_NUM-1 ? CARD_NUM-1 : (int)card_ind);
        card_ind += 1.f;
        parts[i].responce_mask = responce_mask;
        parts[i].responce_permut = responce_permut;
        pthread_create(&threads[i], NULL, thread_shuffle_stack_validate, (void *)&parts[i]);
    }

    int8_t res = 1;
    for (i = 0; i < THREAD_NUM; i++) {
        int flag;
        pthread_join(threads[i], (void **)&flag);
        if (!flag) {
            res = 0;
        }
    }  

    return res;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

void class_action_eq_commit(private_key *commit_priv_key, card_t *commit_card1, card_t *commit_card2, const card_t *E1, const card_t *E2)
{
    int i;
    for (i = 0; i < SECURITY_PARAM; i++)
    {
        csidh_private(&commit_priv_key[i]);
        action(&commit_card1[i], E1, &commit_priv_key[i]);
        action(&commit_card2[i], E2, &commit_priv_key[i]);
    }
}

void class_action_eq_response(int8_t *responce, const int8_t *challenge, const private_key *commit_priv_key, const private_key *mask)
{
    int i;
    for (i = 0; i < SECURITY_PARAM; i++)
    {
        private_key_to_int8(responce + i * num_primes, &commit_priv_key[i]);
        if (challenge[i] != 0)
        {
            int8_t _t[num_primes];
            private_key_to_int8(_t, mask);
            subvec8(responce + i * num_primes, _t);
        }
        randomize_vec(responce + i * num_primes, 3);
    }
}

int8_t class_action_eq_validate(const int8_t *responce, const int8_t *challenge,  
                        const card_t *commit_card1, const card_t *commit_card2, 
                        const card_t *E11, const card_t *E21,
                        const card_t *E12, const card_t *E22)
{
    int i;
    for (i = 0; i < SECURITY_PARAM; i++)
    {
        card_t _E1, _E2;
        if (challenge[i] != 0) {
            action_int8(&_E1, E12, responce + i * num_primes);
            action_int8(&_E2, E22, responce + i * num_primes);
        } else {
            action_int8(&_E1, E11, responce + i * num_primes);
            action_int8(&_E2, E21, responce + i * num_primes);
        }

        int flag1 = memcmp(&_E1, &commit_card1[i], sizeof(_E1));
        int flag2 = memcmp(&_E2, &commit_card2[i], sizeof(_E2));
        //LOG("%d ", flag);
        if (flag1 || flag2) {
            return 0;
        }
    }

    return 1;
}