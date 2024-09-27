#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "protocols.h"
#include "ZKP.h"

void print_private_key(const private_key *priv)
{
	int i = 0;
	for (;i < num_primes; i++)
		printf("%d ", (int8_t) (priv->e[i / 2] << i % 2 * 4) >> 4);
	printf("\n");
}

void print_int8(const int8_t *priv)
{
	int i = 0;
	for (;i < num_primes; i++)
		printf("%d ", priv[i]);
	printf("\n");
}

void u512_print(u512 const *x)
{
    for (size_t i = 63; i < 64; --i)
        printf("%02hhx", i[(unsigned char *) x->c]);
}

void fp_print(fp const *x)
{
    u512 y;
    fp_dec(&y, x);
    u512_print(&y);
	printf("\n");
}

void test1()
{
	srand(time(NULL));

	card_t open_stack[CARD_NUM], close_stack[CARD_NUM];
	private_key mask;
	int pemut[CARD_NUM];

	TIMER_START(gen_open_stack)
    gen_rand_card_stack(open_stack);
	TIMER_END(gen_open_stack)
    
	TIMER_START(gen_close_stack)
    mask_and_shuffle_stack(close_stack, &mask, pemut, open_stack);
	TIMER_END(gen_close_stack)

	int close_ind = rand() % CARD_NUM;
	printf("Chose card %d: ", close_ind);
	fp_print(&close_stack[close_ind].A);

	card_t card;
	unmask_card(&card, &close_stack[close_ind], &mask);
	printf("Open card ");
	fp_print(&card.A);

	int open_ind;
	for (open_ind = 0; open_ind < CARD_NUM; open_ind++) {
		if (!memcmp(&card, &open_stack[open_ind], sizeof(card_t)))
			break;
	}
	if (open_ind < CARD_NUM){
		printf("Card found at %d\n", open_ind);
	} else {
		printf("Card not found!!!\n");
	}

	/*int check_ind;
	printf("Input card index to check: ");
	scanf("%d", &check_ind);

	printf("Checked card ");
	fp_print(open_stack[check_ind]);*/
}

void test2()
{
	srand(time(NULL));

	card_t card, masked_card, unmasked_card;
	private_key mask, i_mask;

	gen_rand_card(&card);
	printf("Card: ");
	fp_print(&card.A);

	csidh_private(&mask);
	printf("Mask: ");
	print_private_key(&mask);

	mask_card(&masked_card, &card, &mask);
	printf("Masked card: ");
	fp_print(&masked_card.A);

	i_mask = inv_mask(&mask);
	printf("Inverted mask: ");
	print_private_key(&i_mask);

	unmask_card(&unmasked_card, &masked_card, &mask);
	printf("Unmasked card: ");
	fp_print(&unmasked_card.A);

	printf("IsEqual: %d\n", !memcmp(&card, &unmasked_card, sizeof(card_t)));
}

void test3()
{
	srand(time(NULL));

	card_t card1, card2, card3;
	private_key mask1, mask2;
	int8_t _mask1[num_primes], _mask2[num_primes];

	gen_rand_card(&card1);
	printf("Card: ");
	fp_print(&card1.A);

	csidh_private(&mask1);
	printf("Mask 1: ");
	print_private_key(&mask1);

	csidh_private(&mask2);
	printf("Mask 2: ");
	print_private_key(&mask2);

	mask_card(&card3, &card1, &mask1);
	mask_card(&card2, &card3, &mask2);
	printf("Private key Masked card: ");
	fp_print(&card2.A);

	memset(&card3, 0, sizeof(card3));

	private_key_to_int8(_mask1, &mask1);
	private_key_to_int8(_mask2, &mask2);
	addvec8(_mask1, _mask2);
	randomize_vec(_mask1, 3);
	printf("Randomize Total Mask: ");
	print_int8(_mask1);

	action_int8(&card3, &card1, _mask1);
	printf("Int8 Masked card: ");
	fp_print(&card3.A);

	printf("IsEqual: %d\n", !memcmp(&card2, &card3, sizeof(card_t)));
}

void test4()
{
	srand(time(NULL));

	card_t card1, card2;
	private_key mask;
	
	gen_rand_card(&card1);
	printf("Card: ");
	fp_print(&card1.A);

	csidh_private(&mask);
	printf("Mask: ");
	print_private_key(&mask);

	mask_card(&card2, &card1, &mask);
	printf("Masked card: ");
	fp_print(&card2.A);

	card_t Eb[SECURITY_PARAM];
	private_key b[SECURITY_PARAM];

	TIMER_START(csi_fish_commit)
	csi_fish_commit(b, Eb, &card1);
	TIMER_END(csi_fish_commit)
	
	int8_t responce[SECURITY_PARAM * num_primes];
	int8_t challenge[SECURITY_PARAM];

	int i;
	printf("Challenge: ");
	for (i = 0; i < SECURITY_PARAM; i++) {
		challenge[i] = rand() % 2;
		printf("%d ", challenge[i]);
	}
	printf("\n");

	TIMER_START(csi_fish_response)
	csi_fish_response(responce, challenge, b, &mask);
	TIMER_END(csi_fish_response)

	TIMER_START(csi_fish_validate)
	printf("IsValid: %d\n", csi_fish_validate(responce, challenge, Eb, &card1, &card2));
	TIMER_END(csi_fish_validate)
}

void test5()
{
	srand(time(NULL));

	card_t open_stack[CARD_NUM], close_stack[CARD_NUM];
	private_key mask;
	int pemut[CARD_NUM];

	TIMER_START(gen_open_stack)
    gen_rand_card_stack(open_stack);
	TIMER_END(gen_open_stack)
    
	TIMER_START(gen_close_stack)
    mask_and_shuffle_stack(close_stack, &mask, pemut, open_stack);
	TIMER_END(gen_close_stack)

	private_key commit_mask[SECURITY_PARAM];
	int commit_pemut[CARD_NUM * SECURITY_PARAM];
	card_t commit_stack[CARD_NUM * SECURITY_PARAM];

	TIMER_START(shuffle_stack_commit)
    shuffle_stack_commit(commit_mask, commit_pemut, commit_stack, open_stack);
	TIMER_END(shuffle_stack_commit)

	int i;
	/*for (i = 0; i < SECURITY_PARAM; i++) {
		int j;
		for (j = 0; j < CARD_NUM; j++) {
			printf("%d.%d ", i, j);
			fp_print(&commit_stack[i * CARD_NUM + j].A);
		}
	}
	for (i = 0; i < SECURITY_PARAM; i++) {
		printf("%d: ", i);
		int j;
		for (j = 0; j < CARD_NUM; j++) {
			printf("%d ", pemut[j]);
		}
		printf("\n");
		printf("%d: ", i);
		for (j = 0; j < CARD_NUM; j++) {
			printf("%d ", j);
		}
		printf("\n");
		printf("%d: ", i);
		for (j = 0; j < CARD_NUM; j++) {
			printf("%d ", commit_pemut[i * CARD_NUM + j]);
		}
		printf("\n\n");
	}*/

	int8_t responce_mask[SECURITY_PARAM * num_primes];
	int8_t challenge[SECURITY_PARAM];
	int responce_pemut[CARD_NUM * SECURITY_PARAM];
	
	printf("Challenge: ");
	for (i = 0; i < SECURITY_PARAM; i++) {
		challenge[i] = rand() % 2;
		printf("%d ", challenge[i]);
	}
	printf("\n");

	TIMER_START(shuffle_stack_response)
    shuffle_stack_response(responce_mask, responce_pemut, challenge, commit_mask, commit_pemut, &mask, pemut);
	TIMER_END(shuffle_stack_response)

	/*for (i = 0; i < SECURITY_PARAM; i++) {
		printf("%d: ", i);
		int j;
		for (j = 0; j < CARD_NUM; j++) {
			printf("%d ", responce_pemut[i * CARD_NUM + j]);
		}
		printf("\n");
	}*/

	TIMER_START(shuffle_stack_validate)
    printf("IsValid: %d\n", shuffle_stack_validate(responce_mask, responce_pemut, challenge, commit_stack, open_stack, close_stack));
	TIMER_END(shuffle_stack_validate)
}

void test6()
{
	srand(time(NULL));

	card_t card11, card21, card12, card22;
	private_key mask;
	
	gen_rand_card(&card11);
	printf("Card 1: ");
	fp_print(&card11.A);
	gen_rand_card(&card21);
	printf("Card 2: ");
	fp_print(&card21.A);

	csidh_private(&mask);
	printf("Mask: ");
	print_private_key(&mask);

	mask_card(&card12, &card11, &mask);
	printf("Masked card 1: ");
	fp_print(&card12.A);
	mask_card(&card22, &card21, &mask);
	printf("Masked card 2: ");
	fp_print(&card22.A);

	card_t commit_card1[SECURITY_PARAM], commit_card2[SECURITY_PARAM];
	private_key commit_priv_key[SECURITY_PARAM];

	TIMER_START(class_action_eq_commit)
	class_action_eq_commit(commit_priv_key, commit_card1, commit_card2, &card11, &card21);
	TIMER_END(class_action_eq_commit)	

	int8_t challenge[SECURITY_PARAM];
	int8_t response[SECURITY_PARAM * num_primes];

	printf("Challenge: ");
	int i;
	for (i = 0; i < SECURITY_PARAM; i++) {
		challenge[i] = rand() % 2;
		printf("%d ", challenge[i]);
	}
	printf("\n");

	TIMER_START(class_action_eq_response)
	class_action_eq_response(response, challenge, commit_priv_key, &mask);
	TIMER_END(class_action_eq_response)	


	TIMER_START(class_action_eq_validate)
    printf("IsValid: %d\n", class_action_eq_validate(response, challenge, commit_card1, commit_card2, &card11, &card21, &card12, &card22));
	TIMER_END(class_action_eq_validate)
}

int main()
{
{
    const char *pStr = "5326738796327623094747867617954605554069371494832722337612446642054009560026576537626892113026381253624626941643949444792662881241621373288942880288065659";
	mcl_init(pStr);
}

	test6();

	return 0;
}