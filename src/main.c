#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "protocols.h"
#include "ZKP.h"
#include "benchmarks.h"

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

	const size_t stack_size = 36;
	stack_t open_stack, close_stack;
	private_key mask;
	int pemut[stack_size];

	create_stack(&open_stack, stack_size);
	create_stack(&close_stack, stack_size);

	TIMER_START(gen_open_stack)
    gen_rand_card_stack(&open_stack);
	TIMER_END(gen_open_stack)
    
	TIMER_START(gen_close_stack)
    mask_and_shuffle_stack(&close_stack, &mask, pemut, &open_stack);
	TIMER_END(gen_close_stack)

	size_t close_ind = rand() % stack_size;
	printf("Chose card %ld: ", close_ind);
	fp_print(&close_stack.cards[close_ind].A);

	card_t card;
	unmask_card(&card, &close_stack.cards[close_ind], &mask);
	printf("Open card ");
	fp_print(&card.A);

	size_t open_ind;
	for (open_ind = 0; open_ind < stack_size; open_ind++) {
		if (!memcmp(&card, &open_stack.cards[open_ind], sizeof(card_t)))
			break;
	}
	if (open_ind < stack_size){
		printf("Card found at %ld\n", open_ind);
	} else {
		printf("Card not found!!!\n");
	}

	/*int check_ind;
	printf("Input card index to check: ");
	scanf("%d", &check_ind);

	printf("Checked card ");
	fp_print(open_stack[check_ind]);*/

	delete_stack(&open_stack);
	delete_stack(&close_stack);
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
	private_key_int8 _mask1, _mask2;

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

	private_key_to_int8(&_mask1, &mask1);
	private_key_to_int8(&_mask2, &mask2);
	addvec8(_mask1.e, _mask2.e);
	randomize_vec(_mask1.e, 3);
	printf("Randomize Total Mask: ");
	print_int8(_mask1.e);

	action_int8(&card3, &card1, &_mask1);
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

	const size_t lambda = 20;
	card_t Eb[lambda];
	private_key b[lambda];

	TIMER_START(csi_fish_commit)
	csi_fish_commit(b, Eb, &card1, lambda);
	TIMER_END(csi_fish_commit)
	
	private_key_int8 responce[lambda];
	int8_t challenge[lambda];

	size_t i;
	printf("Challenge: ");
	for (i = 0; i < lambda; i++) {
		challenge[i] = rand() % 2;
		printf("%d ", challenge[i]);
	}
	printf("\n");

	TIMER_START(csi_fish_response)
	csi_fish_response(responce, challenge, b, &mask, lambda);
	TIMER_END(csi_fish_response)

	TIMER_START(csi_fish_validate)
	printf("IsValid: %d\n", csi_fish_validate(responce, challenge, Eb, &card1, &card2, lambda));
	TIMER_END(csi_fish_validate)
}

void test5()
{
	srand(time(NULL));

	const size_t stack_size = 36;
	stack_t open_stack, close_stack;
	private_key mask;
	int pemut[stack_size];

	create_stack(&open_stack, stack_size);
	create_stack(&close_stack, stack_size);

	TIMER_START(gen_open_stack)
    gen_rand_card_stack(&open_stack);
	TIMER_END(gen_open_stack)
    
	TIMER_START(gen_close_stack)
    mask_and_shuffle_stack(&close_stack, &mask, pemut, &open_stack);
	TIMER_END(gen_close_stack)

	const size_t lambda = 20;
	private_key commit_mask[lambda];
	int commit_pemut[stack_size * lambda];
	stack_t commit_stack[lambda];

	size_t i;
	for (i = 0; i < lambda; i++) {
		create_stack(&commit_stack[i], stack_size);	
	}

	TIMER_START(shuffle_stack_commit)
    shuffle_stack_commit(commit_mask, commit_pemut, commit_stack, &open_stack, lambda);
	TIMER_END(shuffle_stack_commit)

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

	private_key_int8 responce_mask[lambda];
	int8_t challenge[lambda];
	int responce_pemut[stack_size * lambda];
	
	printf("Challenge: ");
	for (i = 0; i < lambda; i++) {
		challenge[i] = rand() % 2;
		printf("%d ", challenge[i]);
	}
	printf("\n");

	TIMER_START(shuffle_stack_response)
    shuffle_stack_response(responce_mask, responce_pemut, challenge, commit_mask, commit_pemut, &mask, pemut, stack_size, lambda);
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
    printf("IsValid: %d\n", 
		shuffle_stack_validate(responce_mask, responce_pemut, 
		challenge, commit_stack, &open_stack, &close_stack, lambda));
	TIMER_END(shuffle_stack_validate)

	for (i = 0; i < lambda; i++) {
		delete_stack(&commit_stack[i]);	
	}

	delete_stack(&close_stack);
	delete_stack(&open_stack);
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

	const size_t lambda = 20;
	card_t commit_card1[lambda], commit_card2[lambda];
	private_key commit_priv_key[lambda];

	TIMER_START(class_action_eq_commit)
	class_action_eq_commit(commit_priv_key, commit_card1, commit_card2, &card11, &card21, lambda);
	TIMER_END(class_action_eq_commit)	

	int8_t challenge[lambda];
	private_key_int8 response[lambda];

	printf("Challenge: ");
	size_t i;
	for (i = 0; i < lambda; i++) {
		challenge[i] = rand() % 2;
		printf("%d ", challenge[i]);
	}
	printf("\n");

	TIMER_START(class_action_eq_response)
	class_action_eq_response(response, challenge, commit_priv_key, &mask, lambda);
	TIMER_END(class_action_eq_response)	


	TIMER_START(class_action_eq_validate)
    printf("IsValid: %d\n", 
		class_action_eq_validate(response, challenge, commit_card1, 
		commit_card2, &card11, &card21, &card12, &card22, lambda));
	TIMER_END(class_action_eq_validate)
}

void game_validate_benchmark(size_t stack_size, size_t player_num, size_t lambda)
{
	stack_t open_stack, close_stack;
	create_stack(&open_stack, stack_size);
	create_stack(&close_stack, stack_size);
	card_t *control_cards = malloc((player_num + 1) * sizeof(card_t));
	private_key *player_masks = malloc(player_num * sizeof(private_key));

	TIMER_START(gen_open_stack)
	stack_gen_open_stack_validate(&open_stack, control_cards, stack_size, player_num, lambda);
	TIMER_END(gen_open_stack)	
	TIMER_START(gen_close_stack)
	stack_gen_close_stack_validate(&close_stack, control_cards, player_masks, &open_stack, stack_size, player_num, lambda);
	TIMER_END(gen_close_stack)	

	TIMER_START(gen_open_card)
	size_t close_ind = ((size_t)rand()) % stack_size;
	size_t player_id = 1;
	card_t opened_card;

	printf("Chosen card %ld from close stack\n", close_ind);
	pickup_card_validate(&opened_card, &close_stack.cards[close_ind], player_masks, 
		control_cards, player_num, player_id, lambda);

	size_t open_ind;
	for (open_ind = 0; open_ind < stack_size; open_ind++) {
		if (!memcmp(&opened_card, &open_stack.cards[open_ind], sizeof(card_t)))
			break;
	}
	if (open_ind < stack_size){
		printf("Card found at %ld in open stack\n", open_ind);
	} else {
		printf("Card not found!!!\n");
	}
	TIMER_END(gen_open_card)	

	free(player_masks);
	free(control_cards);
	delete_stack(&close_stack);
	delete_stack(&open_stack);
}

void game_benchmark(size_t stack_size, size_t player_num)
{
	stack_t open_stack, close_stack;
	create_stack(&open_stack, stack_size);
	create_stack(&close_stack, stack_size);
	private_key *player_masks = malloc(player_num * sizeof(private_key));

	TIMER_START(gen_open_stack)
	stack_gen_open_stack(&open_stack, stack_size, player_num);
	TIMER_END(gen_open_stack)	
	TIMER_START(gen_close_stack)
	stack_gen_close_stack(&close_stack, player_masks, &open_stack, stack_size, player_num);
	TIMER_END(gen_close_stack)	

	TIMER_START(gen_open_card)
	size_t close_ind = ((size_t)rand()) % stack_size;
	size_t player_id = 1;
	card_t opened_card;

	printf("Chosen card %ld from close stack\n", close_ind);
	pickup_card(&opened_card, &close_stack.cards[close_ind], player_masks, 
		player_num, player_id);

	size_t open_ind;
	for (open_ind = 0; open_ind < stack_size; open_ind++) {
		if (!memcmp(&opened_card, &open_stack.cards[open_ind], sizeof(card_t)))
			break;
	}
	if (open_ind < stack_size){
		printf("Card found at %ld in open stack\n", open_ind);
	} else {
		printf("Card not found!!!\n");
	}
	TIMER_END(gen_open_card)	

	free(player_masks);
	delete_stack(&close_stack);
	delete_stack(&open_stack);
}

int main()
{
{
    const char *pStr = "5326738796327623094747867617954605554069371494832722337612446642054009560026576537626892113026381253624626941643949444792662881241621373288942880288065659";
	mcl_init(pStr);
	srand(time(NULL));
}

	size_t stack_size = 52;
	size_t player_num = 3;
	size_t lambda = 20;

	game_validate_benchmark(stack_size, player_num, lambda);

	return 0;
}