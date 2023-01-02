#include <arpa/inet.h>
#include <assert.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>

#include "patricia.h"
#include "patricia_internal.h"

typedef Suite *(*test_module)(void *ctx);

// FIXME: these are in patricia.c too
static const bool TRIE_LEFT = false;
static const bool TRIE_RIGHT = true;

static bool trie_test(struct patricia *trie, int expected);
static bool node_test(struct pnode *node, int depth, int *found);

static Suite *test_module_bits(void *ctx);
static Suite *test_module_child(void *ctx);
static Suite *test_module_route(void *ctx);

static test_module test_modules[] = {
    test_module_bits,
    test_module_child,
    test_module_route,
};
#define N_MODULES ((int)(sizeof(test_modules) / sizeof(test_modules[0])))

// Helper function to add a route to the trie with a consistent name
// FIXME: Should use this for all calls
static void
route_add(struct patricia *trie, const char *addr, uint8_t prefix)
{
	assert(trie);
	assert(addr);
	char buf[100];
	snprintf(buf, sizeof(buf), "%s/%d", addr, prefix);
	bool rv = patricia_route_add_ip4(trie, inet_network(addr), prefix, strdup(buf));
	ck_assert(rv);
}

START_TEST(test_route_add_update_root)
{
	struct patricia *trie = patricia_create(AF_INET, strdup("Wrong"));
	patricia_route_add_ip4(trie, inet_network("0.0.0.0"), 0, strdup("Default"));
	trie_test(trie, 0);
}
END_TEST

START_TEST(test_route_add_one_left)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "127.0.0.0", 8);
	trie_test(trie, 1);
	ck_assert_ptr_nonnull(trie->root.children[0]);
	ck_assert_ptr_null(trie->root.children[1]);
	ck_assert_int_eq(7, trie->root.children[0]->prefixlen);
}
END_TEST

START_TEST(test_route_add_one_right)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "227.0.0.0", 8);
	trie_test(trie, 1);
	ck_assert_ptr_null(trie->root.children[0]);
	ck_assert_ptr_nonnull(trie->root.children[1]);
	ck_assert_int_eq(7, trie->root.children[1]->prefixlen);
}
END_TEST

START_TEST(test_route_add_two_left)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "127.0.0.0", 8);
	route_add(trie, "127.127.0.0", 16);

	trie_test(trie, 2);
	patricia_free(trie);
}
END_TEST
START_TEST(test_route_add_three_left)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "127.0.0.0", 8);
	route_add(trie, "127.127.0.0", 16);
	route_add(trie, "127.127.127.0", 24);

	trie_test(trie, 3);
	patricia_free(trie);
}
END_TEST
START_TEST(test_route_add_eight_right)
{
	// FIXME: Add some asserts
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "128.0.0.0", 1);
	route_add(trie, "192.0.0.0", 2);
	route_add(trie, "224.0.0.0", 3);
	route_add(trie, "240.0.0.0", 4);
	route_add(trie, "248.0.0.0", 5);
	route_add(trie, "252.0.0.0", 6);
	route_add(trie, "254.0.0.0", 7);
	route_add(trie, "255.0.0.0", 8);
	trie_test(trie, 8);
	patricia_free(trie);
}
END_TEST

START_TEST(test_route_add_eight_right_reverse)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "255.0.0.0", 8);
	route_add(trie, "254.0.0.0", 7);
	route_add(trie, "252.0.0.0", 6);
	route_add(trie, "248.0.0.0", 5);
	route_add(trie, "240.0.0.0", 4);
	route_add(trie, "224.0.0.0", 3);
	route_add(trie, "192.0.0.0", 2);
	route_add(trie, "128.0.0.0", 1);
	trie_test(trie, 8);
	patricia_free(trie);
}
END_TEST

START_TEST(test_route_add_eight_right_random)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "255.0.0.0", 8);
	route_add(trie, "240.0.0.0", 4);
	route_add(trie, "252.0.0.0", 6);
	route_add(trie, "192.0.0.0", 2);
	route_add(trie, "248.0.0.0", 5);
	route_add(trie, "254.0.0.0", 7);
	route_add(trie, "224.0.0.0", 3);
	route_add(trie, "128.0.0.0", 1);
	trie_test(trie, 8);
	patricia_free(trie);
}
END_TEST

START_TEST(test_route_add_split_node)
{
	// Create a length 16 branch, then split it in the middle
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "255.255.0.0", 16);
	route_add(trie, "255.0.0.0", 8);
	trie_test(trie, 2);
	patricia_free(trie);
}
END_TEST

START_TEST(test_route_add_split_node_64)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "127.0.0.0", 8);
	route_add(trie, "64.0.0.0", 8);
	trie_test(trie, 2);
	patricia_free(trie);
}
END_TEST

START_TEST(test_route_fork_root)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "192.0.0.0", 2);
	route_add(trie, "0.0.0.0", 2);
	trie_test(trie, 2);
}
END_TEST

START_TEST(test_route_fork_from_one)
{
	// Given a node at 128, add 2 children, 1 left, 1 right
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "128.0.0.0", 1);
	route_add(trie, "128.0.0.0", 2);
	route_add(trie, "192.0.0.0", 2);
	trie_test(trie, 3);
}
END_TEST

START_TEST(test_route_fork_depth_2)
{
	// Test trie
	struct patricia *trie2 = patricia_create(AF_INET, "Default");
	route_add(trie2, "128.0.0.0", 1);
	route_add(trie2, "128.0.0.0", 2);
	route_add(trie2, "192.0.0.0", 2);

	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "128.0.0.0", 2);
	route_add(trie, "192.0.0.0", 2);
	trie_test(trie, 2);

	patricia_free(trie);
	patricia_free(trie2);
}
END_TEST

START_TEST(test_route_fork_depth_2a)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "64.0.0.0", 2);
	route_add(trie, "0.0.0.0", 2);
	trie_test(trie, 2);
}
END_TEST

// Create a node at depth 1, add 2 children at depth 3 that differ in the second bit.
START_TEST(test_route_fork_depth_2_from_1)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "0.0.0.0", 1);
	route_add(trie, "0.0.0.0", 3);
	route_add(trie, "32.0.0.0", 3);
	trie_test(trie, 3);
}
END_TEST

// Same as previous, but with a different bit pattern
START_TEST(test_route_fork_depth_2_from_1_right)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "128.0.0.0", 1);
	route_add(trie, "128.0.0.0", 3);
	route_add(trie, "160.0.0.0", 3);
	trie_test(trie, 3);
}
END_TEST

START_TEST(test_route_fork_depth_8)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	route_add(trie, "255.0.0.0", 8);
	route_add(trie, "240.0.0.0", 8);

	trie_test(trie, 2);
}
END_TEST

START_TEST(test_route_stress_255)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	for (int i = 0; i < 255; i++) {
		char buf[20];
		snprintf(buf, sizeof(buf), "%d.0.0.0", i);
		route_add(trie, buf, 8);
	}

	trie_test(trie, 255);
}
END_TEST

START_TEST(test_child_get_left)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	// FIXME: Build a trie and get the real node
	ck_assert_ptr_null(child_get(&trie->root, TRIE_LEFT));
	patricia_free(trie);
}
END_TEST
START_TEST(test_child_get_right)
{
	// FIXME: Implement
}
END_TEST
START_TEST(test_child_get_nulls)
{
	struct patricia *trie = patricia_create(AF_INET, "Default");
	ck_assert_ptr_null(child_get(&trie->root, TRIE_LEFT));
	ck_assert_ptr_null(child_get(&trie->root, TRIE_RIGHT));
	patricia_free(trie);
}
END_TEST

START_TEST(test_bits_get_first)
{
	ck_assert_int_eq(1, bit_get(BITFIELD_ONE << (BITFIELD_BITS - 1), 0));
	ck_assert_int_eq(0, bit_get(~(BITFIELD_ONE << (BITFIELD_BITS - 1)), 0));
}
END_TEST
START_TEST(test_bits_get_last)
{
	ck_assert_int_eq(1, bit_get(0x1, BITFIELD_BITS - 1));
	ck_assert_int_eq(0, bit_get(~0x1, BITFIELD_BITS - 1));
}
END_TEST
START_TEST(test_bits_get_seven)
{
	if (sizeof(bitfield_t) == 4) {
		ck_assert_int_eq(1, bit_get(0x01000000, 7));
		ck_assert_int_eq(0, bit_get(~0x01000000, 7));
	} else {
		ck_assert_int_eq(1, bit_get(0x0100000000000000, 7));
		ck_assert_int_eq(0, bit_get(~0x0100000000000000, 7));
	}
}
END_TEST

START_TEST(test_bits_prefix_1)
{
	// Different in first bit only
	ck_assert(!bit_prefix_compare(BITFIELD_ONE << (BITFIELD_BITS - 1), 0, 1, NULL));
	ck_assert(!bit_prefix_compare(0, BITFIELD_ONE << (BITFIELD_BITS - 1), 1, NULL));
	// Same in top bit (only bit set)
	ck_assert(bit_prefix_compare(BITFIELD_ONE << (BITFIELD_BITS - 1),
				     BITFIELD_ONE << (BITFIELD_BITS - 1), 1, NULL));
	ck_assert(bit_prefix_compare(0, 0, 1, NULL));

	// So first bit the same, rest different
	ck_assert(bit_prefix_compare(BITFIELD_ONE << (BITFIELD_BITS - 1), -1, 1, NULL));
	ck_assert(bit_prefix_compare(BITFIELD_ONE << (BITFIELD_BITS - 2), 0, 1, NULL));
}

END_TEST
START_TEST(test_bits_prefix_7)
{
	ck_assert(bit_prefix_compare(-1, -1, 7, NULL));
	ck_assert(bit_prefix_compare(-1, -1, 7, NULL));
}
END_TEST
START_TEST(test_bits_prefix_16)
{
	ck_assert(bit_prefix_compare(-1, -1, 16, NULL));
}
END_TEST
START_TEST(test_bits_prefix_31)
{
	ck_assert(bit_prefix_compare(-1, -1, 31, NULL));
}
END_TEST
START_TEST(test_bits_prefix_32)
{
	ck_assert(bit_prefix_compare(0, 0, 32, NULL));
	ck_assert(bit_prefix_compare(0, 0, 32, NULL));
}
END_TEST
START_TEST(test_bits_prefix_0xc0_0x80)
{
	ck_assert(!bit_prefix_compare(0xc0000000, 0x80000000, BITFIELD_BITS, NULL));
}
END_TEST

static Suite *
test_module_bits(__attribute__((unused)) void *ctx)
{
	Suite *s = suite_create("Bits");

	{
		TCase *tc_bits = tcase_create("Get");
		suite_add_tcase(s, tc_bits);

		tcase_add_test(tc_bits, test_bits_get_first);
		tcase_add_test(tc_bits, test_bits_get_last);
		tcase_add_test(tc_bits, test_bits_get_seven);
	}
	{
		TCase *tc_compare = tcase_create("prefix");
		suite_add_tcase(s, tc_compare);

		tcase_add_test(tc_compare, test_bits_prefix_1);
		tcase_add_test(tc_compare, test_bits_prefix_7);
		tcase_add_test(tc_compare, test_bits_prefix_16);
		tcase_add_test(tc_compare, test_bits_prefix_31);
		tcase_add_test(tc_compare, test_bits_prefix_32);
		tcase_add_test(tc_compare, test_bits_prefix_0xc0_0x80);
	}

	return s;
}

START_TEST(test_child_alloc)
{
	struct pnode *node = child_alloc(0, 0x88888888, 8);
	ck_assert_ptr_nonnull(node);
	node_free(node);
}
END_TEST

static bool
trie_test(struct patricia *trie, int expected)
{
	bool rv = true;
	int found = 0;
	ck_assert_str_eq("Default", trie->root.route);
	if (trie->root.children[0])
		if (node_test(trie->root.children[0], 1, &found) == false) rv = false;
	if (trie->root.children[1])
		if (node_test(trie->root.children[1], 1, &found) == false) rv = false;
	ck_assert_int_eq(found, expected);
	return rv;
}
static bool
node_test(struct pnode *node, int depth, int *found)
{
	char buf[40];
	ck_assert_int_le(0, node->prefixlen);
	// We can have empty nodes.
	if (node->route) {
		uint32_t addr;
		if (PATRICIA_SIZE == 64)
			addr = node->prefix >> 32;
		else
			addr = node->prefix;
		snprintf(buf, sizeof(buf), "%s/%d",
			 inet_ntoa((struct in_addr){.s_addr = htonl(addr)}),
			 depth + node->prefixlen);
		ck_assert_str_eq(buf, node->route);
		(*found)++;
	}
	if (node->children[0]) {
		if (node_test(node->children[0], depth + node->prefixlen + 1, found) == false) {
			return false;
		}
	}
	if (node->children[1]) {
		if (node_test(node->children[1], depth + node->prefixlen + 1, found) == false) {

			return false;
		}
	}
	return true;
}

int
patricia_test()
{
	SRunner *sr;
	int nfailed;
	int i;

	sr = srunner_create(NULL);
	for (i = 0; i < N_MODULES; i++) {
		srunner_add_suite(sr, test_modules[i](NULL));
	}

	srunner_run_all(sr, CK_VERBOSE);
	nfailed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return nfailed;
}

static Suite *
test_module_child(__attribute__((unused)) void *ctx)
{
	Suite *s = suite_create("Child");

	{
		TCase *tc_get = tcase_create("Get");
		suite_add_tcase(s, tc_get);

		tcase_add_test(tc_get, test_child_get_left);
		tcase_add_test(tc_get, test_child_get_right);
		tcase_add_test(tc_get, test_child_get_nulls);
	}
	{
		TCase *tc_alloc = tcase_create("Alloc");
		suite_add_tcase(s, tc_alloc);

		tcase_add_test(tc_alloc, test_child_alloc);
	}

	return s;
}

static Suite *
test_module_route(__attribute__((unused)) void *ctx)
{
	Suite *s = suite_create("route");

	{
		TCase *tc_add = tcase_create("add");
		suite_add_tcase(s, tc_add);

		tcase_add_test(tc_add, test_route_add_update_root);
		tcase_add_test(tc_add, test_route_add_one_left);
		tcase_add_test(tc_add, test_route_add_one_right);
		tcase_add_test(tc_add, test_route_add_two_left);
		tcase_add_test(tc_add, test_route_add_three_left);
		tcase_add_test(tc_add, test_route_add_eight_right);
		tcase_add_test(tc_add, test_route_add_eight_right_reverse);
		tcase_add_test(tc_add, test_route_add_eight_right_random);
		tcase_add_test(tc_add, test_route_add_split_node);
		tcase_add_test(tc_add, test_route_add_split_node_64);
	}
	{
		TCase *tc_fork = tcase_create("fork");
		suite_add_tcase(s, tc_fork);

		tcase_add_test(tc_fork, test_route_fork_root);
		tcase_add_test(tc_fork, test_route_fork_from_one);
		tcase_add_test(tc_fork, test_route_fork_depth_2);
		tcase_add_test(tc_fork, test_route_fork_depth_2a);
		tcase_add_test(tc_fork, test_route_fork_depth_2_from_1);
		tcase_add_test(tc_fork, test_route_fork_depth_2_from_1_right);
		tcase_add_test(tc_fork, test_route_fork_depth_8);
	}
	{
		TCase *tc_stress = tcase_create("stress");
		suite_add_tcase(s, tc_stress);

		tcase_add_test(tc_stress, test_route_stress_255);
	}

	return s;
}
