/**
 * Simple (update only) patricia trie.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <check.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "patricia.h"
#include "patricia_internal.h"

enum {
	UINT32_BITS = 32,
};

#define N_CHILDREN 2

#define palloc(type) (type *)calloc(1, sizeof(type))

#define MIN(a, b)                                                                                  \
	({                                                                                         \
		__typeof(a) _a = a;                                                                \
		__typeof(b) _b = b;                                                                \
		(void)(&_a == &_b);                                                                \
		(a < b) ? a : b;                                                                   \
	})

bitfield_t mask_create(int prefix);
static struct pnode *node_child_set(struct pnode *pnode, bool dir, struct pnode *child);
static void node_dump(int depth, struct pnode *node);
static bool route_add(struct pnode *node, int depth, bitfield_t addr, int prefix,
		      const void *route);
static struct pnode *insert_child(struct pnode *parent, int parentdepth, bool dir, int splitdepth,
				  bitfield_t addr);

// We need to work out which count leading zeros we will use.
#if PATRICIA_SIZE == 64
#define patricia_clz(x) __builtin_clzll(x)
#else
#define patricia_clz(x) __builtin_clz(x)
#endif

struct patricia *
patricia_create(int family, const void *route)
{
	struct patricia *trie;

	if (family != AF_INET) {
		printf("IPv4 only at the moment peoples\n");
		return NULL;
	}

	trie = palloc(struct patricia);

	trie->root.route = route;
	return trie;
}

void
patricia_free(struct patricia *trie)
{
	for (int i = 0; i < N_CHILDREN; i++) {
		if (trie->root.children[i]) node_free(trie->root.children[i]);
	}
	free(trie);
}

void
node_free(struct pnode *node)
{
	for (int i = 0; i < N_CHILDREN; i++) {
		if (node->children[i]) node_free(node->children[i]);
	}
	free(node);
}

bool
patricia_route_add(struct patricia *trie, bitfield_t addr, int prefix, const void *route)
{
	assert(trie);
	assert((prefix == 0) || (addr & mask_create(prefix)) == addr);
	return route_add(&trie->root, 0, addr, prefix, route);
}

bool
patricia_route_add_ip4(struct patricia *trie, in_addr_t addr, int prefix, const void *route)
{
#if PATRICIA_SIZE == 64
	return patricia_route_add(trie, ((bitfield_t)addr) << 32, prefix, route);
#else
	return patricia_route_add(trie, addr, prefix, route);
#endif
}

bool
patricia_route_add_ip6(struct patricia *trie, struct in6_addr addr, int prefix, const void *route)
{
	trie = 0;
	addr = (in6_addr_t){0};
	prefix = 0;
	route = NULL;
	// Not implemented yet.
	return false;
}

/**
 * Add a route.
 *
 * The main API call for adding a route to the table.  Adding a route adds no more than 2 nodes to
 * the trie.
 *
 * It tries to handle each of the cases.
 *
 * It recursively calls itself until we find anode we need to either update or add.
 *
 * - If we hit the correct node, we update and return (we may have just added it).
 * - If we hit a NULL child, we create a node of the correct depth, and return.
 * Otherwise we need to split a prefix, in which case we insert the new node, then call again, maybe
 * updating, or maybe adding a child.
 *
 * @param node The current node
 * @param depth the current depth (depth of the node).
 * @param addr The address we are adding
 * @param prefix the Prefix of the address we are adding (target depth)
 * @param route The data to set when we reach the bottom
 * @return true if addedd succesfully, false otherwise.
 */
static bool
route_add(struct pnode *node, int depth, bitfield_t addr, int prefix, const void *route)
{
	assert(node);

	if (depth == prefix) {
		node->route = route;
		return true;
	}

	// Lets see which child we need:
	bool dir = bit_get(addr, depth);

	struct pnode *child = child_get(node, dir);
	if (child == NULL) {
		// No child in that direction - just add.
		child = child_alloc(depth, addr, prefix);
		child->route = route;
		assert(child->prefixlen == prefix - depth - 1);
		node_child_set(node, dir, child);
		return true;
	}

	if (child->prefixlen == 0) {
		// Child exists, and it matches - recurse into it.
		return route_add(child, depth + 1, addr, prefix, route);
	}

	// Compare prefixes, see if child matches
	uint8_t diffoffset;
	bool matched = bit_prefix_compare(child->prefix, addr,
					  MIN(prefix, depth + child->prefixlen + 1), &diffoffset);

	if (matched && prefix > depth + child->prefixlen) {
		// No prefix, fully populated here, recurse down.
		return route_add(child, depth + 1 + child->prefixlen, addr, prefix, route);
	}

	// Do we need to split due to length or because they differ.
	if (matched) {
		// So insert directly in the current trie.
		struct pnode *split = insert_child(node, depth, dir, prefix, addr);
		split->route = route;
		return true;
	}

	// Insert node, then call again to update the new node.
	struct pnode *split = insert_child(node, depth, dir, diffoffset, addr);
	split->route = NULL;

	return route_add(split, diffoffset, addr, prefix, route);
}

static struct pnode *
insert_child(struct pnode *parent, int parentdepth, bool dir, int splitdepth, bitfield_t addr)
{
	assert(splitdepth > parentdepth);
	assert(parent);

	struct pnode *child = child_get(parent, dir);

	struct pnode *split = child_alloc(parentdepth, addr, splitdepth);

	node_child_set(split, bit_get(child->prefix, splitdepth), child);
	node_child_set(parent, bit_get(child->prefix, parentdepth), split);

	child->prefixlen -= split->prefixlen + 1;

	return split;
}

void
patricia_dump(struct patricia *trie)
{
	printf("&&& 0/0 is %s (L%p/R%p)\n", (char *)trie->root.route, trie->root.children[0],
	       trie->root.children[1]);
	node_dump(1, trie->root.children[0]);
	node_dump(1, trie->root.children[1]);
}

/**
 * Create a prefix mask of the approprite length.
 *
 * Does not work for 0.
 */
bitfield_t
mask_create(int prefix)
{
	bitfield_t mask;
	assert(prefix > 0);

	mask = 1ul << prefix;
	mask -= 1;
	mask <<= (BITFIELD_BITS - prefix);

	return mask;
}

static void
node_dump(int depth, struct pnode *node)
{
	if (!node) return;
	printf("%p: %s/%d %" PR_BITFIELD "->%s (L%p/R%p) prefix %d\n", node,
	       inet_ntoa((struct in_addr){.s_addr = htonl(node->prefix)}), depth + node->prefixlen,
	       node->prefix, (const char *)node->route, node->children[0], node->children[1],
	       node->prefixlen);
	node_dump(depth + node->prefixlen + 1, node->children[0]);
	node_dump(depth + node->prefixlen + 1, node->children[1]);
}

struct pnode *
child_get(struct pnode *pnode, bool dir)
{
	return dir ? pnode->children[1] : pnode->children[0];
}
/**
 * Create a child node.
 *
 * Creates a child node, the address and prefix appropriately for the parent at the given depth.
 * The provided address is masked off at the given depth.
 *
 * The allocated node will have a prefix equal to the difference in parentdepth and mydepth minus
 * one.  So depth 1 from the root has a prefix of 0.  Depth 7 from node 3, has a prefix of 3.
 *
 * @param parentdepth The parent's depth.
 * @param addr The address field.  Unmodfied.
 * @param mydepth Depth of this node, must be greater than parentdepth.
 */
struct pnode *
child_alloc(uint8_t parentdepth, bitfield_t addr, uint8_t mydepth)
{
	struct pnode *pnode;

	assert(mydepth > parentdepth);

	pnode = palloc(struct pnode);
	pnode->route = NULL;
	pnode->children[0] = pnode->children[1] = NULL;

	// FIXME: Should mask of the addr to 'mydepth'.

	// So the length of the prefix is the difference in depths, minus one.
	pnode->prefixlen = mydepth - parentdepth - 1;

	bitfield_t mask = mask_create(mydepth);
	pnode->prefix = addr & mask;

	return pnode;
}

static struct pnode *
node_child_set(struct pnode *pnode, bool dir, struct pnode *child)
{
	pnode->children[dir] = child;
	return child;
}

/**
 * Bit helpers
 */
/**
 * Get a single bit from a bitfield at the appropriate index.
 *
 * Bits are counted from the MSB, 0 is the first bit.
 *
 * @param bitfield The bitfield to extract the bit from.
 * @param index Index to retrieve [0, #BITFIELD_BITS).
 * @return 1 or 0 (true or false) based on the value of the bit
 */
bool
bit_get(bitfield_t bitfield, uint8_t index)
{
	assert(index < BITFIELD_BITS);
	bitfield_t mask = BITFIELD_ONE << (BITFIELD_BITS - index - 1);
	return bitfield & mask;
}

/**
 * Given two bit fields, return the index of the first different bit or 0 if they are the same in
 * the range.
 *
 * This is harder than it should be as GCC has 'undefined behaviour' for __builtin_clz.
 *
 * @param a First bitfield,
 * @param b Second bitfield
 * @param end <= sizeof bitfield
 * @param last Index of the differing bit, returns end if they match.
 * @return bool If they matched the entire test length, false otherwise.
 *
 */
bool
bit_prefix_compare(bitfield_t a, bitfield_t b, uint8_t end, uint8_t *differing)
{
	if (differing) *differing = end;

	bitfield_t result = (a ^ b);
	if (result == 0) {
		// Easy case; same (all the way);
		return true;
	}

	// FIXME: Should bit the right clz based on sizeof(bitfield)
	uint8_t index = patricia_clz(result);
	if (differing) *differing = index;
	if (index >= end) {
		// Difference after end. don't care
		return true;
	}
	return false;
}
