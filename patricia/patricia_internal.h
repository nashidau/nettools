
#include <stdbool.h>
#include <inttypes.h>

// 32 bit or 64bit bitfields
#ifndef PATRICIA_SIZE
#define PATRICIA_SIZE 32
#endif

#if PATRICIA_SIZE == 64
typedef uint64_t bitfield_t;
#define BITFIELD_BITS (sizeof(bitfield_t) << 3)
#define PR_BITFIELD PRIx64
#define BITFIELD_ONE  UINT64_C(1)
#elif PATRICIA_SIZE == 32
typedef uint32_t bitfield_t;
#define BITFIELD_BITS (sizeof(bitfield_t) << 3)
#define PR_BITFIELD PRIx32
#define BITFIELD_ONE UINT32_C(1)
#else
#error Bitfield needs to be 32 or 64 bits.
#endif



// Node of the patricia trie.
struct pnode {
	const void *route;
	// Left is 0, Right is one
	struct pnode *children[2];

	int prefixlen;	   // Number of bits in the prefix
	bitfield_t prefix; // The prefix itself.
};

/**
 * Root Node
 */
struct patricia {
	struct pnode root;

	// AF_INET or AF_INET6
	int family;
};

struct pnode *child_get(struct pnode *pnode, bool dir);
struct pnode *child_alloc(uint8_t depth, bitfield_t addr, uint8_t prefixlen);
void node_free(struct pnode *pnode);
bool bit_get(bitfield_t bitfield, uint8_t index);
bool bit_prefix_compare(bitfield_t a, bitfield_t b, uint8_t end, uint8_t *differing);
