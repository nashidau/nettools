
#include <stdbool.h>
#include <stdint.h>

// These need to all update together
typedef uint32_t bitfield_t;
#define BITFIELD_BITS (sizeof(bitfield_t) << 3)

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