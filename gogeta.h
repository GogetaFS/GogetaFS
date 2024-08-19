#ifndef __GOGETA_H
#define __GOGETA_H

#include "fingerprint.h"

// FP to PBN mapping
struct gogeta_rht_entry {
	struct rhash_head node;
	struct gogeta_fp fp;
	__le64 blocknr;
	atomic64_t refcount;
    // TODO: prefetch
	// Lowest 3 bits are unsigned trust degree (<= 7). Initially 4.
	// For each result matching the hint, the trust degree += 1
	// For each result mismatching the hint, the trust degree -= 2.
	// If the resulting trust degree < 0, then the offset is updated.
	// If the trust degree < 4, then the hint is not taken.
	atomic64_t next_hint;
};

struct gogeta_revmap_entry {
	// struct rb_node node;
	__le64 blocknr;
	struct gogeta_fp fp;
};

#endif