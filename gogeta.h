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
};

struct gogeta_revmap_entry {
	// struct rb_node node;
	__le64 blocknr;
	struct gogeta_fp fp;
};

#endif