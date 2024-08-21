/*
 * Definitions of fingerprints.
 *
 * Copyright (c) 2024-2026 Yanqi Pan <wadepan.cs@foxmail.com>
 * Copyright (c) 2020-2022 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef FINGERPRINT_H_
#define FINGERPRINT_H_

#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/crypto.h>
#include <linux/types.h>

#include "wyhash.h"

struct gogeta_fp {
    union {
        u32 index;
        u64 value;
    };
};

struct fp_entry {
	struct gogeta_fp fp;
	u64 blocknr;
	u64 refcount;
	u8 padding[8];
} __packed;

_Static_assert(sizeof(struct gogeta_fp) == 8, "Fingerprint not 8B!");
_Static_assert(sizeof(struct fp_entry) == 32, "Fingerprint entry not 4B!");

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static inline struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_ATOMIC);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static inline int calc_hash(struct crypto_shash *alg, const unsigned char *data,
                            unsigned int datalen, unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }
    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static inline unsigned long get_index(char *digest) {
    unsigned long res = 0;
    unsigned long mask = (unsigned long)(1 << 15) - (unsigned long)1;
    res = (((unsigned char)digest[0] << 10) | ((unsigned char)digest[1] << 2) | ((((unsigned char)digest[2]) & 0xc0) >> 6)) & mask;
    return res;
}

static inline int gogeta_fp_calc(const void *addr, struct gogeta_fp *fp, unsigned long *f_ofs)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";
    unsigned char digest[SHA256_DIGEST_SIZE];
    int ret;

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    ret = calc_hash(alg, addr, 4096, digest);
    crypto_free_shash(alg);

    memcpy(&fp->value, digest, sizeof(fp->value));

	// 32B per fingerprint
	if (f_ofs)
		*f_ofs = get_index(digest) << 5;

    return 0;
}

#endif // FINGERPRINT_H_