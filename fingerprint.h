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

#include <linux/types.h>
#include "wyhash.h"

struct gogeta_fp {
	union {
		u32 index;
		u64 value;
	};
};

_Static_assert(sizeof(struct gogeta_fp) == 8, "Fingerprint not 8B!");

static inline int gogeta_fp_calc(const void *addr, struct gogeta_fp *fp)
{
	// ret.value = xxh64((const char *)addr, 4096, 0);
	fp->value = wyhash((const char *)addr, 4096, 0, _wyp);
	return 0;
}

#endif // FINGERPRINT_H_