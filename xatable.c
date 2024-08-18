/*
 * Use multiple XArrays to improve concurrency.
 *
 * Copyright (c) 2020-2022 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "xatable.h"
#include <linux/slab.h>

int xatable_init(struct xatable *xat, unsigned long num_bit)
{
    unsigned long i, num = 1UL << num_bit;
    xat->xa = kmalloc(sizeof(struct xarray) * num, GFP_KERNEL);
    if (xat->xa == NULL)
        return -ENOMEM;
    for (i = 0; i < num; ++i)
        xa_init(xat->xa + i);
    xat->num_bit = num_bit;
    return 0;
}
void xatable_destroy(struct xatable *xat)
{
    unsigned long i, num;
    if (xat->xa == NULL)
        return;
    num = 1UL << xat->num_bit;
    for (i = 0; i < num; ++i)
        xa_destroy(xat->xa + i);
}

void *xatable_store(struct xatable *xat, unsigned long index, void *entry, gfp_t gfp)
{
    unsigned long which = index & ((1UL << xat->num_bit) - 1);
    void *ret;

    index >>= xat->num_bit;
    ret = xa_store(xat->xa + which, index, entry, gfp);
    return ret;
}

void *xatable_load(struct xatable *xat, unsigned long index)
{
    unsigned long which = index & ((1UL << xat->num_bit) - 1);
    void *ret;

    index >>= xat->num_bit;
    ret = xa_load(xat->xa + which, index);
    return ret;
}

void *xatable_cmpxchg(struct xatable *xat, unsigned long index, void *old, void *entry, gfp_t gfp)
{
    unsigned long which = index & ((1UL << xat->num_bit) - 1);
    void *ret;

    index >>= xat->num_bit;
    ret = xa_cmpxchg(xat->xa + which, index, old, entry, gfp);
    return ret;
}

void *xatable_erase(struct xatable *xat, unsigned long index)
{
    unsigned long which = index & ((1UL << xat->num_bit) - 1);
    void *ret;

    index >>= xat->num_bit;
    ret = xa_erase(xat->xa + which, index);
    return ret;
}
