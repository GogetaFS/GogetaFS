/*
 * Deduplication metadata table.
 *
 * Copyright (c) 2024-2025 Yanqi Pan <wadepan.cs@foxmail.com>
 * Copyright (c) 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/atomic.h>
#include <linux/rhashtable.h>
#include <linux/string.h>

#include "f2fs.h"
#include "fingerprint.h"
#include "gogeta.h"
#include "segment.h"

#define TRUST_DEGREE_BITS           3
#define HINT_TRUST_DEGREE_THRESHOLD (1 << (TRUST_DEGREE_BITS - 1))
#define TRUST_DEGREE_MASK           ((1 << TRUST_DEGREE_BITS) - 1)
#define HINT_ADDR_MASK              (~TRUST_DEGREE_MASK)
#define TRUST_DEGREE_MAX            ((1 << TRUST_DEGREE_BITS) - 1)
#define TRUST_DEGREE_MIN            0

DEFINE_PER_CPU(uint8_t, stream_trust_degree_per_cpu);
DEFINE_PER_CPU(struct gogeta_rht_entry *, last_accessed_fpentry_per_cpu);

DECLARE_PER_CPU(uint8_t, stream_trust_degree_per_cpu);
DECLARE_PER_CPU(struct gogeta_rht_entry *, last_accessed_fpentry_per_cpu);

static void __gogeta_init_hint_stream_per_cpu(struct super_block *sb, int cpu)
{
    per_cpu(stream_trust_degree_per_cpu, cpu) = HINT_TRUST_DEGREE_THRESHOLD;
    per_cpu(last_accessed_fpentry_per_cpu, cpu) = NULL;
}

void gogeta_init_hint_stream(struct super_block *sb)
{
    int cpu;
    for_each_possible_cpu(cpu)
        __gogeta_init_hint_stream_per_cpu(sb, cpu);
}

static inline bool hint_trustable(uint8_t trust_degree)
{
    return trust_degree >= HINT_TRUST_DEGREE_THRESHOLD;
}

static inline unsigned long ceil_log_2(unsigned long x)
{
    unsigned long i = 0;
    while ((1UL << i) < x)
        ++i;
    return i;
}

static inline struct gogeta_rht_entry *rht_entry_alloc(
    struct gogeta_meta *meta)
{
    struct gogeta_rht_entry *entry = kmem_cache_zalloc(meta->rht_entry_cache, GFP_ATOMIC);
    return entry;
}

static void gogeta_rht_entry_free(void *entry, void *arg)
{
    struct kmem_cache *c = (struct kmem_cache *)arg;
    kmem_cache_free(c, entry);
}

static inline struct gogeta_revmap_entry *revmap_entry_alloc(struct gogeta_meta *meta)
{
    return kmem_cache_alloc(meta->revmap_entry_cache, GFP_ATOMIC);
}

static void gogeta_revmap_entry_free(struct gogeta_meta *meta, void *entry)
{
    kmem_cache_free(meta->revmap_entry_cache, entry);
}

static void gogeta_rht_and_rev_entry_free(void *entry, void *arg)
{
    struct gogeta_rht_entry *rht_entry = (struct gogeta_rht_entry *)entry;
    struct gogeta_meta *meta = (struct gogeta_meta *)arg;
    struct kmem_cache *c = (struct kmem_cache *)meta->rht_entry_cache;
    struct gogeta_revmap_entry *rev_entry;

    rev_entry = xa_load(&meta->revmap, rht_entry->blocknr);
    if (rev_entry) {
        gogeta_revmap_entry_free(meta, rev_entry);
    }
    kmem_cache_free(c, entry);
}

static u32 gogeta_rht_entry_key_hashfn(const void *data, u32 len, u32 seed)
{
    struct gogeta_fp *fp = (struct gogeta_fp *)data;
    return fp->index;
}

static u32 gogeta_rht_entry_hashfn(const void *data, u32 len, u32 seed)
{
    struct gogeta_rht_entry *entry = (struct gogeta_rht_entry *)data;
    return entry->fp.index;
}

static int gogeta_rht_key_entry_cmp(struct rhashtable_compare_arg *arg,
                                    const void *obj)
{
    const struct gogeta_fp *fp = (const struct gogeta_fp *)arg->key;
    struct gogeta_rht_entry *entry = (struct gogeta_rht_entry *)obj;
    return fp->value != entry->fp.value;
}

const struct rhashtable_params gogeta_rht_params = {
    .key_len = sizeof(struct gogeta_fp),
    .head_offset = offsetof(struct gogeta_rht_entry, node),
    .automatic_shrinking = true,
    .hashfn = gogeta_rht_entry_key_hashfn,
    .obj_hashfn = gogeta_rht_entry_hashfn,
    .obj_cmpfn = gogeta_rht_key_entry_cmp,
};

// nelem_hint: If 0 then use default
// entry_allocator is left for the caller to initialize
int gogeta_meta_alloc(struct gogeta_meta *meta,
                      struct super_block *sb, size_t nelem_hint)
{
    struct f2fs_sb_info *sbi = F2FS_SB(sb);
    int ret;

    meta->sb = sb;
    meta->cpus = num_online_cpus();
    ret = rhashtable_init(&meta->rht, &gogeta_rht_params);
    if (ret < 0)
        goto err_out1;

    meta->rht_entry_cache = kmem_cache_create("rht_entry_cache",
                                              sizeof(struct gogeta_rht_entry), 0, 0, NULL);
    if (meta->rht_entry_cache == NULL) {
        ret = -ENOMEM;
        goto err_out2;
    }

    xa_init(&meta->revmap);
    meta->revmap_entry_cache = kmem_cache_create("revmap_entry_cache",
                                                 sizeof(struct gogeta_revmap_entry), 0, 0, NULL);
    if (meta->revmap_entry_cache == NULL) {
        ret = -ENOMEM;
        goto err_out3;
    }
    atomic64_set(&meta->thread_num, 0);

    ret = xatable_init(&meta->map_blocknr_to_pentry, ceil_log_2(meta->cpus) + 1);
    if (ret < 0)
        goto err_out4;

    return 0;

err_out4:
    kmem_cache_destroy(meta->revmap_entry_cache);
err_out3:
    kmem_cache_destroy(meta->rht_entry_cache);
err_out2:
    rhashtable_free_and_destroy(&meta->rht, gogeta_rht_entry_free,
                                meta->rht_entry_cache);
err_out1:
    return ret;
}

int gogeta_meta_init(struct gogeta_meta *meta, struct super_block *sb)
{
    struct f2fs_sb_info *sbi = F2FS_SB(sb);
    int ret;

    ret = gogeta_meta_alloc(meta, sb, 0);
    if (ret < 0)
        return ret;

    gogeta_init_hint_stream(sb);

    return 0;
}

// Free everything except entry_allocator
void gogeta_meta_free(struct gogeta_meta *meta)
{
    struct gogeta_revmap_entry *revmap_entry;

    rhashtable_free_and_destroy(&meta->rht,
                                gogeta_rht_and_rev_entry_free, meta);
    kmem_cache_destroy(meta->rht_entry_cache);
    kmem_cache_destroy(meta->revmap_entry_cache);

    xa_destroy(&meta->revmap);
    xatable_destroy(&meta->map_blocknr_to_pentry);
}

void gogeta_init_entry(struct gogeta_rht_entry *pentry, struct gogeta_fp fp, unsigned long blocknr)
{
    pentry->fp = fp;
    pentry->blocknr = cpu_to_le64(blocknr);
    atomic64_set(&pentry->next_hint,
                 cpu_to_le64(HINT_TRUST_DEGREE_THRESHOLD));
}

extern void do_write_page(struct f2fs_summary *sum, struct f2fs_io_info *fio);

static void __gogeta_alloc_and_write(struct dnode_of_data *dn, struct f2fs_io_info *fio)
{
    struct f2fs_summary sum;
    struct page *page = fio->page;

    set_page_writeback(page);
    ClearPageError(page);

    set_summary(&sum, dn->nid, dn->ofs_in_node, fio->version);
    do_write_page(&sum, fio);

    // do not drop page too early
    sb_breadahead(fio->sbi->sb, fio->new_blkaddr);
}

static int __gogeta_handle_new_block(struct dnode_of_data *dn, struct f2fs_io_info *fio, struct gogeta_fp fp)
{
    struct gogeta_meta *meta = &fio->sbi->gogeta_meta;
    struct super_block *sb = meta->sb;
    struct gogeta_rht_entry *rht_entry;
    struct gogeta_revmap_entry *rev_entry;
    int cpu, idx;
    int64_t refcount;
    unsigned long blocknr;
    int ret;

    rht_entry = rht_entry_alloc(meta);
    if (rht_entry == NULL) {
        ret = -ENOMEM;
        goto fail0;
    }

    rev_entry = revmap_entry_alloc(meta);
    if (rev_entry == NULL) {
        ret = -ENOMEM;
        goto fail1;
    }

    __gogeta_alloc_and_write(dn, fio);

    blocknr = fio->new_blkaddr;

    gogeta_init_entry(rht_entry, fp, blocknr);

    rev_entry->blocknr = blocknr;
    rev_entry->fp = fp;

    // insert revmap unless the entry is inserted into rhashtable
    xa_store(&meta->revmap, blocknr, rev_entry, GFP_ATOMIC);

    ret = rhashtable_lookup_insert_key(&meta->rht, &fp, &rht_entry->node,
                                       gogeta_rht_params);
    if (ret < 0) {
        printk("Block %lu with fp %llx fail to insert into rhashtable "
               "with error code %d\n",
               blocknr, fp.value, ret);
        xa_erase(&meta->revmap, rev_entry->blocknr);
        goto fail2;
    }

    refcount = atomic64_cmpxchg(&rht_entry->refcount, 0, 1);
    BUG_ON(refcount != 0);

    return 0;

fail2:
    gogeta_revmap_entry_free(meta, rev_entry);
fail1:
    gogeta_rht_entry_free(rht_entry, meta->rht_entry_cache);
fail0:
    return ret;
}

int gogeta_dedup_one_page(struct dnode_of_data *dn, struct f2fs_io_info *fio)
{
    struct f2fs_sb_info *sbi = fio->sbi;
    struct super_block *sb = sbi->sb;
    struct inode *inode = fio->page->mapping->host;
    struct rhashtable *rht = &sbi->gogeta_meta.rht;
    struct gogeta_rht_entry *rht_entry;
    gfp_t gfp_flags = GFP_NOFS;
    void *kaddr;
    struct gogeta_fp fp;
    unsigned long blocknr;
    struct buffer_head *bh;
    int ret;

    /* wait for GCed page writeback via META_MAPPING */
    f2fs_wait_on_block_writeback(inode, fio->old_blkaddr);

    // calc fp
    kaddr = kmap_atomic(fio->page);
    if (!kaddr)
        return -ENOMEM;
    gogeta_fp_calc(kaddr, &fp);
    kunmap_atomic(kaddr);

    dn->fp = fp;

retry:
    rcu_read_lock();
    rht_entry = rhashtable_lookup(rht, &fp, gogeta_rht_params);
    if (rht_entry == NULL) {
        rcu_read_unlock();
        fio->duplicated = false;
        ret = __gogeta_handle_new_block(dn, fio, fp);
        if (ret == -EEXIST)
            goto retry;
        return 0;
    }

    blocknr = rht_entry->blocknr;

    BUG_ON(blocknr == 0);
    BUG_ON(sb->s_blocksize != PAGE_SIZE);

    // content cmp
    bh = sb_bread(sb, blocknr);
    if (!bh) {
        f2fs_err(sbi, "fail to read block %lu\n", blocknr);
        rcu_read_unlock();
        return -EIO;
    }
    kaddr = kmap_atomic(fio->page);
    if (!memcmp(bh->b_data, kaddr, sb->s_blocksize)) {
        // f2fs_debug(sbi, "%s: duplicated\n", __func__);
        // the same
        fio->new_blkaddr = blocknr;
        fio->duplicated = true;
    } else {
        // f2fs_debug(sbi, "%s: collision\n", __func__);
        // different
        fio->duplicated = false;
    }
    kunmap_atomic(kaddr);
    brelse(bh);

    // refcount
    if (fio->duplicated) {
        atomic64_fetch_add_unless(&rht_entry->refcount, 1, 0);
        fio->last_accessed = rht_entry;
    } else {
        __gogeta_alloc_and_write(dn, fio);
        fio->last_accessed = NULL;
    }

    rcu_read_unlock();
    return 0;
}

static inline void incr_stream_trust_degree(struct f2fs_io_info *fio)
{
    if (fio->stream_trust_degree < TRUST_DEGREE_MAX)
        fio->stream_trust_degree += 1;
}

static inline void decr_stream_trust_degree(struct f2fs_io_info *fio)
{
    if (fio->stream_trust_degree < TRUST_DEGREE_MIN + 2)
        fio->stream_trust_degree = TRUST_DEGREE_MIN;
    else
        fio->stream_trust_degree -= 2;
}

static u64 __update_hint(struct gogeta_meta *meta, atomic64_t *next_hint, u64 old_hint, u64 new_hint)
{
    return le64_to_cpu(atomic64_cmpxchg_relaxed(
        next_hint,
        cpu_to_le64(old_hint),
        cpu_to_le64(new_hint)));
}

static u64 __incr_trust_degree(struct gogeta_meta *meta, atomic64_t *next_hint, u64 addr_ori,
                               uint8_t trust_degree)
{
    __le64 old_hint = cpu_to_le64(addr_ori | trust_degree);
    __le64 tmp;
    uint64_t hint;

    while (1) {
        if (trust_degree == TRUST_DEGREE_MAX)
            return 0;
        trust_degree += 1;
        hint = addr_ori | trust_degree;
        tmp = __update_hint(meta, next_hint, old_hint, cpu_to_le64(hint));
        if (tmp == old_hint)
            return 0;
        hint = le64_to_cpu(tmp);
        if ((hint & HINT_ADDR_MASK) != addr_ori) {
            // The hinted fpentry has been changed.
            return hint;
        }
        trust_degree = hint & TRUST_DEGREE_MASK;
        old_hint = tmp;
    }
}

static u64 __decr_trust_degree(struct gogeta_meta *meta, atomic64_t *next_hint, u64 addr_ori,
                               u64 addr_new, uint8_t trust_degree)
{
    __le64 old_hint = cpu_to_le64(addr_ori | trust_degree);
    __le64 tmp;
    uint64_t hint;

    while (1) {
        if (trust_degree < TRUST_DEGREE_MIN + 2) {
            trust_degree = TRUST_DEGREE_MIN;
        } else {
            trust_degree -= 2;
        }

        if (!hint_trustable(trust_degree)) {
            hint = addr_new | trust_degree;
        } else {
            hint = addr_ori | trust_degree;
        }

        // tmp = atomic64_cmpxchg_relaxed(next_hint, old_hint,
        // 	cpu_to_le64(hint));
        tmp = __update_hint(meta, next_hint, old_hint, cpu_to_le64(hint));
        if (tmp == old_hint)
            return 0;
        hint = le64_to_cpu(tmp);
        if ((hint & HINT_ADDR_MASK) != addr_ori) {
            // The hinted fpentry has been changed.
            return hint;
        }
        trust_degree = hint & TRUST_DEGREE_MASK;
        old_hint = tmp;
    }
}

static int handle_no_hint(struct dnode_of_data *dn, struct f2fs_io_info *fio, atomic64_t *next_hint,
                          u64 old_hint)
{
    u64 addr;
    uint8_t trust_degree;
    uint64_t hint;
    struct gogeta_meta *meta = &fio->sbi->gogeta_meta;
    int ret = 0;

    ret = gogeta_dedup_one_page(dn, fio);
    if (ret < 0) {
        return ret;
    }
    if (unlikely(fio->last_accessed == NULL)) {
        return ret;
    }

    addr = fio->last_accessed;

    hint = __update_hint(meta, next_hint, old_hint,
                         addr | HINT_TRUST_DEGREE_THRESHOLD);

    if ((hint & HINT_ADDR_MASK) == addr) {
        trust_degree = hint & TRUST_DEGREE_MASK;
        __incr_trust_degree(meta, next_hint, addr, trust_degree);
    }
    return ret;
}

static int handle_not_trust(struct dnode_of_data *dn, struct f2fs_io_info *fio, atomic64_t *next_hint,
                            u64 addr, uint8_t trust_degree)
{
    u64 addr_new;
    struct gogeta_meta *meta = &fio->sbi->gogeta_meta;
    int ret = 0;

    ret = gogeta_dedup_one_page(dn, fio);
    if (ret < 0)
        return ret;
    if (unlikely(fio->last_accessed == NULL))
        return ret;
    addr_new = fio->last_accessed;
    if (addr_new == addr) {
        __incr_trust_degree(meta, next_hint, addr, trust_degree);
        incr_stream_trust_degree(fio);
    } else {
        __decr_trust_degree(meta, next_hint, addr, addr_new,
                            trust_degree);
        decr_stream_trust_degree(fio);
    }
    return ret;
}

static void handle_hint_of_hint(struct dnode_of_data *dn, struct f2fs_io_info *fio, atomic64_t *next_hint)
{
    uint64_t hint = le64_to_cpu(atomic64_read(next_hint));
    u64 addr = hint & HINT_ADDR_MASK;
    uint8_t trust_degree = hint & TRUST_DEGREE_MASK;
    struct gogeta_rht_entry *pentry = (struct gogeta_rht_entry *)addr;
    unsigned long blocknr;

    // Be conservative because prefetching consumes bandwidth.
    if (fio->stream_trust_degree != TRUST_DEGREE_MAX || addr == 0 ||
        !hint_trustable(trust_degree))
        return;
    if (atomic64_read(&pentry->refcount) == 0)
        return;

    blocknr = pentry->blocknr;
    BUG_ON(blocknr == 0);
    fio->block_prefetching = pentry->blocknr;
    fio->prefetched_blocknr[1] = fio->prefetched_blocknr[0];
    fio->prefetched_blocknr[0] = blocknr;
}

static int check_hint(struct dnode_of_data *dn, struct f2fs_io_info *fio, struct gogeta_rht_entry *speculative_pentry)
{
    struct f2fs_sb_info *sbi = fio->sbi;
    struct super_block *sb = sbi->sb;
    struct gogeta_meta *meta = &sbi->gogeta_meta;
    unsigned long speculative_blocknr;
    const char *speculative_addr;
    int64_t ret;
    struct buffer_head *bh;

    // To make sure that pentry will not be released while we
    // are reading its content.
    rcu_read_lock();
    // NOTE: entry will be valid if there is a holder.
    if (atomic64_read(&speculative_pentry->refcount) == 0) {
        rcu_read_unlock();
        f2fs_warn(sbi, "refcount is 0\n");
        return 0;
    }

    speculative_blocknr = speculative_pentry->blocknr;
    BUG_ON(speculative_blocknr == 0);
    // It is guaranteed that the block will not be freed,
    // because we are holding the RCU read lock.

    handle_hint_of_hint(dn, fio, &speculative_pentry->next_hint);

    // Increase refcount speculatively
    ret = atomic64_add_unless(&speculative_pentry->refcount, 1, 0);
    if (ret == false) {
        rcu_read_unlock();
        return 0;
    }

    // The blocknr will not be released now, because we are referencing it.
    rcu_read_unlock();

    // prefetch next
    if (fio->block_prefetching)
        sb_breadahead(sb, fio->block_prefetching);

    bh = sb_bread(sb, speculative_blocknr);
    speculative_addr = kmap_atomic(fio->page);
    ret = memcmp(bh->b_data, speculative_addr, sb->s_blocksize);
    kunmap_atomic(speculative_addr);
    brelse(bh);

    if (ret < 0) {
        atomic64_add_return(-1, &speculative_pentry->refcount);
        return -EFAULT;
    }

    if (ret != 0) {
        atomic64_add_return(-1, &speculative_pentry->refcount);
        return 0;
    }

    fio->last_accessed = speculative_pentry;

    return 1;
}

static int handle_hint(struct dnode_of_data *dn, struct f2fs_io_info *fio, atomic64_t *next_hint)
{
    uint64_t hint = le64_to_cpu(atomic64_read(next_hint));
    u64 addr = hint & HINT_ADDR_MASK;
    uint8_t trust_degree = hint & TRUST_DEGREE_MASK;
    struct gogeta_rht_entry *speculative_pentry = (struct gogeta_rht_entry *)addr;
    struct gogeta_meta *meta = &fio->sbi->gogeta_meta;
    int ret;

    if (addr == 0) {
        // Actually no hint
        return handle_no_hint(dn, fio, next_hint, hint);
    }

    if (!hint_trustable(trust_degree)) {
        return handle_not_trust(dn, fio, next_hint,
                                addr, trust_degree);
    }

    ret = check_hint(dn, fio, speculative_pentry);
    if (ret < 0)
        return ret;

    if (ret == 1) {
        __incr_trust_degree(meta, next_hint, addr, trust_degree);
        incr_stream_trust_degree(fio);
        return 0;
    }

    BUG_ON(ret != 0);

    ret = gogeta_dedup_one_page(dn, fio);
    if (ret < 0)
        return ret;

    if (unlikely(fio->last_accessed == NULL))
        return ret;

    __decr_trust_degree(meta, next_hint, addr,
                        fio->last_accessed,
                        trust_degree);
    decr_stream_trust_degree(fio);
    return ret;
}

int gogeta_dedup_one_page_acc(struct dnode_of_data *dn, struct f2fs_io_info *fio)
{
    int cpu;

    cpu = get_cpu();
    fio->last_accessed = per_cpu(last_accessed_fpentry_per_cpu, cpu);
    fio->stream_trust_degree = per_cpu(stream_trust_degree_per_cpu, cpu);
    put_cpu();

    fio->block_prefetching = 0;
    fio->prefetched_blocknr[0] = fio->prefetched_blocknr[1] = 0;

    if (fio->last_accessed) {
        handle_hint(dn, fio, &fio->last_accessed->next_hint);
    } else {
        gogeta_dedup_one_page(dn, fio);
    }

    cpu = get_cpu();
    per_cpu(last_accessed_fpentry_per_cpu, cpu) = fio->last_accessed;
    per_cpu(stream_trust_degree_per_cpu, cpu) = fio->stream_trust_degree;
    put_cpu();

    return 0;
}