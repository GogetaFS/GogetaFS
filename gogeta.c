/*
 * Deduplication metadata table.
 *
 * Copyright (c) 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/atomic.h>
#include <linux/rhashtable.h>
#include <linux/string.h>

#include "gogeta.h"
#include "f2fs.h"
#include "fingerprint.h"
#include "segment.h"

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
}

extern void do_write_page(struct f2fs_summary *sum, struct f2fs_io_info *fio);

int gogeta_handle_new_block(struct dnode_of_data *dn, struct f2fs_io_info *fio, struct gogeta_fp fp)
{
    struct gogeta_meta *meta = &fio->sbi->gogeta_meta;
    struct super_block *sb = meta->sb;
    struct gogeta_rht_entry *rht_entry;
    struct gogeta_revmap_entry *rev_entry;
    struct f2fs_summary sum;
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

    set_summary(&sum, dn->nid, dn->ofs_in_node, fio->version);
    do_write_page(&sum, fio);

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

int gogeta_identify_one_page(struct dnode_of_data *dn, struct f2fs_io_info *fio)
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
        ret = gogeta_handle_new_block(dn, fio, fp);
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
        // the same
        fio->new_blkaddr = blocknr;
        fio->duplicated = true;
    } else {
        // different
        fio->duplicated = false;
    }
    kunmap_atomic(kaddr);
    brelse(bh);

    // refcount
    if (fio->duplicated) {
        atomic64_fetch_add_unless(&rht_entry->refcount, 1, 0);
    }

    rcu_read_unlock();
    return 0;
}