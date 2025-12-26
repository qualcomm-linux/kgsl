// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <linux/kthread.h>
#include <linux/notifier.h>
#include <linux/pagevec.h>
#include <linux/shmem_fs.h>
#include <linux/swap.h>
#include <linux/version.h>

#include "kgsl_reclaim.h"
#include "kgsl_sharedmem.h"
#include "kgsl_trace.h"

/*
 * Reclaiming excessive number of pages from a process will impact launch
 * latency for the subsequent launch of the process. After measuring the
 * launch latencies by having various maximum limits, it has been decided
 * that allowing 30MB (7680 pages) of relcaim per process will have little
 * impact and the latency will be within acceptable limit.
 */
static u32 kgsl_reclaim_max_page_limit = 7680;

/* Setting this to 0 means we reclaim pages as specified in shrinker call */
static u32 kgsl_nr_to_scan;

struct work_struct reclaim_work;

static atomic_t kgsl_nr_to_reclaim;

#if (KERNEL_VERSION(6, 2, 0) <= LINUX_VERSION_CODE)
static void kgsl_memdesc_clear_unevictable(struct kgsl_process_private *process,
		struct kgsl_memdesc *memdesc)
{
	struct folio_batch fbatch;
	int i;

	/*
	 * Pages that are first allocated are by default added to
	 * unevictable list. To reclaim them, we first clear the
	 * AS_UNEVICTABLE flag of the shmem file address space thus
	 * check_move_unevictable_folios() places them on the
	 * evictable list.
	 *
	 * Once reclaim is done, hint that further shmem allocations
	 * will have to be on the unevictable list.
	 */
	mapping_clear_unevictable(memdesc->shmem_filp->f_mapping);
	folio_batch_init(&fbatch);
	for (i = 0; i < memdesc->page_count; i++) {
		set_page_dirty_lock(memdesc->pages[i]);
		spin_lock(&memdesc->lock);
		folio_batch_add(&fbatch, page_folio(memdesc->pages[i]));
		memdesc->pages[i] = NULL;
		atomic_inc(&process->unpinned_page_count);
		spin_unlock(&memdesc->lock);
		if (folio_batch_count(&fbatch) == PAGEVEC_SIZE) {
			check_move_unevictable_folios(&fbatch);
			__folio_batch_release(&fbatch);
		}
	}

	if (folio_batch_count(&fbatch)) {
		check_move_unevictable_folios(&fbatch);
		__folio_batch_release(&fbatch);
	}
}

static int kgsl_read_mapping(struct kgsl_memdesc *memdesc, struct page **page, int i)
{
	struct folio *folio = shmem_read_folio_gfp(memdesc->shmem_filp->f_mapping,
						   i, kgsl_gfp_mask(0));

	if (!IS_ERR(folio)) {
		*page = folio_page(folio, 0);
		return 0;
	}

	return PTR_ERR(folio);
}
#else
static void kgsl_memdesc_clear_unevictable(struct kgsl_process_private *process,
		struct kgsl_memdesc *memdesc)
{
	struct pagevec pvec;
	int i;

	/*
	 * Pages that are first allocated are by default added to
	 * unevictable list. To reclaim them, we first clear the
	 * AS_UNEVICTABLE flag of the shmem file address space thus
	 * check_move_unevictable_pages() places them on the
	 * evictable list.
	 *
	 * Once reclaim is done, hint that further shmem allocations
	 * will have to be on the unevictable list.
	 */
	mapping_clear_unevictable(memdesc->shmem_filp->f_mapping);
	pagevec_init(&pvec);
	for (i = 0; i < memdesc->page_count; i++) {
		set_page_dirty_lock(memdesc->pages[i]);
		spin_lock(&memdesc->lock);
		pagevec_add(&pvec, memdesc->pages[i]);
		memdesc->pages[i] = NULL;
		atomic_inc(&process->unpinned_page_count);
		spin_unlock(&memdesc->lock);
		if (pagevec_count(&pvec) == PAGEVEC_SIZE) {
			check_move_unevictable_pages(&pvec);
			__pagevec_release(&pvec);
		}
	}

	if (pagevec_count(&pvec)) {
		check_move_unevictable_pages(&pvec);
		__pagevec_release(&pvec);
	}
}

static int kgsl_read_mapping(struct kgsl_memdesc *memdesc, struct page **page, int i)
{
	*page = shmem_read_mapping_page_gfp(memdesc->shmem_filp->f_mapping,
					   i, kgsl_gfp_mask(0));
	return PTR_ERR_OR_ZERO(*page);
}
#endif

static int kgsl_memdesc_get_reclaimed_pages(struct kgsl_mem_entry *entry)
{
	struct kgsl_memdesc *memdesc = &entry->memdesc;
	int i, ret;
	struct page *page = NULL;

	spin_lock(&memdesc->lock);
	for (i = 0; i < memdesc->page_count; i++) {
		if (memdesc->pages[i])
			continue;

		spin_unlock(&memdesc->lock);
		ret = kgsl_read_mapping(memdesc, &page, i);
		if (ret)
			return ret;

		kgsl_page_sync(memdesc->dev, page, PAGE_SIZE, DMA_BIDIRECTIONAL);

		/*
		 * Update the pages array only if vmfault has not
		 * updated it meanwhile
		 */
		spin_lock(&memdesc->lock);
		if (!memdesc->pages[i]) {
			memdesc->pages[i] = page;
			atomic_dec(&entry->priv->unpinned_page_count);
		} else
			put_page(page);
		spin_unlock(&memdesc->lock);
	}
	spin_unlock(&memdesc->lock);

	ret = kgsl_mmu_map(memdesc->pagetable, memdesc);
	if (ret)
		return ret;

	trace_kgsl_reclaim_memdesc(entry, false);

	CLEAR_FLAG(KGSL_MEMDESC_RECLAIMED | KGSL_MEMDESC_SKIP_RECLAIM, &memdesc->priv);

	return 0;
}

int kgsl_reclaim_to_pinned_state(
		struct kgsl_process_private *process)
{
	struct kgsl_mem_entry *entry, *valid_entry;
	int next = 0, ret = 0, count;

	mutex_lock(&process->reclaim_lock);

	if (test_bit(KGSL_PROC_PINNED_STATE, &process->state))
		goto done;

	count = atomic_read(&process->unpinned_page_count);

	for ( ; ; ) {
		valid_entry = NULL;
		spin_lock(&process->mem_lock);
		entry = idr_get_next(&process->mem_idr, &next);
		if (entry == NULL) {
			spin_unlock(&process->mem_lock);
			break;
		}

		if (TEST_FLAG(KGSL_MEMDESC_RECLAIMED, &entry->memdesc.priv))
			valid_entry = kgsl_mem_entry_get(entry);
		spin_unlock(&process->mem_lock);

		if (valid_entry) {
			ret = kgsl_memdesc_get_reclaimed_pages(entry);
			kgsl_mem_entry_put(entry);
			if (ret)
				goto done;
		}

		next++;
	}

	trace_kgsl_reclaim_process(process, count, false);
	set_bit(KGSL_PROC_PINNED_STATE, &process->state);
done:
	mutex_unlock(&process->reclaim_lock);
	return ret;
}

static void kgsl_reclaim_foreground_work(struct work_struct *work)
{
	struct kgsl_process_private *process =
		container_of(work, struct kgsl_process_private, fg_work);

	if (test_bit(KGSL_PROC_STATE, &process->state))
		kgsl_reclaim_to_pinned_state(process);
	kgsl_process_private_put(process);
}

#ifdef CONFIG_QCOM_KGSL_HYBRID_ALLOCATION
static void _copy_page(struct kgsl_memdesc *memdesc, struct page *dest, struct page *src)
{
	void *src_ptr, *dest_ptr;

	set_page_dirty_lock(src);

	src_ptr = kmap_local_page(src);
	dest_ptr = kmap_local_page(dest);

	memcpy(dest_ptr, src_ptr, PAGE_SIZE);
	kunmap_local(src_ptr);
	kunmap_local(dest_ptr);

	kgsl_page_sync(memdesc->dev, dest, PAGE_SIZE, DMA_BIDIRECTIONAL);
}

static u32 kgsl_shmem_mem_entry_migrate(struct mm_struct *mm, struct kgsl_mem_entry *entry)
{
	struct kgsl_memdesc *memdesc = &entry->memdesc;
	u32 page_count = 0;
	struct page **pages = NULL;
	struct file *shmem_filp = NULL;
	int i = 0;
	int ret = 1;
	int vidx;
	struct vm_area_struct *vma;
	int page_size = PAGE_SIZE;
	struct page **old_pages;

	/* Skip mem entries that are mapped into a VBO */
	if (atomic_read(&entry->vbo_count))
		return 0;

	/* Check if migrating this memdesc will put us over the limit */
	if ((atomic_read(&entry->priv->migrated_page_count) + memdesc->page_count) >
		kgsl_reclaim_max_page_limit)
		return 0;

	pages = kvcalloc(memdesc->page_count, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return 0;

	shmem_filp = kgsl_memdesc_file_setup(memdesc);
	if (IS_ERR_OR_NULL(shmem_filp))
		goto cleanup_pages;

	/* Allocate replacement shmem pages */
	for (i = 0; i < memdesc->page_count; i++) {
		ret = kgsl_alloc_shmem_page(memdesc, shmem_filp, &page_size, &pages[i], NULL, i);
		if (ret <= 0) {
			pr_err_ratelimited(
				"kgsl: Failed to alloc shmem page process %d entry %d offset %d\n",
				pid_nr(entry->priv->pid), entry->id, i);
			goto cleanup_shmem;
		}
	}

	/* Unmap the memdesc from the mmu */
	ret = kgsl_mmu_unmap(memdesc->pagetable, memdesc);
	if (ret) {
		pr_err_ratelimited("kgsl: Failed to unmap process %d entry %d\n",
				pid_nr(entry->priv->pid), entry->id);
		kill_pid(entry->priv->pid, SIGKILL, 1);
		goto cleanup_shmem;
	}

	/* Take the mmap write lock to prevent concurrent entry mmaps and vm_faults */
	mmap_write_lock(mm);

	/*
	 * Zap ptes to force a vm_fault on the next userspace access.
	 * vma_idr is protected by the mmap lock
	 */
	idr_for_each_entry(&memdesc->vma_idr, vma, vidx) {
		zap_page_range_single(vma, vma->vm_start,
			vma->vm_end - vma->vm_start, NULL);
	}

	for (i = 0; i < memdesc->page_count; ) {
		struct page *p;
		int n;
		int count;

		p = memdesc->pages[i];
		count = 1 << compound_order(p);

		/* Copy over existing data */
		for (n = 0; n < count; n++) {
			struct page *page = memdesc->pages[i + n];
			struct page *new_page = pages[i + n];

			_copy_page(memdesc, new_page, page);
			page_count++;
		}

		i += count;
	}

	old_pages = memdesc->pages;
	spin_lock(&memdesc->lock);
	memdesc->pages = pages;
	memdesc->shmem_filp = shmem_filp;
	SET_FLAG(KGSL_MEMDESC_MIGRATED, &memdesc->priv);
	spin_unlock(&memdesc->lock);

	/* Re-enable mmaps and vm_faults on the entry memdesc */
	mmap_write_unlock(mm);

	/* Free the old pages back into the pool */
	kgsl_pool_free_pages(old_pages, memdesc->page_count);
	kvfree(old_pages);

	/* Map the new pages to the mmu */
	ret = kgsl_mmu_map(memdesc->pagetable, memdesc);
	if (ret) {
		pr_err_ratelimited("kgsl: Failed to map process %d entry %d\n",
					pid_nr(entry->priv->pid), entry->id);
		kill_pid(entry->priv->pid, SIGKILL, 1);
	}

	atomic_add(memdesc->page_count, &entry->priv->migrated_page_count);
	trace_kgsl_migrate_memdesc(entry);

	return page_count;

cleanup_shmem:
	for (i--; i >= 0; i--)
		put_page(pages[i]);

	kgsl_memdesc_pagelist_cleanup(shmem_filp, memdesc);
	SHMEM_I(shmem_filp->f_mapping->host)->android_vendor_data1 = 0;
	fput(shmem_filp);

cleanup_pages:
	kvfree(pages);

	return 0;
}

static void kgsl_shmem_migrate(struct kgsl_process_private *process)
{
	u32 migrate_count = 0;
	struct kgsl_mem_entry *entry;
	struct task_struct *task;
	struct mm_struct *mm;
	u32 next = 0;

	/* Skip migration if we're already over the limit for the process */
	if (atomic_read(&process->migrated_page_count) >= kgsl_reclaim_max_page_limit)
		return;

	if (!mutex_trylock(&process->reclaim_lock))
		return;

	task = get_pid_task(process->pid, PIDTYPE_PID);
	if (!task)
		goto done;

	mm = get_task_mm(task);
	if (!mm)
		goto put_task;

	for ( ; ; ) {
		struct kgsl_mem_entry *valid_entry = NULL;
		u32 priv;

		/* Abort migration if process submitted work. */
		if (atomic_read(&process->cmd_count))
			goto abort;

		if (atomic_read(&process->migrated_page_count) >= kgsl_reclaim_max_page_limit)
			break;

		spin_lock(&process->mem_lock);
		entry = idr_get_next(&process->mem_idr, &next);
		if (entry == NULL) {
			spin_unlock(&process->mem_lock);
			break;
		}

		/*
		 * Skip entries that are pending free or are already migrated or
		 * cannot be reclaimed
		 */
		priv = atomic_read(&entry->memdesc.priv);
		if (!(entry->pending_free || (priv & KGSL_MEMDESC_MIGRATED) ||
			!(priv & KGSL_MEMDESC_CAN_RECLAIM)))
			valid_entry = kgsl_mem_entry_get(entry);

		spin_unlock(&process->mem_lock);

		next++;
		if (!valid_entry)
			continue;

		migrate_count += kgsl_shmem_mem_entry_migrate(mm, valid_entry);
		kgsl_mem_entry_put(valid_entry);
	}

	clear_bit(KGSL_PROC_CAN_MIGRATE, &process->state);
abort:
	trace_kgsl_migrate_process(process, migrate_count);
	mmput(mm);
put_task:
	put_task_struct(task);
done:
	mutex_unlock(&process->reclaim_lock);
}

static void kgsl_background_work(struct work_struct *work)
{
	struct kgsl_process_private *process =
		container_of(work, struct kgsl_process_private, bg_work);

	if (!test_bit(KGSL_PROC_STATE, &process->state))
		kgsl_shmem_migrate(process);
	kgsl_process_private_put(process);
}
#else
static void kgsl_background_work(struct work_struct *work)
{
}
#endif

static ssize_t kgsl_proc_state_show(struct kobject *kobj,
		struct kgsl_process_attribute *attr, char *buf)
{
	struct kgsl_process_private *process =
		container_of(kobj, struct kgsl_process_private, kobj);

	if (test_bit(KGSL_PROC_STATE, &process->state))
		return scnprintf(buf, PAGE_SIZE, "foreground\n");
	else
		return scnprintf(buf, PAGE_SIZE, "background\n");
}

static ssize_t kgsl_proc_state_store(struct kobject *kobj,
	struct kgsl_process_attribute *attr, const char *buf, ssize_t count)
{
	struct kgsl_process_private *process =
		container_of(kobj, struct kgsl_process_private, kobj);

	if (sysfs_streq(buf, "foreground")) {
		if (!test_and_set_bit(KGSL_PROC_STATE, &process->state) &&
			kgsl_process_private_get(process))
			kgsl_schedule_work(&process->fg_work);
	} else if (sysfs_streq(buf, "background")) {
		clear_bit(KGSL_PROC_STATE, &process->state);
	} else
		return -EINVAL;

	return count;
}

static ssize_t gpumem_reclaimed_show(struct kobject *kobj,
		struct kgsl_process_attribute *attr, char *buf)
{
	struct kgsl_process_private *process =
		container_of(kobj, struct kgsl_process_private, kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
		atomic_read(&process->unpinned_page_count) << PAGE_SHIFT);
}

PROCESS_ATTR(state, 0644, kgsl_proc_state_show, kgsl_proc_state_store);
PROCESS_ATTR(gpumem_reclaimed, 0444, gpumem_reclaimed_show, NULL);

static const struct attribute *proc_reclaim_attrs[] = {
	&attr_state.attr,
	&attr_gpumem_reclaimed.attr,
	NULL,
};

void kgsl_reclaim_proc_sysfs_init(struct kgsl_process_private *process)
{
	WARN_ON(sysfs_create_files(&process->kobj, proc_reclaim_attrs));
}

ssize_t kgsl_proc_max_reclaim_limit_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int ret;

	ret = kstrtou32(buf, 0, &kgsl_reclaim_max_page_limit);
	return ret ? ret : count;
}

ssize_t kgsl_proc_max_reclaim_limit_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", kgsl_reclaim_max_page_limit);
}

ssize_t kgsl_nr_to_scan_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int ret;

	ret = kstrtou32(buf, 0, &kgsl_nr_to_scan);
	return ret ? ret : count;
}

ssize_t kgsl_nr_to_scan_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", kgsl_nr_to_scan);
}

static u32 kgsl_reclaim_process(struct kgsl_process_private *process,
		u32 pages_to_reclaim)
{
	struct kgsl_memdesc *memdesc;
	struct kgsl_mem_entry *entry, *valid_entry;
	u32 next = 0, remaining = pages_to_reclaim, priv = 0;

	/*
	 * If we do not get the lock here, it means that the buffers are
	 * being pinned back. So do not keep waiting here as we would anyway
	 * return empty handed once the lock is acquired.
	 */
	if (!mutex_trylock(&process->reclaim_lock))
		return 0;

	while (remaining) {

		if (atomic_read(&process->unpinned_page_count) >=
				kgsl_reclaim_max_page_limit)
			break;

		/* Abort reclaim if process submitted work. */
		if (atomic_read(&process->cmd_count))
			break;

		/* Abort reclaim if process foreground hint is received. */
		if (test_bit(KGSL_PROC_STATE, &process->state))
			break;

		valid_entry = NULL;
		spin_lock(&process->mem_lock);
		entry = idr_get_next(&process->mem_idr, &next);
		if (entry == NULL) {
			spin_unlock(&process->mem_lock);
			break;
		}

		memdesc = &entry->memdesc;
		priv = atomic_read(&memdesc->priv);
		if (!entry->pending_free &&
				(priv & KGSL_MEMDESC_CAN_RECLAIM) &&
				!(priv & KGSL_MEMDESC_RECLAIMED) &&
				!(priv & KGSL_MEMDESC_SKIP_RECLAIM))
			valid_entry = kgsl_mem_entry_get(entry);
		spin_unlock(&process->mem_lock);

		if (!valid_entry) {
			next++;
			continue;
		}

		/* Do not reclaim pages mapped into a VBO */
		if (atomic_read(&valid_entry->vbo_count)) {
			kgsl_mem_entry_put(entry);
			next++;
			continue;
		}

		if ((atomic_read(&process->unpinned_page_count) +
			memdesc->page_count) > kgsl_reclaim_max_page_limit) {
			kgsl_mem_entry_put(entry);
			next++;
			continue;
		}

		if (memdesc->page_count > remaining) {
			kgsl_mem_entry_put(entry);
			next++;
			continue;
		}

		if (!kgsl_mmu_unmap(memdesc->pagetable, memdesc)) {
			kgsl_memdesc_clear_unevictable(process, memdesc);
			remaining -= memdesc->page_count;
			reclaim_shmem_address_space(memdesc->shmem_filp->f_mapping);
			mapping_set_unevictable(memdesc->shmem_filp->f_mapping);
			SET_FLAG(KGSL_MEMDESC_RECLAIMED, &memdesc->priv);
			trace_kgsl_reclaim_memdesc(entry, true);
		}

		kgsl_mem_entry_put(entry);
		next++;
	}

	if (next)
		clear_bit(KGSL_PROC_PINNED_STATE, &process->state);

	trace_kgsl_reclaim_process(process, pages_to_reclaim - remaining, true);
	mutex_unlock(&process->reclaim_lock);

	return (pages_to_reclaim - remaining);
}

static void kgsl_reclaim_background_work(struct work_struct *work)
{
	u32 bg_proc = 0, nr_pages = atomic_read(&kgsl_nr_to_reclaim);
	u64 pp_nr_pages;
	struct list_head kgsl_reclaim_process_list;
	struct kgsl_process_private *process, *next;

	INIT_LIST_HEAD(&kgsl_reclaim_process_list);
	read_lock(&kgsl_driver.proclist_lock);
	list_for_each_entry(process, &kgsl_driver.process_list, list) {
		if (test_bit(KGSL_PROC_STATE, &process->state) ||
				!kgsl_process_private_get(process))
			continue;

		bg_proc++;
		list_add(&process->reclaim_list, &kgsl_reclaim_process_list);
	}
	read_unlock(&kgsl_driver.proclist_lock);

	list_for_each_entry(process, &kgsl_reclaim_process_list, reclaim_list) {
		if (!nr_pages)
			break;

		pp_nr_pages = nr_pages;
		do_div(pp_nr_pages, bg_proc--);
		nr_pages -= kgsl_reclaim_process(process, pp_nr_pages);
	}

	list_for_each_entry_safe(process, next,
			&kgsl_reclaim_process_list, reclaim_list) {
		list_del(&process->reclaim_list);
		kgsl_process_private_put(process);
	}
}

/* Shrinker callback functions */
static unsigned long
kgsl_reclaim_shrink_scan_objects(struct shrinker *shrinker,
		struct shrink_control *sc)
{
	if (!current_is_kswapd())
		return 0;

	atomic_set(&kgsl_nr_to_reclaim, kgsl_nr_to_scan ?
					kgsl_nr_to_scan : sc->nr_to_scan);
	kgsl_schedule_work(&reclaim_work);

	return atomic_read(&kgsl_nr_to_reclaim);
}

static unsigned long
kgsl_reclaim_shrink_count_objects(struct shrinker *shrinker,
		struct shrink_control *sc)
{
	struct kgsl_process_private *process;
	unsigned long count_reclaimable = 0;

	if (!current_is_kswapd())
		return 0;

	read_lock(&kgsl_driver.proclist_lock);
	list_for_each_entry(process, &kgsl_driver.process_list, list) {
		if (!test_bit(KGSL_PROC_STATE, &process->state))
			count_reclaimable += kgsl_reclaim_max_page_limit -
				atomic_read(&process->unpinned_page_count);
	}
	read_unlock(&kgsl_driver.proclist_lock);

	return count_reclaimable;
}

void kgsl_reclaim_proc_private_init(struct kgsl_process_private *process)
{
	mutex_init(&process->reclaim_lock);
	INIT_WORK(&process->fg_work, kgsl_reclaim_foreground_work);
	set_bit(KGSL_PROC_PINNED_STATE, &process->state);
	set_bit(KGSL_PROC_STATE, &process->state);
	atomic_set(&process->unpinned_page_count, 0);
}

#if (KERNEL_VERSION(6, 7, 0) <= LINUX_VERSION_CODE)
static int kgsl_reclaim_shrinker_init(void)
{
	kgsl_driver.reclaim_shrinker = shrinker_alloc(0, "kgsl_reclaim_shrinker");

	if (!kgsl_driver.reclaim_shrinker)
		return -ENOMEM;

	/* Initialize shrinker */
	kgsl_driver.reclaim_shrinker->count_objects = kgsl_reclaim_shrink_count_objects;
	kgsl_driver.reclaim_shrinker->scan_objects = kgsl_reclaim_shrink_scan_objects;
	kgsl_driver.reclaim_shrinker->seeks = DEFAULT_SEEKS;
	kgsl_driver.reclaim_shrinker->batch = 0;

	shrinker_register(kgsl_driver.reclaim_shrinker);
	return 0;
}

static void kgsl_reclaim_shrinker_close(void)
{
	if (kgsl_driver.reclaim_shrinker)
		shrinker_free(kgsl_driver.reclaim_shrinker);

	kgsl_driver.reclaim_shrinker = NULL;
}
#else
/* Shrinker callback data*/
static struct shrinker kgsl_reclaim_shrinker = {
	.count_objects = kgsl_reclaim_shrink_count_objects,
	.scan_objects = kgsl_reclaim_shrink_scan_objects,
	.seeks = DEFAULT_SEEKS,
	.batch = 0,
};

static int kgsl_reclaim_shrinker_init(void)
{
	int ret;

	kgsl_driver.reclaim_shrinker = &kgsl_reclaim_shrinker;

	/* Initialize shrinker */
#if (KERNEL_VERSION(6, 0, 0) <= LINUX_VERSION_CODE)
	ret = register_shrinker(kgsl_driver.reclaim_shrinker, "kgsl_reclaim_shrinker");
#else
	ret = register_shrinker(kgsl_driver.reclaim_shrinker);
#endif
	return ret;
}

static void kgsl_reclaim_shrinker_close(void)
{
	unregister_shrinker(kgsl_driver.reclaim_shrinker);
}
#endif

int kgsl_reclaim_start(void)
{
	return kgsl_reclaim_shrinker_init();
}

int kgsl_reclaim_init(void)
{
	int ret = kgsl_reclaim_start();

	if (ret) {
		pr_err("kgsl: reclaim: Failed to register shrinker\n");
		return ret;
	}

	INIT_WORK(&reclaim_work, kgsl_reclaim_background_work);

	return 0;
}

void kgsl_reclaim_close(void)
{
	kgsl_reclaim_shrinker_close();
	cancel_work_sync(&reclaim_work);
}
