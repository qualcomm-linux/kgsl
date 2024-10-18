/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2008-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#ifndef __KGSL_H
#define __KGSL_H

#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <uapi/linux/msm_kgsl.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "kgsl_gmu_core.h"
#include "kgsl_pwrscale.h"
#include "kgsl_sharedmem.h"

#define KGSL_L3_DEVICE "kgsl-l3"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
#include <soc/qcom/boot_stats.h>
#define KGSL_BOOT_MARKER(str)          place_marker("M - DRIVER " str)
#else
#define KGSL_BOOT_MARKER(str)          pr_info("boot_kpi: M - DRIVER " str)
#endif

/*
 * --- kgsl drawobj flags ---
 * These flags are same as --- drawobj flags ---
 * but renamed to reflect that cmdbatch is renamed to drawobj.
 */
#define KGSL_DRAWOBJ_MEMLIST           KGSL_CMDBATCH_MEMLIST
#define KGSL_DRAWOBJ_MARKER            KGSL_CMDBATCH_MARKER
#define KGSL_DRAWOBJ_SUBMIT_IB_LIST    KGSL_CMDBATCH_SUBMIT_IB_LIST
#define KGSL_DRAWOBJ_CTX_SWITCH        KGSL_CMDBATCH_CTX_SWITCH
#define KGSL_DRAWOBJ_PROFILING         KGSL_CMDBATCH_PROFILING
#define KGSL_DRAWOBJ_PROFILING_KTIME   KGSL_CMDBATCH_PROFILING_KTIME
#define KGSL_DRAWOBJ_END_OF_FRAME      KGSL_CMDBATCH_END_OF_FRAME
#define KGSL_DRAWOBJ_SYNC              KGSL_CMDBATCH_SYNC
#define KGSL_DRAWOBJ_PWR_CONSTRAINT    KGSL_CMDBATCH_PWR_CONSTRAINT
#define KGSL_DRAWOBJ_START_RECURRING   KGSL_CMDBATCH_START_RECURRING
#define KGSL_DRAWOBJ_STOP_RECURRING    KGSL_CMDBATCH_STOP_RECURRING


#define kgsl_drawobj_profiling_buffer kgsl_cmdbatch_profiling_buffer


/* The number of memstore arrays limits the number of contexts allowed.
 * If more contexts are needed, update multiple for MEMSTORE_SIZE
 */
#define KGSL_MEMSTORE_SIZE	((int)(PAGE_SIZE * 8))
#define KGSL_MEMSTORE_GLOBAL	(0)
#define KGSL_PRIORITY_MAX_RB_LEVELS 4
#define KGSL_LPAC_RB_ID		KGSL_PRIORITY_MAX_RB_LEVELS
/* Subtract one for LPAC */
#define KGSL_MEMSTORE_MAX	(KGSL_MEMSTORE_SIZE / \
	sizeof(struct kgsl_devmemstore) - 2 - KGSL_PRIORITY_MAX_RB_LEVELS)
#define KGSL_MAX_CONTEXTS_PER_PROC 200

#define MEMSTORE_RB_OFFSET(rb, field)	\
	KGSL_MEMSTORE_OFFSET(((rb)->id + KGSL_MEMSTORE_MAX), field)

#define MEMSTORE_ID_GPU_ADDR(dev, iter, field) \
	((dev)->memstore->gpuaddr + KGSL_MEMSTORE_OFFSET(iter, field))

#define MEMSTORE_RB_GPU_ADDR(dev, rb, field)	\
	((dev)->memstore->gpuaddr + \
	 KGSL_MEMSTORE_OFFSET(((rb)->id + KGSL_MEMSTORE_MAX), field))

#define KGSL_CONTEXT_PRIORITY_HIGH 0
/* Last context id is reserved for global context */
#define KGSL_GLOBAL_CTXT_ID (KGSL_MEMSTORE_MAX - 1)

/*
 * SCRATCH MEMORY: The scratch memory is one page worth of data that
 * is mapped into the GPU. This allows for some 'shared' data between
 * the GPU and CPU. For example, it will be used by the GPU to write
 * each updated RPTR for each RB.
 */

/* Shadow global helpers */
struct adreno_rb_shadow {
	/** @rptr: per ringbuffer address where GPU writes the rptr */
	u32 rptr;
	/** @bv_rptr: per ringbuffer address where GPU writes BV rptr */
	u32 bv_rptr;
	/** @bv_ts: per ringbuffer address where BV ringbuffer timestamp is written to */
	u32 bv_ts;
	/** @current_rb_ptname: The current pagetable active on the given RB */
	u32 current_rb_ptname;
	/** @ttbr0: value to program into TTBR0 during pagetable switch */
	u64 ttbr0;
	/** @contextidr: value to program into CONTEXTIDR during pagetable switch */
	u32 contextidr;
};

/**
 * struct gpu_work_period - App specific GPU work period stats
 */
struct gpu_work_period {
	struct kref refcount;
	struct list_head list;
	/** @uid: application unique identifier */
	uid_t uid;
	/** @active: Total amount of time the GPU spent running work */
	u64 active;
	/** @cmds: Total number of commands completed within work period */
	u32 cmds;
	/** @frames: Total number of frames completed within work period */
	atomic_t frames;
	/** @flags: Flags to accumulate GPU busy stats */
	unsigned long flags;
	/** @active_cmds: The number of active cmds from application */
	atomic_t active_cmds;
	/** @defer_ws: Work struct to clear gpu work period */
	struct work_struct defer_ws;
};

#define SCRATCH_RB_OFFSET(id, _field) ((id * sizeof(struct adreno_rb_shadow)) + \
	offsetof(struct adreno_rb_shadow, _field))
#define SCRATCH_RB_GPU_ADDR(dev, id, _field) \
	((dev)->scratch->gpuaddr + SCRATCH_RB_OFFSET(id, _field))

/* OFFSET to KMD postamble packets in scratch buffer */
#define SCRATCH_POSTAMBLE_OFFSET (100 * sizeof(u64))
#define SCRATCH_POSTAMBLE_ADDR(dev) \
	((dev)->scratch->gpuaddr + SCRATCH_POSTAMBLE_OFFSET)

/* Timestamp window used to detect rollovers (half of integer range) */
#define KGSL_TIMESTAMP_WINDOW 0x80000000

/*
 * A macro for memory statistics - add the new size to the stat and if
 * the statisic is greater then _max, set _max
 */
static inline void KGSL_STATS_ADD(uint64_t size, atomic_long_t *stat,
		atomic_long_t *max)
{
	uint64_t ret = atomic_long_add_return(size, stat);

	if (ret > atomic_long_read(max))
		atomic_long_set(max, ret);
}

#define KGSL_MAX_NUMIBS 2000
#define KGSL_MAX_SYNCPOINTS 32

struct kgsl_device;
struct kgsl_context;

/**
 * struct kgsl_driver - main container for global KGSL things
 * @cdev: Character device struct
 * @major: Major ID for the KGSL device
 * @class: Pointer to the class struct for the core KGSL sysfs entries
 * @virtdev: Virtual device for managing the core
 * @ptkobj: kobject for storing the pagetable statistics
 * @prockobj: kobject for storing the process statistics
 * @devp: Array of pointers to the individual KGSL device structs
 * @process_list: List of open processes
 * @pagetable_list: LIst of open pagetables
 * @ptlock: Lock for accessing the pagetable list
 * @process_mutex: Mutex for accessing the process list
 * @proclist_lock: Lock for accessing the process list
 * @devlock: Mutex protecting the device list
 * @stats: Struct containing atomic memory statistics
 * @full_cache_threshold: the threshold that triggers a full cache flush
 * @workqueue: Pointer to a single threaded workqueue
 */
struct kgsl_driver {
	struct cdev cdev;
	dev_t major;
	struct class *class;
	struct device virtdev;
	struct kobject *ptkobj;
	struct kobject *prockobj;
	struct kgsl_device *devp[1];
	struct list_head process_list;
	/** @wp_list: List of work period allocated per uid */
	struct list_head wp_list;
	/** @wp_list_lock: Lock for accessing the work period list */
	spinlock_t wp_list_lock;
	struct list_head pagetable_list;
	spinlock_t ptlock;
	struct mutex process_mutex;
	rwlock_t proclist_lock;
	struct mutex devlock;
	struct {
		atomic_long_t vmalloc;
		atomic_long_t vmalloc_max;
		atomic_long_t page_alloc;
		atomic_long_t page_alloc_max;
		atomic_long_t coherent;
		atomic_long_t coherent_max;
		atomic_long_t secure;
		atomic_long_t secure_max;
		atomic_long_t mapped;
		atomic_long_t mapped_max;
	} stats;
	unsigned int full_cache_threshold;
	struct workqueue_struct *workqueue;
	/* @lockless_workqueue: Pointer to a workqueue handler which doesn't hold device mutex */
	struct workqueue_struct *lockless_workqueue;
	/** @pool_shrinker: Pointer to a shrinker that resizes the kgsl page pools */
	struct shrinker *pool_shrinker;
	/** @reclaim_shrinker: Pointer to a shrinker that reclaims kgsl memory */
	struct shrinker *reclaim_shrinker;
};

extern struct kgsl_driver kgsl_driver;

struct kgsl_pagetable;

/*
 * List of different memory entry types. The usermem enum
 * starts at 0, which we use for allocated memory, so 1 is
 * added to the enum values.
 */
#define KGSL_MEM_ENTRY_KERNEL 0
#define KGSL_MEM_ENTRY_USER (KGSL_USER_MEM_TYPE_ADDR + 1)
#define KGSL_MEM_ENTRY_ION (KGSL_USER_MEM_TYPE_ION + 1)
#define KGSL_MEM_ENTRY_MAX (KGSL_USER_MEM_TYPE_MAX + 1)

/* For application specific GPU work period stats */
#define KGSL_WORK_PERIOD	0
/* GPU work period time in msec to emulate application work stats */
#define KGSL_WORK_PERIOD_MS	900

struct kgsl_device_private;
struct kgsl_event_group;

typedef void (*kgsl_event_func)(struct kgsl_device *, struct kgsl_event_group *,
		void *, int);

/**
 * struct kgsl_event - KGSL GPU timestamp event
 * @device: Pointer to the KGSL device that owns the event
 * @context: Pointer to the context that owns the event
 * @timestamp: Timestamp for the event to expire
 * @func: Callback function for the event when it expires
 * @priv: Private data passed to the callback function
 * @node: List node for the kgsl_event_group list
 * @created: Jiffies when the event was created
 * @work: kthread_work struct for dispatching the callback
 * @result: KGSL event result type to pass to the callback
 * group: The event group this event belongs to
 */
struct kgsl_event {
	struct kgsl_device *device;
	struct kgsl_context *context;
	unsigned int timestamp;
	kgsl_event_func func;
	void *priv;
	struct list_head node;
	unsigned int created;
	struct kthread_work work;
	int result;
	struct kgsl_event_group *group;
};

typedef int (*readtimestamp_func)(struct kgsl_device *, void *,
	enum kgsl_timestamp_type, unsigned int *);

/**
 * struct event_group - A list of GPU events
 * @context: Pointer to the active context for the events
 * @lock: Spinlock for protecting the list
 * @events: List of active GPU events
 * @group: Node for the master group list
 * @processed: Last processed timestamp
 * @name: String name for the group (for the debugfs file)
 * @readtimestamp: Function pointer to read a timestamp
 * @priv: Priv member to pass to the readtimestamp function
 */
struct kgsl_event_group {
	struct kgsl_context *context;
	spinlock_t lock;
	struct list_head events;
	struct list_head group;
	unsigned int processed;
	char name[64];
	readtimestamp_func readtimestamp;
	void *priv;
};

/**
 * struct submission_info - Container for submission statistics
 * @inflight: Number of commands that are inflight
 * @rb_id: id of the ringbuffer to which this submission is made
 * @rptr: Read pointer of the ringbuffer
 * @wptr: Write pointer of the ringbuffer
 * @gmu_dispatch_queue: GMU dispach queue to which this submission is made
 */
struct submission_info {
	int inflight;
	u32 rb_id;
	u32 rptr;
	u32 wptr;
	u32 gmu_dispatch_queue;
};

/**
 * struct retire_info - Container for retire statistics
 * @inflight: NUmber of commands that are inflight
 * @rb_id: id of the ringbuffer to which this submission is made
 * @rptr: Read pointer of the ringbuffer
 * @wptr: Write pointer of the ringbuffer
 * @gmu_dispatch_queue: GMU dispach queue to which this submission is made
 * @timestamp: Timestamp of submission that retired
 * @submitted_to_rb: AO ticks when GMU put this submission on ringbuffer
 * @sop: AO ticks when GPU started procssing this submission
 * @eop: AO ticks when GPU finished this submission
 * @retired_on_gmu: AO ticks when GMU retired this submission
 * @active: Number AO of ticks taken by GPU to complete the command
 */
struct retire_info {
	int inflight;
	int rb_id;
	u32 rptr;
	u32 wptr;
	u32 gmu_dispatch_queue;
	u32 timestamp;
	u64 submitted_to_rb;
	u64 sop;
	u64 eop;
	u64 retired_on_gmu;
	u64 active;
};

long kgsl_ioctl_device_getproperty(struct kgsl_device_private *dev_priv,
					  unsigned int cmd, void *data);
long kgsl_ioctl_device_setproperty(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_device_waittimestamp_ctxtid(struct kgsl_device_private
				*dev_priv, unsigned int cmd, void *data);
long kgsl_ioctl_rb_issueibcmds(struct kgsl_device_private *dev_priv,
				      unsigned int cmd, void *data);
long kgsl_ioctl_submit_commands(struct kgsl_device_private *dev_priv,
				unsigned int cmd, void *data);
long kgsl_ioctl_cmdstream_readtimestamp_ctxtid(struct kgsl_device_private
					*dev_priv, unsigned int cmd,
					void *data);
long kgsl_ioctl_cmdstream_freememontimestamp_ctxtid(
						struct kgsl_device_private
						*dev_priv, unsigned int cmd,
						void *data);
long kgsl_ioctl_drawctxt_create(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_drawctxt_destroy(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_sharedmem_free(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpumem_free_id(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_map_user_mem(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpumem_sync_cache(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpumem_sync_cache_bulk(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_sharedmem_flush_cache(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpumem_alloc(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpumem_alloc_id(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpumem_get_info(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_timestamp_event(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpuobj_alloc(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpuobj_free(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpuobj_info(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpuobj_import(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpuobj_sync(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data);
long kgsl_ioctl_gpu_command(struct kgsl_device_private *dev_priv,
				unsigned int cmd, void *data);
long kgsl_ioctl_gpuobj_set_info(struct kgsl_device_private *dev_priv,
				unsigned int cmd, void *data);
long kgsl_ioctl_gpumem_bind_ranges(struct kgsl_device_private *dev_priv,
				unsigned int cmd, void *data);
long kgsl_ioctl_gpu_aux_command(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data);
long kgsl_ioctl_timeline_create(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data);
long kgsl_ioctl_timeline_wait(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data);
long kgsl_ioctl_timeline_query(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data);
long kgsl_ioctl_timeline_fence_get(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data);
long kgsl_ioctl_timeline_signal(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data);
long kgsl_ioctl_timeline_destroy(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data);
long kgsl_ioctl_get_fault_report(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data);
long kgsl_ioctl_recurring_command(struct kgsl_device_private *dev_priv,
				unsigned int cmd, void *data);

void kgsl_mem_entry_destroy(struct kref *kref);
void kgsl_mem_entry_destroy_deferred(struct kref *kref);

void kgsl_get_egl_counts(struct kgsl_mem_entry *entry,
			int *egl_surface_count, int *egl_image_count);

unsigned long kgsl_get_dmabuf_inode_number(struct kgsl_mem_entry *entry);

struct kgsl_mem_entry * __must_check
kgsl_sharedmem_find(struct kgsl_process_private *private, uint64_t gpuaddr);

struct kgsl_mem_entry * __must_check
kgsl_sharedmem_find_id(struct kgsl_process_private *process, unsigned int id);

struct kgsl_mem_entry *gpumem_alloc_entry(struct kgsl_device_private *dev_priv,
				uint64_t size, uint64_t flags);
long gpumem_free_entry(struct kgsl_mem_entry *entry);

enum kgsl_mmutype kgsl_mmu_get_mmutype(struct kgsl_device *device);

/* Helper functions */
int kgsl_request_irq(struct platform_device *pdev, const  char *name,
		irq_handler_t handler, void *data);

int kgsl_request_irq_optional(struct platform_device *pdev, const  char *name,
		irq_handler_t handler, void *data);

int __init kgsl_core_init(void);
void kgsl_core_exit(void);

static inline int timestamp_cmp(unsigned int a, unsigned int b)
{
	/* check for equal */
	if (a == b)
		return 0;

	/* check for greater-than for non-rollover case */
	if ((a > b) && (a - b < KGSL_TIMESTAMP_WINDOW))
		return 1;

	/* check for greater-than for rollover case
	 * note that <= is required to ensure that consistent
	 * results are returned for values whose difference is
	 * equal to the window size
	 */
	a += KGSL_TIMESTAMP_WINDOW;
	b += KGSL_TIMESTAMP_WINDOW;
	return ((a > b) && (a - b <= KGSL_TIMESTAMP_WINDOW)) ? 1 : -1;
}

/**
 * kgsl_schedule_work() - Schedule a work item on the KGSL workqueue
 * @work: work item to schedule
 */
static inline void kgsl_schedule_work(struct work_struct *work)
{
	queue_work(kgsl_driver.workqueue, work);
}

static inline struct kgsl_mem_entry *
kgsl_mem_entry_get(struct kgsl_mem_entry *entry)
{
	if (!IS_ERR_OR_NULL(entry) && kref_get_unless_zero(&entry->refcount))
		return entry;

	return NULL;
}

static inline void
kgsl_mem_entry_put(struct kgsl_mem_entry *entry)
{
	if (!IS_ERR_OR_NULL(entry))
		kref_put(&entry->refcount, kgsl_mem_entry_destroy);
}

/*
 * kgsl_mem_entry_put_deferred() - Puts refcount and triggers deferred
 * mem_entry destroy when refcount is the last refcount.
 * @entry: memory entry to be put.
 *
 * Use this to put a memory entry when we don't want to block
 * the caller while destroying memory entry.
 */
static inline void kgsl_mem_entry_put_deferred(struct kgsl_mem_entry *entry)
{
	if (entry)
		kref_put(&entry->refcount, kgsl_mem_entry_destroy_deferred);
}

/*
 * kgsl_addr_range_overlap() - Checks if 2 ranges overlap
 * @gpuaddr1: Start of first address range
 * @size1: Size of first address range
 * @gpuaddr2: Start of second address range
 * @size2: Size of second address range
 *
 * Function returns true if the 2 given address ranges overlap
 * else false
 */
static inline bool kgsl_addr_range_overlap(uint64_t gpuaddr1,
		uint64_t size1, uint64_t gpuaddr2, uint64_t size2)
{
	if ((size1 > (U64_MAX - gpuaddr1)) || (size2 > (U64_MAX - gpuaddr2)))
		return false;
	return !(((gpuaddr1 + size1) <= gpuaddr2) ||
		(gpuaddr1 >= (gpuaddr2 + size2)));
}

/**
 * kgsl_work_period_update() - To update application work period stats
 * @device: Pointer to the KGSL device
 * @period: GPU work period stats
 * @active: Command active time
 */
void kgsl_work_period_update(struct kgsl_device *device,
			struct gpu_work_period *period, u64 active);

/**
 * kgsl_context_destroy_deferred() - Destroy context in a deferred manner
 * @kref: Pointer to context refcount
 */
void kgsl_context_destroy_deferred(struct kref *kref);
#endif /* __KGSL_H */
