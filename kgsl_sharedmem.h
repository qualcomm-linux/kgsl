/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2002,2007-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#ifndef __KGSL_SHAREDMEM_H
#define __KGSL_SHAREDMEM_H

#include <linux/bitfield.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

struct kgsl_device;
struct kgsl_process_private;

/* Internal definitions for memdesc->priv */
#define KGSL_MEMDESC_GUARD_PAGE BIT(0)
/* Set if the memdesc is mapped into all pagetables */
#define KGSL_MEMDESC_GLOBAL BIT(1)
/* The memdesc is frozen during a snapshot */
#define KGSL_MEMDESC_FROZEN BIT(2)
/* The memdesc is mapped into a pagetable */
#define KGSL_MEMDESC_MAPPED BIT(3)
/* The memdesc is secured for content protection */
#define KGSL_MEMDESC_SECURE BIT(4)
/* Memory is accessible in privileged mode */
#define KGSL_MEMDESC_PRIVILEGED BIT(6)
/* This is an instruction buffer */
#define KGSL_MEMDESC_UCODE BIT(7)
/* For global buffers, randomly assign an address from the region */
#define KGSL_MEMDESC_RANDOM BIT(8)
/* Allocate memory from the system instead of the pools */
#define KGSL_MEMDESC_SYSMEM BIT(9)
/* The memdesc pages can be reclaimed */
#define KGSL_MEMDESC_CAN_RECLAIM BIT(10)
/* The memdesc pages were reclaimed */
#define KGSL_MEMDESC_RECLAIMED BIT(11)
/* Skip reclaim of the memdesc pages */
#define KGSL_MEMDESC_SKIP_RECLAIM BIT(12)
/* The memdesc is hypassigned to HLOS*/
#define KGSL_MEMDESC_HYPASSIGNED_HLOS BIT(13)

struct kgsl_memdesc;

struct kgsl_memdesc_ops {
	u32 vmflags;
	vm_fault_t (*vmfault)(struct kgsl_memdesc *memdesc,
		struct vm_area_struct *vma, struct vm_fault *vmf);
	void (*free)(struct kgsl_memdesc *memdesc);
	int (*map_kernel)(struct kgsl_memdesc *memdesc);
	void (*unmap_kernel)(struct kgsl_memdesc *memdesc);
	/**
	 * @put_gpuaddr: Put away the GPU address and unmap the memory
	 * descriptor
	 */
	void (*put_gpuaddr)(struct kgsl_memdesc *memdesc);
};

/**
 * struct kgsl_memdesc - GPU memory object descriptor
 * @pagetable: Pointer to the pagetable that the object is mapped in
 * @hostptr: Kernel virtual address
 * @hostptr_count: Number of threads using hostptr
 * @gpuaddr: GPU virtual address
 * @physaddr: Physical address of the memory object
 * @size: Size of the memory object
 * @priv: Internal flags and settings
 * @sgt: Scatter gather table for allocated pages
 * @ops: Function hooks for the memdesc memory type
 * @flags: Flags set from userspace
 * @dev: Pointer to the struct device that owns this memory
 * @attrs: dma attributes for this memory
 * @pages: An array of pointers to allocated pages
 * @page_count: Total number of pages allocated
 */
struct kgsl_memdesc {
	struct kgsl_pagetable *pagetable;
	void *hostptr;
	u32 hostptr_count;
	u64 gpuaddr;
	phys_addr_t physaddr;
	u64 size;
	u32 priv;
	struct sg_table *sgt;
	const struct kgsl_memdesc_ops *ops;
	u64 flags;
	struct device *dev;
	unsigned long attrs;
	struct page **pages;
	u32 page_count;
	/*
	 * @lock: Spinlock to protect the gpuaddr from being accessed by
	 * multiple entities trying to map the same SVM region at once
	 */
	spinlock_t lock;
	/** @shmem_filp: Pointer to the shmem file backing this memdesc */
	struct file *shmem_filp;
	/** @ranges: rbtree base for the interval list of vbo ranges */
	struct rb_root_cached ranges;
	/** @ranges_lock: Mutex to protect the range database */
	struct mutex ranges_lock;
	/** @gmuaddr: GMU VA if this is mapped in GMU */
	u32 gmuaddr;
	/*@kgsl_dev: kgsl device dev instance */
	struct device *kgsl_dev;
	/*@shmem_page_list: shmem pages list */
	struct list_head shmem_page_list;
};

/*
 * struct kgsl_mem_entry - a userspace memory allocation
 * @refcount: reference count. Currently userspace can only
 *  hold a single reference count, but the kernel may hold more.
 * @memdesc: description of the memory
 * @priv_data: type-specific data, such as the dma-buf attachment pointer.
 * @node: rb_node for the gpu address lookup rb tree
 * @id: idr index for this entry, can be used to find memory that does not have
 *  a valid GPU address.
 * @priv: back pointer to the process that owns this memory
 * @pending_free: if !0, userspace requested that his memory be freed, but there
 *  are still references to it.
 * @dev_priv: back pointer to the device file that created this entry.
 * @metadata: String containing user specified metadata for the entry
 * @work: Work struct used to schedule kgsl_mem_entry_destroy()
 */
struct kgsl_mem_entry {
	struct kref refcount;
	struct kgsl_memdesc memdesc;
	void *priv_data;
	struct rb_node node;
	u32 id;
	struct kgsl_process_private *priv;
	int pending_free;
	char metadata[KGSL_GPUOBJ_ALLOC_METADATA_MAX + 1];
	struct work_struct work;
	/**
	 * @map_count: Count how many vmas this object is mapped in - used for
	 * debugfs accounting
	 */
	atomic_t map_count;
	/** @vbo_count: Count how many VBO ranges this entry is mapped in */
	atomic_t vbo_count;
};

/**
 * struct kgsl_global_memdesc  - wrapper for global memory objects
 */
struct kgsl_global_memdesc {
	/** @memdesc: Container for the GPU memory descriptor for the object */
	struct kgsl_memdesc memdesc;
	/** @name: Name of the object for the debugfs list */
	const char *name;
	/** @node: List node for the list of global objects */
	struct list_head node;
};

extern bool kgsl_sharedmem_noretry_flag;

#define KGSL_CACHE_OP_INV       0x01
#define KGSL_CACHE_OP_FLUSH     0x02
#define KGSL_CACHE_OP_CLEAN     0x03

void kgsl_sharedmem_free(struct kgsl_memdesc *memdesc);

int kgsl_sharedmem_readl(const struct kgsl_memdesc *memdesc,
			uint32_t *dst,
			uint64_t offsetbytes);

/**
 * kgsl_sharedmem_writel - write a 32 bit value to a shared memory object
 * @memdesc: Pointer to a GPU memory object
 * @offsetbytes: Offset inside of @memdesc to write to
 * @src: Value to write
 *
 * Write @src to @offsetbytes from the start of @memdesc
 */
void kgsl_sharedmem_writel(const struct kgsl_memdesc *memdesc,
			uint64_t offsetbytes,
			uint32_t src);

int kgsl_sharedmem_readq(const struct kgsl_memdesc *memdesc,
			uint64_t *dst,
			uint64_t offsetbytes);

/**
 * kgsl_sharedmem_writeq - write a 64 bit value to a shared memory object
 * @memdesc: Pointer to a GPU memory object
 * @offsetbytes: Offset inside of @memdesc to write to
 * @src: Value to write
 *
 * Write @src to @offsetbytes from the start of @memdesc
 */
void kgsl_sharedmem_writeq(const struct kgsl_memdesc *memdesc,
			uint64_t offsetbytes,
			uint64_t src);

int kgsl_cache_range_op(struct kgsl_memdesc *memdesc,
			uint64_t offset, uint64_t size,
			unsigned int op);

void kgsl_memdesc_init(struct kgsl_device *device,
			struct kgsl_memdesc *memdesc, uint64_t flags);

void kgsl_process_init_sysfs(struct kgsl_device *device,
		struct kgsl_process_private *private);

int kgsl_sharedmem_init_sysfs(void);

void kgsl_get_memory_usage(char *str, size_t len, uint64_t memflags);

void kgsl_free_secure_page(struct page *page);

struct page *kgsl_alloc_secure_page(void);

#if IS_ENABLED(CONFIG_QCOM_SECURE_BUFFER)
int kgsl_lock_sgt(struct sg_table *sgt, u64 size);

int kgsl_unlock_sgt(struct sg_table *sgt);
#endif

/**
 * kgsl_zero_page() - zero out a page
 * @p: pointer to the struct page
 * @order: order of the page
 * @dev: A &struct device pointer
 *
 * Map a page into kernel and zero it out
 */
void kgsl_zero_page(struct page *p, unsigned int order,
		struct device *dev);

/**
 * kgsl_gfp_mask() - get gfp_mask to be used
 * @page_order: order of the page
 *
 * Get the gfp_mask to be used for page allocation
 * based on the order of the page
 *
 * Return appropriate gfp_mask
 */
gfp_t kgsl_gfp_mask(int page_order);

/**
 * kgsl_allocate_user - Allocate user visible GPU memory
 * @device: A GPU device handle
 * @memdesc: Memory descriptor for the object
 * @size: Size of the allocation in bytes
 * @flags: Control flags for the allocation
 * @priv: Internal flags for the allocation
 *
 * Allocate GPU memory on behalf of the user.
 * Return: 0 on success or negative on failure.
 */
int kgsl_allocate_user(struct kgsl_device *device, struct kgsl_memdesc *memdesc,
		u64 size, u64 flags, u32 priv);

/**
 * kgsl_allocate_kernel - Allocate kernel visible GPU memory
 * @device: A GPU device handle
 * @memdesc: Memory descriptor for the object
 * @size: Size of the allocation in bytes
 * @flags: Control flags for the allocation
 * @priv: Internal flags for the allocation
 *
 * Allocate GPU memory on for use by the kernel. Kernel objects are
 * automatically mapped into the kernel address space (except for secure).
 * Return: 0 on success or negative on failure.
 */
int kgsl_allocate_kernel(struct kgsl_device *device,
		struct kgsl_memdesc *memdesc, u64 size, u64 flags, u32 priv);

/**
 * kgsl_allocate_global - Allocate a global GPU memory object
 * @device: A GPU device handle
 * @size: Size of the allocation in bytes
 * @padding: Amount of extra adding to add to the VA allocation
 * @flags: Control flags for the allocation
 * @priv: Internal flags for the allocation
 * @name: Name of the allocation (for the debugfs file)
 *
 * Allocate a global GPU object for use by all processes. The buffer is
 * automatically mapped into the kernel address space and added to the list of
 * global buffers that get mapped into each newly created pagetable.
 * Return: The memory descriptor on success or a ERR_PTR encoded error on
 * failure.
 */
struct kgsl_memdesc *kgsl_allocate_global(struct kgsl_device *device,
		u64 size, u32 padding, u64 flags, u32 priv, const char *name);

/**
 * kgsl_allocate_global_fixed - Allocate a global GPU memory object from a fixed
 * region defined in the device tree
 * @device: A GPU device handle
 * @size: Size of the allocation in bytes
 * @flags: Control flags for the allocation
 * @priv: Internal flags for the allocation
 *
 * Allocate a global GPU object for use by all processes. The buffer is
 * added to the list of global buffers that get mapped into each newly created
 * pagetable.
 *
 * Return: The memory descriptor on success or a ERR_PTR encoded error on
 * failure.
 */
struct kgsl_memdesc *kgsl_allocate_global_fixed(struct kgsl_device *device,
		const char *resource, const char *name);
/**
 * kgsl_memdesc_init_fixed - Intializes a memory object from a fixed
 * region defined in the device tree
 * @device: A GPU device handle
 * @pdev: Pointer to the platform device
 * @resource: Name of the resource to get the size and address to allocate
 * @memdesc: Memory descriptor for the object
 *
 * Intializes a memory object for a fixed I/O region defined in device tree.
 *
 * Return: 0 on success or negative on failure.
 */
int kgsl_memdesc_init_fixed(struct kgsl_device *device,
	struct platform_device *pdev, const char *resource,
	struct kgsl_memdesc *memdesc);

/**
 * kgsl_free_globals - Free all global objects
 * @device: A GPU device handle
 *
 * Free all the global buffer objects. Should only be called during shutdown
 * after the pagetables have been freed
 */
void kgsl_free_globals(struct kgsl_device *device);

/**
 * kgsl_page_sync_for_device - Initialize SG table with page & sync to/from device
 * @dev: A GPU device handle
 * @page: Pointer to the struct page
 * @size: Size of the page
 * @dir: DMA direction flag
 */
void kgsl_page_sync(struct device *dev, struct page *page,
		size_t size, enum dma_data_direction dir);

/*
 * kgsl_memdesc_get_align - Get alignment flags from a memdesc
 * @memdesc - the memdesc
 *
 * Returns the alignment requested, as power of 2 exponent.
 */
static inline int
kgsl_memdesc_get_align(const struct kgsl_memdesc *memdesc)
{
	return FIELD_GET(KGSL_MEMALIGN_MASK, memdesc->flags);
}

/*
 * kgsl_memdesc_get_cachemode - Get cache mode of a memdesc
 * @memdesc: the memdesc
 *
 * Returns a KGSL_CACHEMODE* value.
 */
static inline int
kgsl_memdesc_get_cachemode(const struct kgsl_memdesc *memdesc)
{
	return FIELD_GET(KGSL_CACHEMODE_MASK, memdesc->flags);
}

static inline unsigned int
kgsl_memdesc_get_memtype(const struct kgsl_memdesc *memdesc)
{
	return FIELD_GET(KGSL_MEMTYPE_MASK, memdesc->flags);
}
/*
 * kgsl_memdesc_set_align - Set alignment flags of a memdesc
 * @memdesc - the memdesc
 * @align - alignment requested, as a power of 2 exponent.
 */
static inline int
kgsl_memdesc_set_align(struct kgsl_memdesc *memdesc, unsigned int align)
{
	if (align > 32)
		align = 32;

	memdesc->flags &= ~(uint64_t)KGSL_MEMALIGN_MASK;
	memdesc->flags |= FIELD_PREP(KGSL_MEMALIGN_MASK, align);
	return 0;
}

/**
 * kgsl_memdesc_usermem_type - return buffer type
 * @memdesc - the memdesc
 *
 * Returns a KGSL_MEM_ENTRY_* value for this buffer, which
 * identifies if was allocated by us, or imported from
 * another allocator.
 */
static inline unsigned int
kgsl_memdesc_usermem_type(const struct kgsl_memdesc *memdesc)
{
	return FIELD_GET(KGSL_MEMFLAGS_USERMEM_MASK, memdesc->flags);
}

/**
 * kgsl_memdesc_sg_dma - Turn a dma_addr (from CMA) into a sg table
 * @memdesc: Pointer to a memory descriptor
 * @addr: Physical address from the dma_alloc function
 * @size: Size of the chunk
 *
 * Create a sg table for the contiguous chunk specified by addr and size.
 *
 * Return: 0 on success or negative on failure.
 */
int kgsl_memdesc_sg_dma(struct kgsl_memdesc *memdesc,
		phys_addr_t addr, u64 size);

/*
 * kgsl_memdesc_is_global - is this a globally mapped buffer?
 * @memdesc: the memdesc
 *
 * Return: True if this is a global mapping
 */
static inline bool kgsl_memdesc_is_global(const struct kgsl_memdesc *memdesc)
{
	return memdesc && (memdesc->priv & KGSL_MEMDESC_GLOBAL);
}

/*
 * kgsl_memdesc_is_secured - is this a secure buffer?
 * @memdesc: the memdesc
 *
 * Returns true if this is a secure mapping, false otherwise
 */
static inline bool kgsl_memdesc_is_secured(const struct kgsl_memdesc *memdesc)
{
	return memdesc && (memdesc->priv & KGSL_MEMDESC_SECURE);
}

/*
 * kgsl_memdesc_is_reclaimed - check if a buffer is reclaimed
 * @memdesc: the memdesc
 *
 * Return: true if the memdesc pages were reclaimed, false otherwise
 */
static inline bool kgsl_memdesc_is_reclaimed(const struct kgsl_memdesc *memdesc)
{
	return memdesc && (memdesc->priv & KGSL_MEMDESC_RECLAIMED);
}

/*
 * kgsl_memdesc_use_cpu_map - use the same virtual mapping on CPU and GPU?
 * @memdesc: the memdesc
 *
 * Return: true if the memdesc is using SVM mapping
 */
static inline bool
kgsl_memdesc_use_cpu_map(const struct kgsl_memdesc *memdesc)
{
	return memdesc && (memdesc->flags & KGSL_MEMFLAGS_USE_CPU_MAP);
}

/*
 * kgsl_memdesc_footprint - get the size of the mmap region
 * @memdesc - the memdesc
 *
 * The entire memdesc must be mapped. Additionally if the
 * CPU mapping is going to be mirrored, there must be room
 * for the guard page to be mapped so that the address spaces
 * match up.
 */
static inline uint64_t
kgsl_memdesc_footprint(const struct kgsl_memdesc *memdesc)
{
	if (!(memdesc->priv & KGSL_MEMDESC_GUARD_PAGE))
		return memdesc->size;

	return PAGE_ALIGN(memdesc->size + PAGE_SIZE);
}

/**
 * kgsl_memdesc_put_gpuaddr - Release the gpuaddr assigned to a memdesc
 * @memdesc: Pointer to a GPU memory object
 *
 * Call the memdesc specific function to release the GPU address assigned to the
 * memdesc and unmap the memory
 */
static inline void kgsl_sharedmem_put_gpuaddr(struct kgsl_memdesc *memdesc)
{
	if (memdesc && memdesc->ops->put_gpuaddr)
		memdesc->ops->put_gpuaddr(memdesc);
}

/**
 * kgsl_cachemode_is_cached - Return true if the passed flags indicate a cached
 * buffer
 * @flags: A bitmask of KGSL_MEMDESC_ flags
 *
 * Return: true if the flags indicate a cached buffer
 */
static inline bool kgsl_cachemode_is_cached(u64 flags)
{
	u64 mode = FIELD_GET(KGSL_CACHEMODE_MASK, flags);

	return (mode != KGSL_CACHEMODE_UNCACHED &&
		mode != KGSL_CACHEMODE_WRITECOMBINE);
}

static inline bool kgsl_gpuaddr_in_memdesc(const struct kgsl_memdesc *memdesc,
				u64 gpuaddr, u64 size)
{
	if (IS_ERR_OR_NULL(memdesc))
		return false;

	/* set a minimum size to search for */
	if (!size)
		size = 1;

	/* don't overflow */
	if (size > U64_MAX - gpuaddr)
		return false;

	return (gpuaddr >= memdesc->gpuaddr &&
	    ((gpuaddr + size) <= (memdesc->gpuaddr + memdesc->size)));
}

static inline void *kgsl_memdesc_map(struct kgsl_memdesc *memdesc)
{
	if (memdesc->ops && memdesc->ops->map_kernel)
		memdesc->ops->map_kernel(memdesc);

	return memdesc->hostptr;
}

static inline void kgsl_memdesc_unmap(struct kgsl_memdesc *memdesc)
{
	if (memdesc->ops && memdesc->ops->unmap_kernel)
		memdesc->ops->unmap_kernel(memdesc);
}

static inline void *kgsl_gpuaddr_to_vaddr(struct kgsl_memdesc *memdesc, u64 gpuaddr)
{
	void *hostptr = NULL;

	if ((gpuaddr >= memdesc->gpuaddr) &&
		(gpuaddr < (memdesc->gpuaddr + memdesc->size)))
		hostptr = kgsl_memdesc_map(memdesc);

	return hostptr != NULL ? hostptr + (gpuaddr - memdesc->gpuaddr) : NULL;
}

/**
 * kgsl_unmap_and_put_gpuaddr - Unmap the memory and release the gpuaddr
 * assigned to a memdesc
 * @memdesc: Pointer to a GPU memory object
 *
 * Remove the mapping from pagetable and release the GPU address assigned
 * to the memdesc
 */
void kgsl_unmap_and_put_gpuaddr(struct kgsl_memdesc *memdesc);

/**
 * struct kgsl_process_attribute - basic attribute for a process
 * @attr: Underlying struct attribute
 * @show: Attribute show function
 * @store: Attribute store function
 */
struct kgsl_process_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj,
			struct kgsl_process_attribute *attr, char *buf);
	ssize_t (*store)(struct kobject *kobj,
		struct kgsl_process_attribute *attr, const char *buf,
		ssize_t count);
};

#define PROCESS_ATTR(_name, _mode, _show, _store) \
	static struct kgsl_process_attribute attr_##_name = \
			__ATTR(_name, _mode, _show, _store)

struct kgsl_sharedmem_bind_op_range {
	u64 start;
	u64 last;
	u32 child_offset;
	u32 op;
	struct kgsl_mem_entry *entry;
};

struct kgsl_sharedmem_bind_op {
	struct kgsl_mem_entry *target;
	struct kgsl_sharedmem_bind_op_range *ops;
	int nr_ops;
	void (*callback)(struct kgsl_sharedmem_bind_op *op);
	void *data;
	struct work_struct work;
	struct completion comp;
	struct kref ref;
};

/**
 * kgsl_sharedmem_allocate_vbo - Allocate a new virtual buffer object
 * @device: A KGSL GPU handle
 * @memdesc: Memory descriptor container to initialize
 * @size:  Size of the VBO
 * @flags: Bitmask of KGSL_MEMFLAGS_*
 *
 * Initialize a new virtual buffer object memory descriptor
 *
 * Return: 0 on success or negative on failure.
 */
int kgsl_sharedmem_allocate_vbo(struct kgsl_device *device,
		struct kgsl_memdesc *memdesc, u64 size, u64 flags);

/**
 * kgsl_memdesc_print_vbo_ranges - Print a new virtual buffer object
 * @entry: A KGSL memory entry
 * @s:	seq_file pointer
 *
 * Print virtual buffer object memory ranges
 */
void kgsl_memdesc_print_vbo_ranges(struct kgsl_mem_entry *entry,
		struct seq_file *s);

/**
 * kgsl_sharedmem_create_bind_op - Create a new bind op
 * @private: A KGSL process private
 * @target_id:	Target virtual buffer object id
 * @ranges: User memory pointer to an array of range operations of type &struct
 * kgsl_gpumem_bind_range
 * @ranges_nents: Number of entries in @ranges
 * @ranges_size: Size of each entry in @ranges in bytes
 *
 * Create a new bind op to be used to map ranges
 *
 * Return: On success return kgsl_sharedmem_bind_op pointer or negative
 * on failure
 *
 */
struct kgsl_sharedmem_bind_op *
kgsl_sharedmem_create_bind_op(struct kgsl_process_private *private,
		u32 target_id, void __user *ranges, u32 ranges_nents,
		u64 ranges_size);

/**
 * kgsl_sharedmem_bind_ranges - Bind ranges to virtual buffer object
 * @op: One of KGSL_GPUMEM_RANGE_OP_BIND or KGSL_GPUMEM_RANGE_OP_UNBIND
 *
 * Add or remove a range from kgsl memory descriptor
 */
void kgsl_sharedmem_bind_ranges(struct kgsl_sharedmem_bind_op *op);

/**
 * kgsl_sharedmem_bind_range_destroy - Bind ranges to virtual buffer object
 * @kref: kref to bind kgsl_sharedmem_bind_op
 *
 * Destroy bind ranges object
 */
void kgsl_sharedmem_bind_range_destroy(struct kref *kref);

/**
 * kgsl_sharedmem_put_bind_op - Bind ranges to virtual buffer object
 * @op: One of KGSL_GPUMEM_RANGE_OP_BIND or KGSL_GPUMEM_RANGE_OP_UNBIND
 *
 * Put kgsl_sharedmem_bind_range_destroy to free resources
 */
static inline void kgsl_sharedmem_put_bind_op(struct kgsl_sharedmem_bind_op *op)
{
	if (!IS_ERR_OR_NULL(op))
		kref_put(&op->ref, kgsl_sharedmem_bind_range_destroy);
}

/**
 * kgsl_register_shmem_callback - Register vendor hook callback with SHMEM
 * driver
 */
void kgsl_register_shmem_callback(void);
#endif /* __KGSL_SHAREDMEM_H */
