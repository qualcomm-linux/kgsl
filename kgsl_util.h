/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _KGSL_UTIL_H_
#define _KGSL_UTIL_H_

#include <linux/version.h>

#define KGSL_DRIVER "kgsl_driver"
#define KGSL_ADRENO_DEVICE "kgsl_adreno_device"
#define KGSL_A6XX_DEVICE "kgsl_a6xx_device"
#define KGSL_GEN7_DEVICE "kgsl_gen7_device"
#define KGSL_HWSCHED_DEVICE "kgsl_hwsched_device"
#define KGSL_GEN8_DEVICE "kgsl_gen8_device"

#define KGSL_SCRATCH_ENTRY "scratch"
#define KGSL_MEMSTORE_ENTRY "memstore"
#define KGSL_GMU_LOG_ENTRY "kgsl_gmu_log"
#define KGSL_GMU_TRACE_ENTRY "kgsl_gmu_trace"
#define KGSL_HFIMEM_ENTRY "kgsl_hfi_mem"
#define KGSL_GMU_DUMPMEM_ENTRY "kgsl_gmu_dump_mem"
#define KGSL_GMU_RB_ENTRY "gmu_rb"
#define KGSL_GMU_KERNEL_PROF_ENTRY "gmu_kernel_profiling"
#define KGSL_GMU_USER_PROF_ENTRY "gmu_user_profiling"
#define KGSL_GMU_CMD_BUFFER_ENTRY "gmu_cmd_buffer"
#define KGSL_HFI_BIG_IB_ENTRY "kgsl_hfi_big_ib"
#define KGSL_HFI_BIG_IB_REC_ENTRY "kgsl_hfi_big_ib_rec"
#define KGSL_ADRENO_CTX_ENTRY "kgsl_adreno_ctx"
#define KGSL_PROC_PRIV_ENTRY "kgsl_proc_priv"
#define KGSL_PGTABLE_ENTRY "kgsl_pgtable"
#define KGSL_GMU_VRB_ENTRY "kgsl_gmu_vrb"
#define KGSL_SYNC_FENCE_ENTRY "kgsl_sync_fence"
#define KGSL_SYNC_TIMELINE_ENTRY "kgsl_sync_timeline"
#define KGSL_PAGE_POOL_ENTRY "kgsl_page_pool"
#define KGSL_ADRENO_TZ_DATA_ENTRY "kgsl_adreno_tz_data"
#define KGSL_NC_OVERRIDES_ENTRY "kgsl_nc_overrides"

#define MAX_VA_MINIDUMP_STR_LEN 48


/**
 * Request TZ to program set of access controlled registers that KGSL needs
 * irrespective of any features
 */
#define GPU_ALWAYS_EN_REQ BIT(0)
/**
 * Request TZ to program BCL id to access controlled register when BCL is
 * enabled
 */
#define GPU_BCL_EN_REQ BIT(1)
/**
 * Request TZ to program set of access controlled register for CLX feature
 * when enabled
 */
#define GPU_CLX_EN_REQ BIT(2)
/**
 * Request TZ to program tsense ids to access controlled registers for reading
 * gpu temperature sensors
 */
#define GPU_TSENSE_EN_REQ BIT(3)
/**
 * Request TZ to program tsense measurement to a large period
 */
#define GPU_TSENSE_MEASURE_DEFAULT_DISABLE BIT(4)

struct regulator;
struct clk_bulk_data;

/**
 * struct cpu_gpu_lock - CP spinlock structure for power up list
 * @gpu_req: flag value set by CP
 * @cpu_req: flag value set by KMD
 * @turn: turn variable set by both CP and KMD
 * @list_length: this tells CP the last dword in the list:
 * 16 + (4 * (List_Length - 1))
 * @list_offset: this tells CP the start of preemption only list:
 * 16 + (4 * List_Offset)
 * @ifpc_list_len: number of static ifpc duplets in the list
 * @preemption_list_len: number of static preemption duplets in the list
 * @dynamic_list_len: number of dynamically added triplets in the list
 */
struct cpu_gpu_lock {
	u32 gpu_req;
	u32 cpu_req;
	u32 turn;
	union {
		struct {
			u16 list_length;
			u16 list_offset;
		};
		struct {
			u8 ifpc_list_len;
			u8 preemption_list_len;
			u16 dynamic_list_len;
		};
	};
};

/**
 * kgsl_hwlock - Try to get the spinlock
 * @lock: cpu_gpu_lock structure
 *
 * Spin while the GPU has the lock.
 *
 * Return: 0 if lock is successful, -EBUSY if timed out waiting for lock
 */
int kgsl_hwlock(struct cpu_gpu_lock *lock);

/**
 * kgsl_hwunlock - Release a previously grabbed lock
 * @lock: cpu_gpu_lock structure
 */
void kgsl_hwunlock(struct cpu_gpu_lock *lock);

/**
 * kgsl_genpd_is_enabled - Check whether genpd is enabled or not
 * @dev: Power domain handle
 *
 * Return: True if genpd is enabled otherwise false.
 */
bool kgsl_genpd_is_enabled(struct device *dev);

/**
 * kgsl_of_clk_by_name - Return a clock device for a given name
 * @clks: Pointer to an array of bulk clk data
 * @count: Number of entries in the array
 * @id: Name of the clock to search for
 *
 * Returns: A pointer to the clock device for the given name or NULL if not
 * found
 */
struct clk *kgsl_of_clk_by_name(struct clk_bulk_data *clks, int count,
		const char *id);
/**
 * kgsl_regulator_set_voltage - Set voltage level for regulator
 * @dev: A &struct device pointer
 * @reg: A &struct regulator handle
 * @voltage: Voltage value to set regulator
 *
 * Return: 0 on success and negative error on failure.
 */
int kgsl_regulator_set_voltage(struct device *dev,
		struct regulator *reg, u32 voltage);

/**
 * kgsl_clk_set_rate - Set a clock to a given rate
 * @clks: Pointer to an array of bulk clk data
 * @count: Number of entries in the array
 * @id: Name of the clock to search for
 * @rate: Rate to st the clock to
 *
 * Return: 0 on success or negative error on failure
 */
int kgsl_clk_set_rate(struct clk_bulk_data *clks, int num_clks,
		const char *id, unsigned long rate);


/**
 * kgsl_is_compatible_node_available() - Check if a device with matching
 *					compatible is available
 * @compat: The compatible string that the device must have
 *
 * Find a device with the compatible string that is passed and check if
 * the device is available.
 *
 * Return: true if a suitable device is available, false otherwise
 */
bool kgsl_is_compatible_node_available(const char *compat);

/**
 * kgsl_attach_iommu_group() - Get iommu group and attach domain
 *
 * @dev: iommu group of this device is used
 * @domain: iommu domain to attach
 * @group: This is updated with iommu group on successful attach
 *
 * Get the iommu group of a device and attach iommu domain to the group.
 *
 * Return: 0 on success, negative error on failure
 */
int kgsl_attach_iommu_group(struct device *dev, struct iommu_domain *domain,
		struct iommu_group **group);

/**
 * kgsl_detach_iommu_group() - Detach iommu domain from group
 *
 * @domain: iommu domain to detach
 * @group: iommu group to be used for detach
 *
 * Detach iommu domain from iommu group
 */
void kgsl_detach_iommu_group(struct iommu_domain *domain, struct iommu_group *group);

/**
 * kgsl_scm_gpu_init_regs - Load secure registers through tz
 * @dev: Pointer to the GPU platform device
 * @gpu_req: Bit mask of requests to enable
 *
 * Return: 0 on success or negative on failure and EOPNOTSUPP if scm call
 * not supported
 */
int kgsl_scm_gpu_init_regs(struct device *dev, u32 gpu_req);

#if IS_ENABLED(CONFIG_QCOM_VA_MINIDUMP)
/**
 * kgsl_add_to_minidump - Add a physically contiguous section to minidump
 * @name: Name of the section
 * @virt_addr: Virtual address of the section
 * @phy_addr: Physical address of the section
 * @size: Size of the section
 */
void kgsl_add_to_minidump(char *name, u64 virt_addr, u64 phy_addr, size_t size);

/**
 * kgsl_remove_from_minidump - Remove a contiguous section from minidump
 * @name: Name of the section
 * @virt_addr: Virtual address of the section
 * @phy_addr: Physical address of the section
 * @size: Size of the section
 */
void kgsl_remove_from_minidump(char *name, u64 virt_addr, u64 phy_addr, size_t size);

/**
 * kgsl_add_va_to_minidump - Add a physically non-contiguous section to minidump
 * @dev: Pointer to the struct device for the GPU platform device
 * @name: Name of the section
 * @ptr: Virtual address of the section
 * @size: Size of the section
 */
int kgsl_add_va_to_minidump(struct device *dev, const char *name, void *ptr,
		size_t size);

/**
 * kgsl_qcom_va_md_register - Register driver with va-minidump
 * @device: Pointer to kgsl device
 */
void kgsl_qcom_va_md_register(struct kgsl_device *device);

/**
 * kgsl_qcom_va_md_unregister - Unregister driver with va-minidump
 * @device: Pointer to kgsl device
 */
void kgsl_qcom_va_md_unregister(struct kgsl_device *device);
#else
static inline void kgsl_add_to_minidump(char *name, u64 virt_addr, u64 phy_addr, size_t size)
{
}

static inline void kgsl_remove_from_minidump(char *name, u64 virt_addr, u64 phy_addr, size_t size)
{
}

static inline int kgsl_add_va_to_minidump(struct device *dev, const char *name, void *ptr,
		size_t size)
{
	return 0;
}

static inline void kgsl_qcom_va_md_register(struct kgsl_device *device)
{
}

static inline void kgsl_qcom_va_md_unregister(struct kgsl_device *device)
{
}
#endif

#ifdef CONFIG_QCOM_KGSL_UPSTREAM
static inline int qcom_scm_pas_shutdown_retry(u32 peripheral)
{
	return -EINVAL;
}

static inline int qcom_scm_kgsl_set_smmu_lpac_aperture(
                               unsigned int num_context_bank)
{
       return -EINVAL;
}

/**
 * kgsl_get_ddrtype - Type of ddr on the current device
 *
 * Return: ddr type on success or negative error on failure.
 */
int kgsl_get_ddrtype(void);

static inline void qcom_clk_dump(struct clk *clk, struct regulator *regulator,
		bool calltrace)
{
}

#endif

/**
 * isdb_write - Program isdb registers to issue break commands to SP
 * @base: Base address of qdss registers to be programmed
 * @offset: offset to the SP block
 */
void isdb_write(void __iomem *base, u32 offset);

/**
 * cmp_u32 - Comparator function for sorting u32 values
 * @first: Pointer to the first element
 * @second: Pointer to the second element
 *
 * It is intended for use with the kernel's sort() function to sort
 * arrays of u32 in ascending order.
 */
int cmp_u32(const void *first, const void *second);

#if KERNEL_VERSION(6, 15, 0) <= LINUX_VERSION_CODE
#define kgsl_delete_timer(timer) timer_delete(timer)
#define kgsl_delete_timer_sync(timer) timer_delete_sync(timer)
#else
#define kgsl_delete_timer(timer) del_timer(timer)
#define kgsl_delete_timer_sync(timer) del_timer_sync(timer)
#endif

#if (KERNEL_VERSION(6, 16, 0) <= LINUX_VERSION_CODE)
#define kgsl_timer_container_of timer_container_of
#else
#define kgsl_timer_container_of from_timer
#endif

#if (KERNEL_VERSION(6, 18, 0) <= LINUX_VERSION_CODE)
/**
 * When using kgsl_nth_page, user has to make sure the pages are contiguous.
 * It can be checked with help of page_range_contiguous().
 */
#define kgsl_nth_page(page, n) ((page) + (n))
#else
#define kgsl_nth_page(page, n) nth_page((page), (n))
#endif

#endif
