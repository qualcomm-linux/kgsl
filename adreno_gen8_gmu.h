/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __ADRENO_GEN8_GMU_H
#define __ADRENO_GEN8_GMU_H

#include <linux/soc/qcom/qcom_aoss.h>

#include "adreno_gen8_hfi.h"
#include "kgsl_gmu_core.h"

struct gen8_dcvs_table {
	u32 gpu_level_num;
	u32 gmu_level_num;
	struct opp_gx_desc gx_votes[MAX_GX_LEVELS];
	struct opp_desc cx_votes[MAX_CX_LEVELS];
};

/**
 * struct gen8_gmu_device - GMU device structure
 * @ver: GMU Version information
 * @irq: GMU interrupt number
 * @fw_image: GMU FW image
 * @gmu_log: gmu event log memory
 * @hfi: HFI controller
 * @idle_level: Minimal GPU idle power level
 * @log_wptr_retention: Store the log wptr offset on slumber
 */
struct gen8_gmu_device {
	int irq;
	const struct firmware *fw_image;
	struct kgsl_memdesc *gmu_log;
	/** @gmu_init_scratch: Memory to store the initial HFI messages */
	struct kgsl_memdesc *gmu_init_scratch;
	/** @gpu_boot_scratch: Memory to store the bootup HFI messages */
	struct kgsl_memdesc *gpu_boot_scratch;
	struct gen8_hfi hfi;
	u32 idle_level;
	/** @qmp: aoss_qmp handle */
	struct qmp *qmp;
	u32 log_wptr_retention;
	/** @cm3_fault: whether gmu received a cm3 fault interrupt */
	atomic_t cm3_fault;
	/**
	 * @itcm_shadow: Copy of the itcm block in firmware binary used for
	 * snapshot
	 */
	void *itcm_shadow;
	/** @flags: Internal gmu flags */
	unsigned long flags;
	/** @rscc_virt: Pointer where RSCC block is mapped */
	void __iomem *rscc_virt;
	/** @log_stream_enable: GMU log streaming enable. Disabled by default */
	bool log_stream_enable;
	/** @log_group_mask: Allows overriding default GMU log group mask */
	u32 log_group_mask;
	struct kobject log_kobj;
	/** @num_oob_perfcntr: Number of active oob_perfcntr requests */
	u32 num_oob_perfcntr;
	/** @acd_debug_val: DVM value to calibrate ACD for a level */
	u32 acd_debug_val;
	/** @stats_enable: GMU stats feature enable */
	bool stats_enable;
	/** @stats_mask: GMU performance countables to enable */
	u32 stats_mask;
	/** @stats_interval: GMU performance counters sampling interval */
	u32 stats_interval;
	/** @stats_kobj: kernel object for GMU stats directory in sysfs */
	struct kobject stats_kobj;
	/** @cp_init_hdr: raw command header for cp_init */
	u32 cp_init_hdr;
	/** @switch_to_unsec_hdr: raw command header for switch to unsecure packet */
	u32 switch_to_unsec_hdr;
	/** @dcvs_table: Table for gpu dcvs levels */
	struct gen8_dcvs_table dcvs_table;
	/** @dcvs_cmdbuf: Pointer to the table to pass DCVS data to GMU */
	u32 *dcvs_cmdbuf;
	/** @gmu_scaling_cmdbuf: Pointer to the table to pass GMU power levels */
	u32 *gmu_scaling_cmdbuf;
};

/* Helper function to get to gen8 gmu device from adreno device */
struct gen8_gmu_device *to_gen8_gmu(struct adreno_device *adreno_dev);

/* Helper function to get to adreno device from gen8 gmu device */
struct adreno_device *gen8_gmu_to_adreno(struct gen8_gmu_device *gmu);

/**
 * gen8_build_rpmh_tables - Build the rpmh tables
 * @adreno_dev: Pointer to the adreno device
 *
 * This function creates the gpu dcvs and bw tables
 *
 * Return: 0 on success and negative error on failure
 */
int gen8_build_rpmh_tables(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_gx_is_on - Check if GX is on
 * @adreno_dev: Pointer to the adreno device
 *
 * This function reads pwr status registers to check if GX
 * is on or off
 */
bool gen8_gmu_gx_is_on(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_device_probe - GEN8 GMU snapshot function
 * @pdev: Pointer to the platform device
 * @chipid: Chipid of the target
 * @gpucore: Pointer to the gpucore
 *
 * The target specific probe function for gmu based gen8 targets.
 */
int gen8_gmu_device_probe(struct platform_device *pdev,
		u32 chipid, const struct adreno_gpu_core *gpucore);

/**
 * gen8_gmu_reset - Reset and restart the gmu
 * @adreno_dev: Pointer to the adreno device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_reset(struct adreno_device *adreno_dev);

/**
 * gen8_enable_gpu_irq - Enable gpu interrupt
 * @adreno_dev: Pointer to the adreno device
 */
void gen8_enable_gpu_irq(struct adreno_device *adreno_dev);

/**
 * gen8_disable_gpu_irq - Disable gpu interrupt
 * @adreno_dev: Pointer to the adreno device
 */
void gen8_disable_gpu_irq(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_snapshot- Take snapshot for gmu targets
 * @adreno_dev: Pointer to the adreno device
 * @snapshot: Pointer to the snapshot structure
 *
 * Send an NMI to gmu if we hit a gmu fault. Then take gmu
 * snapshot and carry on with rest of the gen8 snapshot
 */
void gen8_gmu_snapshot(struct adreno_device *adreno_dev,
		struct kgsl_snapshot *snapshot);

/**
 * gen8_gmu_probe - Probe gen8 gmu resources
 * @device: Pointer to the kgsl device
 * @pdev: Pointer to the gmu platform device
 *
 * Probe the gmu and hfi resources
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_probe(struct kgsl_device *device,
		struct platform_device *pdev);

/**
 * gen8_gmu_parse_fw - Parse the gmu fw binary
 * @adreno_dev: Pointer to the adreno device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_parse_fw(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_memory_init - Allocate gmu memory
 * @adreno_dev: Pointer to the adreno device
 *
 * Allocates the gmu log buffer and others if ndeeded.
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_memory_init(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_aop_send_acd_state - Enable or disable acd feature in aop
 * @gmu: Pointer to the gen8 gmu device
 * @flag: Boolean to enable or disable acd in aop
 *
 * This function enables or disables gpu acd feature using qmp
 */
void gen8_gmu_aop_send_acd_state(struct gen8_gmu_device *gmu, bool flag);

/**
 * gen8_gmu_load_fw - Load gmu firmware
 * @adreno_dev: Pointer to the adreno device
 *
 * Loads the gmu firmware binary into TCMs and memory
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_load_fw(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_device_start - Bring gmu out of reset
 * @adreno_dev: Pointer to the adreno device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_device_start(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_hfi_start - Indicate hfi start to gmu
 * @device: Pointer to the kgsl device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_hfi_start(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_itcm_shadow - Create itcm shadow copy for snapshot
 * @adreno_dev: Pointer to the adreno device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_itcm_shadow(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_register_config - gmu register configuration
 * @adreno_dev: Pointer to the adreno device
 *
 * Program gmu regsiters based on features
 */
void gen8_gmu_register_config(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_version_info - Get gmu firmware version
 * @adreno_dev: Pointer to the adreno device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_version_info(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_irq_enable - Enable gmu interrupts
 * @adreno_dev: Pointer to the adreno device
 */
void gen8_gmu_irq_enable(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_irq_disable - Disaable gmu interrupts
 * @adreno_dev: Pointer to the adreno device
 */
void gen8_gmu_irq_disable(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_suspend - Hard reset the gpu and gmu
 * @adreno_dev: Pointer to the adreno device
 * @force: Set to true to enforce a hard reset
 *
 * In case we hit a gmu fault, hard reset the gpu and gmu
 * to recover from the fault
 */
void gen8_gmu_suspend(struct adreno_device *adreno_dev, bool force);

/**
 * gen8_gmu_oob_set - send gmu oob request
 * @device: Pointer to the kgsl device
 * @req: Type of oob request as defined in enum oob_request
 *
 * Request gmu to keep gpu powered up till the oob is cleared
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_oob_set(struct kgsl_device *device, enum oob_request oob);

/**
 * gen8_gmu_oob_clear - clear an asserted oob request
 * @device: Pointer to the kgsl device
 * @req: Type of oob request as defined in enum oob_request
 *
 * Clear a previously requested oob so that gmu can power
 * collapse the gpu
 */
void gen8_gmu_oob_clear(struct kgsl_device *device, enum oob_request oob);

/**
 * gen8_gmu_wait_for_lowest_idle - wait for gmu to complete ifpc
 * @adreno_dev: Pointer to the adreno device
 *
 * If ifpc is enabled, wait for gmu to put gpu into ifpc.
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_wait_for_lowest_idle(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_wait_for_idle - Wait for gmu to become idle
 * @adreno_dev: Pointer to the adreno device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_gmu_wait_for_idle(struct adreno_device *adreno_dev);

/**
 * gen8_rscc_sleep_sequence - Trigger rscc sleep sequence
 * @adreno_dev: Pointer to the adreno device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_rscc_sleep_sequence(struct adreno_device *adreno_dev);

/**
 * gen8_rscc_wakeup_sequence - Trigger rscc wakeup sequence
 * @adreno_dev: Pointer to the adreno device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_rscc_wakeup_sequence(struct adreno_device *adreno_dev);

/**
 * gen8_halt_gbif - Halt CX and GX requests in GBIF
 * @adreno_dev: Pointer to the adreno device
 *
 * Clear any pending GX or CX transactions in GBIF and
 * deassert GBIF halt
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_halt_gbif(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_remove - Clean up gmu probed resources
 * @device: Pointer to the kgsl device
 */
void gen8_gmu_remove(struct kgsl_device *device);

/**
 * gen8_gmu_handle_watchdog - Handle watchdog interrupt
 * @adreno_dev: Pointer to the adreno device
 */
void gen8_gmu_handle_watchdog(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_send_nmi - Send NMI to GMU
 * @device: Pointer to the kgsl device
 * @gf_policy: GMU fault panic setting policy
 * @force: Boolean to forcefully send NMI irrespective of GMU state
 */
void gen8_gmu_send_nmi(struct kgsl_device *device, bool force,
		       enum gmu_fault_panic_policy gf_policy);

/**
 * gen8_gmu_add_to_minidump - Register gen8_device with va minidump
 * @adreno_dev: Pointer to the adreno device
 */
int gen8_gmu_add_to_minidump(struct adreno_device *adreno_dev);

/**
 * gen8_gmu_rpmh_pwr_state_is_active - Check the state of GPU HW
 * @device: Pointer to the kgsl device
 *
 * Returns true on active or false otherwise
 */
bool gen8_gmu_rpmh_pwr_state_is_active(struct kgsl_device *device);
#endif
