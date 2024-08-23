/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023-2024, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _ADRENO_GEN8_HWSCHED_H_
#define _ADRENO_GEN8_HWSCHED_H_

#include "adreno_gen8_hwsched_hfi.h"

/**
 * enum gen8_gmu_dcvs_obj - Type of DCVS object to be used for GMU based DCVS
 * @GMU_GPU_DCVS_OBJ_OFF: DCVS disabled
 * @GMU_GPU_DCVS_OBJ_DEPRECATED: Deprecated object
 * @GMU_GPU_DCVS_OBJ_DOS: DCVS Old School algorithm
 * @GMU_GPU_DCVS_OBJ_PARITY: Parity algorithm based on host based DCVS
 * @GMU_GPU_DCVS_OBJ_MAX: enum to define max allowed object
 */
enum gen8_gmu_dcvs_obj {
	GMU_GPU_DCVS_OBJ_OFF = 0,
	GMU_GPU_DCVS_OBJ_DEPRECATED = 1,
	GMU_GPU_DCVS_OBJ_DOS = 2,
	GMU_GPU_DCVS_OBJ_PARITY = 3,
	GMU_GPU_DCVS_OBJ_MAX,
};

/**
 * struct gen8_hwsched_device - Container for the gen8 hwscheduling device
 */
struct gen8_hwsched_device {
	/** @gen8_dev: Container for the gen8 device */
	struct gen8_device gen8_dev;
	/** @hwsched_hfi: Container for hwscheduling specific hfi resources */
	struct gen8_hwsched_hfi hwsched_hfi;
};

/**
 * gen8_hwsched_probe - Target specific probe for hwsched
 * @pdev: Pointer to the platform device
 * @chipid: Chipid of the target
 * @gpucore: Pointer to the gpucore
 *
 * The target specific probe function for hwsched enabled gmu targets.
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_hwsched_probe(struct platform_device *pdev,
		u32 chipid, const struct adreno_gpu_core *gpucore);

/**
 * gen8_hwsched_reset_replay - Restart the gmu and gpu and replay inflight cmdbatches
 * @adreno_dev: Pointer to the adreno device
 *
 * Return: 0 on success or negative error on failure
 */
int gen8_hwsched_reset_replay(struct adreno_device *adreno_dev);

/**
 * gen8_hwsched_snapshot - take gen8 hwsched snapshot
 * @adreno_dev: Pointer to the adreno device
 * @snapshot: Pointer to the snapshot instance
 *
 * Snapshot the faulty ib and then snapshot rest of gen8 gmu things
 */
void gen8_hwsched_snapshot(struct adreno_device *adreno_dev,
		struct kgsl_snapshot *snapshot);

/**
 * gen8_hwsched_handle_watchdog - Handle watchdog interrupt
 * @adreno_dev: Pointer to the adreno device
 */
void gen8_hwsched_handle_watchdog(struct adreno_device *adreno_dev);

/**
 * gen8_hwsched_add_to_minidump - Register hwsched_device with va minidump
 * @adreno_dev: Pointer to the adreno device
 */
int gen8_hwsched_add_to_minidump(struct adreno_device *adreno_dev);

/**
 * gen8_hwsched_send_recurring_cmdobj - Dispatch IBs to GMU
 * @adreno_dev: Pointer to adreno device structure
 * @cmdobj: The command object which needs to be submitted
 *
 * This function is used to register the context if needed and submit
 * recurring IBs to the GMU. Upon receiving ipc interrupt GMU will submit
 * recurring IBs to GPU.

 * Return: 0 on success and negative error on failure
 */
int gen8_hwsched_send_recurring_cmdobj(struct adreno_device *adreno_dev,
		struct kgsl_drawobj_cmd *cmdobj);

/**
 * gen8_hwsched_fault - Set hwsched fault to request recovery
 * @adreno_dev: A handle to adreno device
 * @fault: The type of fault
 */
void gen8_hwsched_fault(struct adreno_device *adreno_dev, u32 fault);

/**
 * gen8_hwsched_soccp_vote - Vote for soccp power
 * @adreno_dev: A handle to adreno device
 * @pwr_on: Boolean to turn soccp on/off
 */
void gen8_hwsched_soccp_vote(struct adreno_device *adreno_dev, bool pwr_on);

/**
 * gen8_hwsched_set_pwrconstraint - Send perf hint to GMU
 * @adreno_dev: A handle to adreno device
 * @context_id: Id for the context associated with hint
 */
void gen8_hwsched_set_pwrconstraint(struct adreno_device *adreno_dev, u32 context_id);

/**
 * gen8_hwsched_init_ucode_regs - Initializes CP ucode registers
 * @adreno_dev: A handle to adreno device
 */
void gen8_hwsched_init_ucode_regs(struct adreno_device *adreno_dev);
#endif
