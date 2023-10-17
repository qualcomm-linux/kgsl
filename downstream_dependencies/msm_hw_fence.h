/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __MSM_HW_FENCE_H
#define __MSM_HW_FENCE_H

#include <linux/types.h>
#include <linux/dma-fence.h>

/**
 * MSM_HW_FENCE_FLAG_ENABLED_BIT - Hw-fence is enabled for the dma_fence.
 *
 * Drivers set this flag in the dma_fence 'flags' to fences that
 * are backed up by a hw-fence.
 */
#define MSM_HW_FENCE_FLAG_ENABLED_BIT    31

/**
 * MSM_HW_FENCE_FLAG_SIGNALED_BIT - Hw-fence is signaled for the dma_fence.
 *
 * This flag is set by hw-fence driver when a client wants to add itself as
 * a waiter for this hw-fence. The client uses this flag to avoid adding itself
 * as a waiter for a fence that is already retired.
 */
#define MSM_HW_FENCE_FLAG_SIGNALED_BIT    30

/**
 * MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT - Maximum number of signals per client
 */
#define MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT 64

/**
 * struct msm_hw_fence_create_params - Creation parameters.
 *
 * @name : Optional parameter associating a name with the object for debug purposes.
 *         Only first 64 bytes are accepted, rest will be ignored.
 * @handle : Pointer to fence hash (filled by function).
 * @fence : Pointer to fence.
 * @flags : flags for customization.
 */
struct msm_hw_fence_create_params {
	const char *name;
	u64 *handle;
	void *fence;
	u32 flags;
};

/**
 * struct msm_hw_fence_hfi_queue_table_header - HFI queue table structure.
 * @version: HFI protocol version.
 * @size: Queue table size in dwords.
 * @qhdr0_offset: First queue header offset (dwords) in this table.
 * @qhdr_size: Queue header size.
 * @num_q: Number of queues defined in this table.
 * @num_active_q: Number of active queues.
 */
struct msm_hw_fence_hfi_queue_table_header {
	u32 version;
	u32 size;
	u32 qhdr0_offset;
	u32 qhdr_size;
	u32 num_q;
	u32 num_active_q;
};

/**
 * struct msm_hw_fence_hfi_queue_header - HFI queue header structure.
 * @status: Active = 1, Inactive = 0.
 * @start_addr: Starting address of the queue.
 * @type: Queue type (rx/tx).
 * @queue_size: Size of the queue.
 * @pkt_size: Size of the queue packet entries,
 *            0 - means variable size of message in the queue,
 *            non-zero - size of the packet, fixed.
 * @pkt_drop_cnt: Number of packets drop by sender.
 * @rx_wm: Receiver watermark, applicable in event driven mode.
 * @tx_wm: Sender watermark, applicable in event driven mode.
 * @rx_req: Receiver sets this bit if queue is empty.
 * @tx_req: Sender sets this bit if queue is full.
 * @rx_irq_status: Receiver sets this bit and triggers an interrupt to the
 *                 sender after packets are dequeued. Sender clears this bit.
 * @tx_irq_status: Sender sets this bit and triggers an interrupt to the
 *                 receiver after packets are queued. Receiver clears this bit.
 * @read_index: read index of the queue.
 * @write_index: write index of the queue.
 */
struct msm_hw_fence_hfi_queue_header {
	u32 status;
	u32 start_addr;
	u32 type;
	u32 queue_size;
	u32 pkt_size;
	u32 pkt_drop_cnt;
	u32 rx_wm;
	u32 tx_wm;
	u32 rx_req;
	u32 tx_req;
	u32 rx_irq_status;
	u32 tx_irq_status;
	u32 read_index;
	u32 write_index;
};

/**
 * struct msm_hw_fence_mem_addr - Memory descriptor of the queue allocated by
 *                           the fence driver for each client during
 *                           register.
 * @virtual_addr: Kernel virtual address of the queue.
 * @device_addr: Physical address of the memory object.
 * @size: Size of the memory.
 * @mem_data: Internal pointer with the attributes of the allocation.
 */
struct msm_hw_fence_mem_addr {
	void *virtual_addr;
	phys_addr_t device_addr;
	u64 size;
	void *mem_data;
};

/**
 * enum hw_fence_client_id - Unique identifier of the supported clients.
 * @HW_FENCE_CLIENT_ID_CTX0: GFX Client.
 * @HW_FENCE_CLIENT_ID_CTL0: DPU Client 0.
 * @HW_FENCE_CLIENT_ID_CTL1: DPU Client 1.
 * @HW_FENCE_CLIENT_ID_CTL2: DPU Client 2.
 * @HW_FENCE_CLIENT_ID_CTL3: DPU Client 3.
 * @HW_FENCE_CLIENT_ID_CTL4: DPU Client 4.
 * @HW_FENCE_CLIENT_ID_CTL5: DPU Client 5.
 * @HW_FENCE_CLIENT_ID_VAL0: debug Validation client 0.
 * @HW_FENCE_CLIENT_ID_VAL1: debug Validation client 1.
 * @HW_FENCE_CLIENT_ID_VAL2: debug Validation client 2.
 * @HW_FENCE_CLIENT_ID_VAL3: debug Validation client 3.
 * @HW_FENCE_CLIENT_ID_VAL4: debug Validation client 4.
 * @HW_FENCE_CLIENT_ID_VAL5: debug Validation client 5.
 * @HW_FENCE_CLIENT_ID_VAL6: debug Validation client 6.
 * @HW_FENCE_CLIENT_ID_IPE: IPE Client.
 * @HW_FENCE_CLIENT_ID_VPU: VPU Client.
 * @HW_FENCE_CLIENT_ID_IFE0: IFE0 Client 0.
 * @HW_FENCE_CLIENT_ID_IFE1: IFE1 Client 0.
 * @HW_FENCE_CLIENT_ID_IFE2: IFE2 Client 0.
 * @HW_FENCE_CLIENT_ID_IFE3: IFE3 Client 0.
 * @HW_FENCE_CLIENT_ID_IFE4: IFE4 Client 0.
 * @HW_FENCE_CLIENT_ID_IFE5: IFE5 Client 0.
 * @HW_FENCE_CLIENT_ID_IFE6: IFE6 Client 0.
 * @HW_FENCE_CLIENT_ID_IFE7: IFE7 Client 0.
 * @HW_FENCE_CLIENT_MAX: Max number of clients, any client must be added
 *                       before this enum.
 */
enum hw_fence_client_id {
	HW_FENCE_CLIENT_ID_CTX0 = 0x1,
	HW_FENCE_CLIENT_ID_CTL0,
	HW_FENCE_CLIENT_ID_CTL1,
	HW_FENCE_CLIENT_ID_CTL2,
	HW_FENCE_CLIENT_ID_CTL3,
	HW_FENCE_CLIENT_ID_CTL4,
	HW_FENCE_CLIENT_ID_CTL5,
	HW_FENCE_CLIENT_ID_VAL0,
	HW_FENCE_CLIENT_ID_VAL1,
	HW_FENCE_CLIENT_ID_VAL2,
	HW_FENCE_CLIENT_ID_VAL3,
	HW_FENCE_CLIENT_ID_VAL4,
	HW_FENCE_CLIENT_ID_VAL5,
	HW_FENCE_CLIENT_ID_VAL6,
	HW_FENCE_CLIENT_ID_IPE,
	HW_FENCE_CLIENT_ID_VPU,
	HW_FENCE_CLIENT_ID_IFE0,
	HW_FENCE_CLIENT_ID_IFE1 = HW_FENCE_CLIENT_ID_IFE0 + MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT,
	HW_FENCE_CLIENT_ID_IFE2 = HW_FENCE_CLIENT_ID_IFE1 + MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT,
	HW_FENCE_CLIENT_ID_IFE3 = HW_FENCE_CLIENT_ID_IFE2 + MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT,
	HW_FENCE_CLIENT_ID_IFE4 = HW_FENCE_CLIENT_ID_IFE3 + MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT,
	HW_FENCE_CLIENT_ID_IFE5 = HW_FENCE_CLIENT_ID_IFE4 + MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT,
	HW_FENCE_CLIENT_ID_IFE6 = HW_FENCE_CLIENT_ID_IFE5 + MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT,
	HW_FENCE_CLIENT_ID_IFE7 = HW_FENCE_CLIENT_ID_IFE6 + MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT,
	HW_FENCE_CLIENT_MAX = HW_FENCE_CLIENT_ID_IFE7 + MSM_HW_FENCE_MAX_SIGNAL_PER_CLIENT
};

static inline void *msm_hw_fence_register(enum hw_fence_client_id client_id,
	struct msm_hw_fence_mem_addr *mem_descriptor)
{
	return NULL;
}

static inline int msm_hw_fence_deregister(void *client_handle)
{
	return -EINVAL;
}

static inline int msm_hw_fence_create(void *client_handle,
	struct msm_hw_fence_create_params *params)
{
	return -EINVAL;
}

static inline int msm_hw_fence_destroy(void *client_handle, struct dma_fence *fence)
{
	return -EINVAL;
}

static inline int msm_hw_fence_wait_update(void *client_handle,
	struct dma_fence **fences, u32 num_fences, bool reg)
{
	return -EINVAL;
}

static inline int msm_hw_fence_update_txq(void *client_handle, u64 handle, u64 flags, u32 error)
{
	return -EINVAL;
}

static inline int msm_hw_fence_trigger_signal(void *client_handle, u32 tx_client_id,
	u32 rx_client_id, u32 signal_id)
{
	return -EINVAL;
}

#endif
