/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019, 2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __QTEE_SHMBRIDGE_H__
#define __QTEE_SHMBRIDGE_H__

/* VMID and permission definitions */

/**
 * struct qtee_shm - info of shared memory allocated from the default bridge
 * @ paddr: physical address of the shm allocated from the default bridge
 * @ vaddr: virtual address of the shm
 * @ size: size of the shm
 */
struct qtee_shm {
	phys_addr_t paddr;
	void *vaddr;
	size_t size;
};

static inline bool qtee_shmbridge_is_enabled(void)
{
	return false;
}
static inline int32_t qtee_shmbridge_allocate_shm(size_t size, struct qtee_shm *shm)
{
	return -EINVAL;
}
static inline void qtee_shmbridge_free_shm(struct qtee_shm *shm) { }

#endif /*__QTEE_SHMBRIDGE_H__*/
