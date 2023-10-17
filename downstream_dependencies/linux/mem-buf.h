/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 *  Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _MEM_BUF_H
#define _MEM_BUF_H

#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>

static inline bool mem_buf_dma_buf_exclusive_owner(struct dma_buf *dmabuf)
{
	return false;
}

static inline int mem_buf_dma_buf_copy_vmperm(struct dma_buf *dmabuf, int **vmids, int **perms,
		int *nr_acl_entries)
{
	return -EINVAL;
}

#endif
