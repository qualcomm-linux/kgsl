/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _MSM_SYSSTATS_H_
#define _MSM_SYSSTATS_H_

static inline void sysstats_register_kgsl_stats_cb(u64 (*cb)(pid_t pid))
{
}

static inline void sysstats_unregister_kgsl_stats_cb(void)
{
}
#endif /* _MSM_SYSSTATS_H_ */
