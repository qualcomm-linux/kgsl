// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021 The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/trace.h>
#include "adreno.h"

/* Instantiate tracepoints */
#define CREATE_TRACE_POINTS
#include "adreno_trace.h"

#ifdef CONFIG_QCOM_KGSL_FENCE_TRACE
static const char * const kgsl_fence_trace_events[] = {
	"adreno_cmdbatch_submitted",
	"adreno_cmdbatch_retired",
	"syncpoint_fence",
	"syncpoint_fence_expire",
	"kgsl_fire_event",
	"kgsl_timeline_fence_alloc",
	"kgsl_timeline_fence_release",
};

void adreno_fence_trace_array_init(struct kgsl_device *device)
{
	int i;

#if (KERNEL_VERSION(6, 7, 0) >= LINUX_VERSION_CODE)
	device->fence_trace_array = trace_array_get_by_name("kgsl-fence");
#else
	device->fence_trace_array = trace_array_get_by_name("kgsl-fence", NULL);
#endif

	if (!device->fence_trace_array)
		return;

	for (i = 0; i < ARRAY_SIZE(kgsl_fence_trace_events); i++)
		trace_array_set_clr_event(device->fence_trace_array,
			"kgsl", kgsl_fence_trace_events[i], true);

}
#endif
