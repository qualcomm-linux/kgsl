/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __QCOM_OF_H
#define __QCOM_OF_H

#include <linux/of.h>

static inline int of_fdt_get_ddrtype(void)
{
	return -EINVAL;
}

#endif
