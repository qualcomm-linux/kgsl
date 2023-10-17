/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __LINUX_CLK_QCOM_H_
#define __LINUX_CLK_QCOM_H_

#include <linux/clk.h>
#include <linux/regulator/consumer.h>

static inline void qcom_clk_dump(struct clk *clk, struct regulator *regulator,
				 bool calltrace)
{
}

#endif  /* __LINUX_CLK_QCOM_H_ */
