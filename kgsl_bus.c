// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <dt-bindings/interconnect/qcom,icc.h>
#include <linux/interconnect.h>
#include <linux/of.h>
#include <linux/sort.h>
#include <soc/qcom/of_common.h>

#include "kgsl_bus.h"
#include "kgsl_device.h"
#include "kgsl_pwrctrl.h"
#include "kgsl_trace.h"
#include "kgsl_util.h"

static u32 _ab_buslevel_update(struct kgsl_pwrctrl *pwr,
		u32 ib)
{
	if (!ib)
		return 0;

	/*
	 * In the absence of any other settings, make ab 25% of ib
	 * where the ib vote is in kbps
	 */
	if ((!pwr->bus_percent_ab) && (!pwr->bus_ab_mbytes))
		return 25 * ib / 100000;

	if (pwr->bus_width)
		return pwr->bus_ab_mbytes;

	return (pwr->bus_percent_ab * pwr->bus_max) / 100;
}

int kgsl_bus_update(struct kgsl_device *device,
			 enum kgsl_bus_vote vote_state)
{
	struct kgsl_pwrctrl *pwr = &device->pwrctrl;
	int buslevel;
	u32 ab;

	/* the bus should be ON to update the active frequency */
	if ((vote_state != KGSL_BUS_VOTE_OFF) &&
		!(test_bit(KGSL_PWRFLAGS_AXI_ON, &pwr->power_flags)))
		return 0;
	/*
	 * If the bus should remain on calculate our request and submit it,
	 * otherwise request bus level 0, off.
	 */
	switch (vote_state) {
	case KGSL_BUS_VOTE_OFF:
		/* If the bus is being turned off, reset to default level */
		pwr->cur_dcvs_buslevel = 0;
		pwr->bus_mod = 0;
		pwr->bus_percent_ab = 0;
		pwr->bus_ab_mbytes = 0;
		ab = 0;
		break;
	case KGSL_BUS_VOTE_ON:
		{
		/* FIXME: this might be wrong? */
		int cur = pwr->pwrlevels[pwr->active_pwrlevel].bus_freq;

		buslevel = min_t(int, pwr->pwrlevels[0].bus_max,
				cur + pwr->bus_mod);
		buslevel = max_t(int, buslevel, 1);
		pwr->cur_dcvs_buslevel = buslevel;
		ab = _ab_buslevel_update(pwr, pwr->ddr_table[buslevel]);
		break;
		}
	case KGSL_BUS_VOTE_MINIMUM:
		/* Request bus level 1, minimum non-zero value */
		pwr->cur_dcvs_buslevel = 1;
		pwr->bus_mod = 0;
		pwr->bus_percent_ab = 0;
		pwr->bus_ab_mbytes = 0;
		ab = _ab_buslevel_update(pwr,
			pwr->ddr_table[pwr->cur_dcvs_buslevel]);
		break;
	case KGSL_BUS_VOTE_RT_HINT_ON:
		pwr->rt_bus_hint_active = true;
		/* Only update IB during bus hint */
		ab = pwr->cur_ab;
		break;
	case KGSL_BUS_VOTE_RT_HINT_OFF:
		pwr->rt_bus_hint_active = false;
		/* Only update IB during bus hint */
		ab = pwr->cur_ab;
		break;
	}

	buslevel = pwr->rt_bus_hint_active ?
		max(pwr->cur_dcvs_buslevel, pwr->rt_bus_hint) :
		pwr->cur_dcvs_buslevel;

	return device->ftbl->gpu_bus_set(device, buslevel, ab);
}

#ifdef CONFIG_QCOM_KGSL_UPSTREAM
void kgsl_icc_set_tag(struct kgsl_pwrctrl *pwr, int buslevel)
{
	icc_set_tag(pwr->icc_path, QCOM_ICC_TAG_ALWAYS);
}
#else
void kgsl_icc_set_tag(struct kgsl_pwrctrl *pwr, int buslevel)
{
	if (buslevel == pwr->pwrlevels[0].bus_max)
		icc_set_tag(pwr->icc_path, QCOM_ICC_TAG_ALWAYS | QCOM_ICC_TAG_PERF_MODE);
	else
		icc_set_tag(pwr->icc_path, QCOM_ICC_TAG_ALWAYS);
}
#endif

static u32 *kgsl_bus_get_table_from_opp_freqs(struct platform_device *pdev, int *count)
{
	struct device_node *node, *child;
	u32 bus_freq = 0;
	u32 *levels;
	int index = 0, j = 0;

	node = of_parse_phandle(pdev->dev.of_node, "operating-points-v2", 0);
	if (!node)
		return ERR_PTR(-EINVAL);

	levels = kcalloc(KGSL_MAX_PWRLEVELS, sizeof(*levels), GFP_KERNEL);
	if (!levels)
		return ERR_PTR(-ENOMEM);

	/* Set lowest bandwidth vote to zero. */
	levels[0] = 0;
	index++;

	for_each_child_of_node(node, child) {
		if (index >= KGSL_MAX_PWRLEVELS) {
			dev_err(&pdev->dev, "opp-table items exceed the capacity\n");
			kfree(levels);
			return ERR_PTR(-EINVAL);
		}

		if (of_property_read_u32(child, "opp-peak-kBps", &bus_freq)) {
			dev_warn(&pdev->dev, "Missing opp-peak-kBps in OPP node\n");
			continue;
		}

		if (!bus_freq)
			continue;

		for (j = 0; j < index; j++) {
			if (levels[j] == bus_freq)
				break;
		}

		if (j == index)
			levels[index++] = bus_freq;
	}

	if (index == 1) {
		kfree(levels);
		return ERR_PTR(-EINVAL);
	}

	sort(levels, index, sizeof(u32), cmp_u32, NULL);
	*count = index;
	return levels;
}

u32 *kgsl_bus_get_table(struct platform_device *pdev,
		const char *name, int *count)
{
	u32 *levels;
	int i, num = of_property_count_elems_of_size(pdev->dev.of_node,
		name, sizeof(u32));

	/* If the bus wasn't specified, then build a static table */
	if (num <= 0)
		return ERR_PTR(-EINVAL);

	levels = kcalloc(num, sizeof(*levels), GFP_KERNEL);
	if (!levels)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < num; i++)
		of_property_read_u32_index(pdev->dev.of_node,
			name, i, &levels[i]);

	*count = num;
	return levels;
}

int kgsl_bus_init(struct kgsl_device *device, struct platform_device *pdev)
{
	struct kgsl_pwrctrl *pwr = &device->pwrctrl;
	int count;
	int ddr = kgsl_get_ddrtype();

	if (ddr >= 0) {
		char str[32];

		snprintf(str, sizeof(str), "qcom,bus-table-ddr%d", ddr);

		pwr->ddr_table = kgsl_bus_get_table(pdev, str, &count);
		if (!IS_ERR(pwr->ddr_table))
			goto done;
	}

	/* Look if a generic table is present */
	pwr->ddr_table = kgsl_bus_get_table(pdev, "qcom,bus-table-ddr", &count);

	if (!IS_ERR(pwr->ddr_table))
		goto done;

	/*
	 * If ddr table is not present in DT, create ddr table from set of opp-peak-kBps
	 * values from OPP table.
	 */
	pwr->ddr_table = kgsl_bus_get_table_from_opp_freqs(pdev, &count);

	if (IS_ERR(pwr->ddr_table)) {
		int ret = PTR_ERR(pwr->ddr_table);

		pwr->ddr_table = NULL;
		return ret;
	}
done:
	pwr->ddr_table_count = count;

	/*
	 * In standard device tree bindings, the interconnect path is named "gfx-mem",
	 * whereas downstream bindings use "gpu_icc_path". Since multiple GPU interconnect
	 * paths have not been maintained in gpu device-tree, invoke of_icc_get() with a NULL
	 * path name to default to index 0. This will work for both standard and downstream
	 * bindings.
	 */
	pwr->icc_path = of_icc_get(&pdev->dev, NULL);

	if (IS_ERR(pwr->icc_path) && !gmu_core_scales_bandwidth(device)) {
		WARN(1, "The CPU has no way to set the GPU bus levels\n");

		kfree(pwr->ddr_table);
		pwr->ddr_table = NULL;
		return PTR_ERR(pwr->icc_path);
	}

	return 0;
}

void kgsl_bus_close(struct kgsl_device *device)
{
	kfree(device->pwrctrl.ddr_table);
	device->pwrctrl.ddr_table = NULL;
	icc_put(device->pwrctrl.icc_path);
	device->pwrctrl.icc_path = NULL;
}
