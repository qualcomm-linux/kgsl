/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef __ADRENO_GEN7_5_0_SNAPSHOT_H
#define __ADRENO_GEN7_5_0_SNAPSHOT_H

#include "adreno_gen7_15_0_snapshot.h"

/*
 * Block   : ['CPR']
 * REGION  : UNSLICE
 * Pipeline: PIPE_NONE
 * pairs   : 20 (Regs:455)
 */
static const u32 gen7_5_0_cpr_registers[] = {
	 0x26800, 0x26805, 0x26808, 0x2680c, 0x26814, 0x26814, 0x2681c, 0x2681c,
	 0x26820, 0x26838, 0x26840, 0x26840, 0x26848, 0x26848, 0x26850, 0x26850,
	 0x26880, 0x2689e, 0x26980, 0x269b0, 0x269c0, 0x269c8, 0x269e0, 0x269ee,
	 0x269fb, 0x269ff, 0x26a02, 0x26a07, 0x26a09, 0x26a0b, 0x26a10, 0x26b0f,
	 0x27440, 0x27441, 0x27444, 0x27444, 0x27480, 0x274a2, 0x274ac, 0x274ad,
	 UINT_MAX, UINT_MAX,
};
static_assert(IS_ALIGNED(sizeof(gen7_5_0_cpr_registers), 8));

/*
 * Block   : ['GPU_CC_GPU_CC_REG']
 * REGION  : UNSLICE
 * Pipeline: PIPE_NONE
 * pairs   : 22 (Regs:155)
 */
static const u32 gen7_5_0_gpu_cc_gpu_cc_reg_registers[] = {
	 0x25400, 0x25404, 0x25800, 0x25804, 0x25c00, 0x25c04,
	 0x26000, 0x26004, 0x26400, 0x26405, 0x26414, 0x2641d, 0x2642a, 0x26430,
	 0x26432, 0x26433, 0x26441, 0x2644b, 0x2644d, 0x26457, 0x26466, 0x26468,
	 0x26478, 0x2647a, 0x26489, 0x2648a, 0x2649c, 0x2649e, 0x264a0, 0x264a4,
	 0x264c5, 0x264c7, 0x264d6, 0x264d8, 0x264e8, 0x264e9, 0x264f9, 0x264fc,
	 0x2651c, 0x2651e, 0x26540, 0x26576, 0x26578, 0x26579,
	 UINT_MAX, UINT_MAX,
};
static_assert(IS_ALIGNED(sizeof(gen7_5_0_gpu_cc_gpu_cc_reg_registers), 8));

/*
 * Block   : ['GPU_CC_PLL0_CM_PLL_ZONDA_OLE']
 * REGION  : UNSLICE
 * Pipeline: PIPE_NONE
 * pairs   : 1 (Regs:17)
 */
static const u32 gen7_5_0_gpu_cc_pll0_cm_pll_zonda_ole_registers[] = {
	 0x24000, 0x24010,
	 UINT_MAX, UINT_MAX,
};
static_assert(IS_ALIGNED(sizeof(gen7_5_0_gpu_cc_pll0_cm_pll_zonda_ole_registers), 8));

/*
 * Block   : ['DPM_LEAKAGE']
 * REGION  : UNSLICE
 * Pipeline: PIPE_NONE
 * pairs   : 9 (Regs:26)
 */
static const u32 gen7_5_0_dpm_leakage_registers[] = {
	 0x21c00, 0x21c00, 0x21c08, 0x21c09, 0x21c0e, 0x21c0f, 0x21c4f, 0x21c50,
	 0x21c52, 0x21c52, 0x21c54, 0x21c56, 0x21c58, 0x21c5a, 0x21c5c, 0x21c60,
	 0x22048, 0x2204e,
	 UINT_MAX, UINT_MAX,
};
static_assert(IS_ALIGNED(sizeof(gen7_5_0_dpm_leakage_registers), 8));

static const u32 *gen7_5_0_external_core_regs[] = {
	gen7_15_0_gpu_cc_acd_acd_registers,
	gen7_15_0_gpu_cc_ahb2phy_broadcast_swman_registers,
	gen7_15_0_gpu_cc_ahb2phy_swman_registers,
	gen7_5_0_gpu_cc_gpu_cc_reg_registers,
	gen7_5_0_gpu_cc_pll0_cm_pll_zonda_ole_registers,
	gen7_15_0_gpu_cc_pll1_cm_pll_lucid_ole_registers,
	gen7_5_0_cpr_registers,
	gen7_5_0_dpm_leakage_registers,
};
#endif /*_ADRENO_GEN7_5_0_SNAPSHOT_H */
