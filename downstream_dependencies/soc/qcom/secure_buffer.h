/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __QCOM_SECURE_BUFFER_H__
#define __QCOM_SECURE_BUFFER_H__

/*
 * if you add a secure VMID here make sure you update
 * msm_secure_vmid_to_string.
 * Make sure to keep the VMID_LAST as the last entry in the enum.
 * This is needed in ion to create a list and it's sized using VMID_LAST.
 */
enum vmid {
	VMID_TZ = 0x1,
	VMID_HLOS = 0x3,
	VMID_CP_TOUCH = 0x8,
	VMID_CP_BITSTREAM = 0x9,
	VMID_CP_PIXEL = 0xA,
	VMID_CP_NON_PIXEL = 0xB,
	VMID_CP_CAMERA = 0xD,
	VMID_HLOS_FREE = 0xE,
	VMID_MSS_MSA = 0xF,
	VMID_MSS_NONMSA = 0x10,
	VMID_CP_SEC_DISPLAY = 0x11,
	VMID_CP_APP = 0x12,
	VMID_LPASS = 0x16,
	VMID_WLAN = 0x18,
	VMID_WLAN_CE = 0x19,
	VMID_CP_SPSS_SP = 0x1A,
	VMID_CP_CAMERA_PREVIEW = 0x1D,
	VMID_CP_SPSS_SP_SHARED = 0x22,
	VMID_CP_SPSS_HLOS_SHARED = 0x24,
	VMID_ADSP_HEAP = 0x25,
	VMID_CP_CDSP = 0x2A,
	VMID_NAV = 0x2B,
	VMID_TVM = 0x2D,
	VMID_OEMVM = 0x31,
	VMID_LAST,
	VMID_INVAL = -1
};
#endif
