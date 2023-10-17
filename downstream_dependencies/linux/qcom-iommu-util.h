/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __QCOM_IOMMU_UTIL_H
#define __QCOM_IOMMU_UTIL_H

#include <linux/iommu.h>

#include <soc/qcom/secure_buffer.h>

/* IOMMU fault behaviors */
#define QCOM_IOMMU_FAULT_MODEL_NO_STALL	BIT(2)

#ifndef IOMMU_SYS_CACHE
/* Attributes are not supported, so render them ineffective. */
#define IOMMU_SYS_CACHE		(0)
#define IOMMU_SYS_CACHE_NWA	(0)
#endif

/* Use upstream device's bus attribute */
#define IOMMU_USE_UPSTREAM_HINT	(IOMMU_SYS_CACHE)

/* Use upstream device's bus attribute with no write-allocate cache policy */
#define IOMMU_USE_LLC_NWA	(IOMMU_SYS_CACHE_NWA)

/* vendor iommu fault flags */
#define IOMMU_FAULT_TRANSLATION         (1 << 2)
#define IOMMU_FAULT_PERMISSION          (1 << 3)
#define IOMMU_FAULT_EXTERNAL            (1 << 4)
#define IOMMU_FAULT_TRANSACTION_STALLED (1 << 5)

static inline int qcom_iommu_set_fault_model(struct iommu_domain *domain, int fault_model)
{
	return -EINVAL;
}

static inline int qcom_iommu_get_context_bank_nr(struct iommu_domain *domain)
{
	return 0;
}

static inline int qcom_iommu_get_asid_nr(struct iommu_domain *domain)
{
	return -EINVAL;
}

static inline int qcom_iommu_set_secure_vmid(struct iommu_domain *domain, enum vmid vmid)
{
	return -EINVAL;
}

static inline int qcom_skip_tlb_management(struct device *dev, bool skip)
{
	return -EINVAL;
}

#endif /* __QCOM_IOMMU_UTIL_H */
