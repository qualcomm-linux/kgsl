// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2018-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <dt-bindings/power/qcom-rpmpd.h>
#include <linux/of.h>
#include <linux/io.h>
#include <linux/of_platform.h>
#include <linux/pm_opp.h>

#include "adreno.h"
#include "adreno_trace.h"
#include "kgsl_device.h"
#include "kgsl_gmu_core.h"
#include "kgsl_power_trace.h"
#include "kgsl_sync.h"
#include "kgsl_trace.h"

static const struct of_device_id gmu_match_table[] = {
	{ .compatible = "qcom,gpu-gmu", .data = &a6xx_gmu_driver },
	{ .compatible = "qcom,gpu-rgmu", .data = &a6xx_rgmu_driver },
	{ .compatible = "qcom,gen7-gmu", .data = &gen7_gmu_driver },
	{ .compatible = "qcom,gen8-gmu", .data = &gen8_gmu_driver },
	{ .compatible = "qcom,adreno-gmu-623.0", .data = &a6xx_gmu_driver },
	{ .compatible = "qcom,adreno-gmu-663.0", .data = &a6xx_gmu_driver },
	{ .compatible = "qcom,adreno-gmu-635.0", .data = &a6xx_gmu_driver },
	{ .compatible = "qcom,adreno-rgmu", .data = &a6xx_rgmu_driver },
	{ .compatible = "qcom,adreno-gmu-x185.1", .data = &gen7_gmu_driver },
	{ .compatible = "qcom,adreno-gmu-x145.0", .data = &gen7_gmu_driver },
	{ .compatible = "qcom,adreno-gmu-x285.1", .data = &gen8_gmu_driver },
	{},
};

void __init gmu_core_register(void)
{
	const struct of_device_id *match;
	struct device_node *node;

	node = of_find_matching_node_and_match(NULL, gmu_match_table,
		&match);
	if (!node)
		return;

	platform_driver_register((struct platform_driver *) match->data);
	of_node_put(node);
}

void gmu_core_unregister(void)
{
	const struct of_device_id *match;
	struct device_node *node;

	node = of_find_matching_node_and_match(NULL, gmu_match_table,
		&match);
	if (!node)
		return;

	platform_driver_unregister((struct platform_driver *) match->data);
	of_node_put(node);
}

bool gmu_core_isenabled(struct kgsl_device *device)
{
	return test_bit(GMU_ENABLED, &device->gmu_core.flags);
}

bool gmu_core_gpmu_isenabled(struct kgsl_device *device)
{
	return (device->gmu_core.dev_ops != NULL);
}

bool gmu_core_scales_bandwidth(struct kgsl_device *device)
{
	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	if (ops && ops->scales_bandwidth)
		return ops->scales_bandwidth(device);

	return false;
}

int gmu_core_dev_acd_set(struct kgsl_device *device, bool val)
{
	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	if (ops && ops->acd_set)
		return ops->acd_set(device, val);

	return -EINVAL;
}

void gmu_core_regread(struct kgsl_device *device, unsigned int offsetwords,
		unsigned int *value)
{
	u32 val = kgsl_regmap_read(&device->regmap, offsetwords);
	*value  = val;
}

void gmu_core_regwrite(struct kgsl_device *device, unsigned int offsetwords,
		unsigned int value)
{
	kgsl_regmap_write(&device->regmap, value, offsetwords);
}

void gmu_core_blkwrite(struct kgsl_device *device, unsigned int offsetwords,
		const void *buffer, size_t size)
{
	kgsl_regmap_bulk_write(&device->regmap, offsetwords,
		buffer, size >> 2);
}

void gmu_core_regrmw(struct kgsl_device *device,
		unsigned int offsetwords,
		unsigned int mask, unsigned int bits)
{
	kgsl_regmap_rmw(&device->regmap, offsetwords, mask, bits);
}

int gmu_core_dev_oob_set(struct kgsl_device *device, enum oob_request req)
{
	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	if (ops && ops->oob_set)
		return ops->oob_set(device, req);

	return 0;
}

void gmu_core_dev_oob_clear(struct kgsl_device *device, enum oob_request req)
{
	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	if (ops && ops->oob_clear)
		ops->oob_clear(device, req);
}

void gmu_core_dev_cooperative_reset(struct kgsl_device *device)
{

	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	if (ops && ops->cooperative_reset)
		ops->cooperative_reset(device);
}

int gmu_core_dev_ifpc_isenabled(struct kgsl_device *device)
{
	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	if (ops && ops->ifpc_isenabled)
		return ops->ifpc_isenabled(device);

	return 0;
}

int gmu_core_dev_ifpc_store(struct kgsl_device *device, unsigned int val)
{
	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	if (ops && ops->ifpc_store)
		return ops->ifpc_store(device, val);

	return -EINVAL;
}

int gmu_core_dev_wait_for_active_transition(struct kgsl_device *device)
{
	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	if (ops && ops->wait_for_active_transition)
		return ops->wait_for_active_transition(device);

	return 0;
}

void gmu_core_fault_snapshot(struct kgsl_device *device,
			enum gmu_fault_panic_policy gf_policy)
{
	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	/* Send NMI first to halt GMU and capture the state close to the point of failure */
	if (ops && ops->send_nmi)
		ops->send_nmi(device, false, gf_policy);

	kgsl_device_snapshot(device, NULL, NULL, true);
}

int gmu_core_timed_poll_check(struct kgsl_device *device,
		unsigned int offset, unsigned int expected_ret,
		unsigned int timeout_ms, unsigned int mask)
{
	u32 val;

	return kgsl_regmap_read_poll_timeout(&device->regmap, offset,
		val, (val & mask) == expected_ret, 100, timeout_ms * 1000);
}

int gmu_core_map_memdesc(struct iommu_domain *domain, struct kgsl_memdesc *memdesc,
		u64 gmuaddr, int attrs)
{
	ssize_t mapped;

	if (!memdesc->pages) {
		mapped = kgsl_mmu_map_sg(domain, gmuaddr, memdesc->sgt->sgl,
			memdesc->sgt->nents, attrs);
	} else {
		struct sg_table sgt = { 0 };
		int ret;

		ret = sg_alloc_table_from_pages(&sgt, memdesc->pages,
			memdesc->page_count, 0, memdesc->size, GFP_KERNEL);

		if (ret)
			return ret;

		mapped = kgsl_mmu_map_sg(domain, gmuaddr, sgt.sgl, sgt.nents, attrs);
		sg_free_table(&sgt);
	}

	if (!mapped)
		mapped = -ENOMEM;

	return (mapped < 0) ? mapped : 0;
}

struct kgsl_memdesc *gmu_core_find_memdesc(struct kgsl_device *device, u32 addr, u32 size)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	int i;

	for (i = 0; i < gmu->global_entries; i++) {
		struct kgsl_memdesc *md = &gmu->gmu_globals[i];

		if ((addr >= md->gmuaddr) &&
				(((addr + size) <= (md->gmuaddr + md->size))))
			return md;
	}

	return NULL;
}

int gmu_core_find_vma_block(struct kgsl_device *device, u32 addr, u32 size)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	int i;

	for (i = 0; i < gmu->num_vmas; i++) {
		struct gmu_vma_entry *vma = &gmu->vma[i];

		if ((addr >= vma->start) &&
			((addr + size) <= (vma->start + vma->size)))
			return i;
	}

	return -ENOENT;
}

void gmu_core_free_globals(struct kgsl_device *device)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	int i;

	for (i = 0; i < gmu->global_entries && i < ARRAY_SIZE(gmu->gmu_globals); i++) {
		struct kgsl_memdesc *md = &gmu->gmu_globals[i];

		if (!md->gmuaddr)
			continue;

		iommu_unmap(gmu->domain, md->gmuaddr, md->size);

		if (TEST_FLAG(KGSL_MEMDESC_SYSMEM, &md->priv))
			kgsl_sharedmem_free(md);

		memset(md, 0, sizeof(*md));
	}

	if (gmu->domain) {
		kgsl_detach_iommu_group(gmu->domain, gmu->group);
		iommu_domain_free(gmu->domain);
		gmu->domain = NULL;
	}

	gmu->global_entries = 0;
}

static struct gmu_vma_node *find_va(struct gmu_vma_entry *vma, u32 addr, u32 size)
{
	struct rb_node *node = vma->vma_root.rb_node;

	while (node != NULL) {
		struct gmu_vma_node *data = rb_entry(node, struct gmu_vma_node, node);

		if (addr + size <= data->va)
			node = node->rb_left;
		else if (addr >= data->va + data->size)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

/* Return true if VMA supports dynamic allocations */
static bool vma_is_dynamic(struct kgsl_device *device, int vma_id)
{
	/* Dynamic allocations are done in the GMU_NONCACHED_KERNEL space */
	return (vma_id == GMU_NONCACHED_KERNEL) && (!adreno_is_a6xx(ADRENO_DEVICE(device)));
}

static int insert_va(struct gmu_vma_entry *vma, u32 addr, u32 size)
{
	struct rb_node **node, *parent = NULL;
	struct gmu_vma_node *new = kzalloc(sizeof(*new), GFP_NOWAIT);

	if (new == NULL)
		return -ENOMEM;

	new->va = addr;
	new->size = size;

	node = &vma->vma_root.rb_node;
	while (*node != NULL) {
		struct gmu_vma_node *this;

		parent = *node;
		this = rb_entry(parent, struct gmu_vma_node, node);

		if (addr + size <= this->va)
			node = &parent->rb_left;
		else if (addr >= this->va + this->size)
			node = &parent->rb_right;
		else {
			kfree(new);
			return -EEXIST;
		}
	}

	/* Add new node and rebalance tree */
	rb_link_node(&new->node, parent, node);
	rb_insert_color(&new->node, &vma->vma_root);

	return 0;
}

static u32 find_unmapped_va(struct gmu_vma_entry *vma, u32 size, u32 va_align)
{
	struct rb_node *node = rb_first(&vma->vma_root);
	u32 cur = vma->start;
	bool found = false;

	cur = ALIGN(cur, va_align);

	while (node) {
		struct gmu_vma_node *data = rb_entry(node, struct gmu_vma_node, node);

		if (cur + size <= data->va) {
			found = true;
			break;
		}

		cur = ALIGN(data->va + data->size, va_align);
		node = rb_next(node);
	}

	/* Do we have space after the last node? */
	if (!found && (cur + size <= vma->start + vma->size))
		found = true;
	return found ? cur : 0;
}

static int _map_gmu_dynamic(struct kgsl_device *device, struct kgsl_memdesc *md,
	u32 addr, u32 vma_id, int attrs, u32 align)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	struct device *gmu_pdev_dev = GMU_PDEV_DEV(device);
	struct gmu_vma_entry *vma = &gmu->vma[vma_id];
	struct gmu_vma_node *vma_node = NULL;
	int ret;
	u32 size = ALIGN(md->size, hfi_get_gmu_sz_alignment(align));

	spin_lock(&vma->lock);
	if (!addr) {
		/*
		 * We will end up with a hole (GMU VA range not backed by physical mapping) if
		 * the aligned size is greater than the size of the physical mapping
		 */
		addr = find_unmapped_va(vma, size, hfi_get_gmu_va_alignment(align));
		if (addr == 0) {
			spin_unlock(&vma->lock);
			dev_err(gmu_pdev_dev,
				"Insufficient VA space size: %x\n", size);
			return -ENOMEM;
		}
	}

	ret = insert_va(vma, addr, size);
	spin_unlock(&vma->lock);
	if (ret < 0) {
		dev_err(gmu_pdev_dev,
			"Could not insert va: %x size %x\n", addr, size);
		return ret;
	}

	ret = gmu_core_map_memdesc(gmu->domain, md, addr, attrs);
	if (!ret) {
		md->gmuaddr = addr;
		return 0;
	}

	/* Failed to map to GMU */
	dev_err(gmu_pdev_dev,
		"Unable to map GMU kernel block: addr:0x%08x size:0x%llx :%d\n",
		addr, md->size, ret);

	spin_lock(&vma->lock);
	vma_node = find_va(vma, md->gmuaddr, size);
	if (vma_node)
		rb_erase(&vma_node->node, &vma->vma_root);
	spin_unlock(&vma->lock);
	kfree(vma_node);

	return ret;
}

static int _map_gmu_static(struct kgsl_device *device, struct kgsl_memdesc *md,
	u32 addr, u32 vma_id, int attrs, u32 align)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	struct gmu_vma_entry *vma = &gmu->vma[vma_id];
	int ret;
	u32 size = ALIGN(md->size, hfi_get_gmu_sz_alignment(align));

	if (!addr)
		addr = ALIGN(vma->next_va, hfi_get_gmu_va_alignment(align));

	ret = gmu_core_map_memdesc(device->gmu_core.domain, md, addr, attrs);
	if (ret) {
		dev_err(GMU_PDEV_DEV(device),
			"Unable to map GMU kernel block: addr:0x%08x size:0x%llx :%d\n",
			addr, md->size, ret);
		return ret;
	}
	md->gmuaddr = addr;
	/*
	 * We will end up with a hole (GMU VA range not backed by physical mapping) if the aligned
	 * size is greater than the size of the physical mapping
	 */
	vma->next_va = md->gmuaddr + size;
	return 0;
}

int gmu_core_reserve_gmuaddr(struct kgsl_device *device, struct kgsl_memdesc *md, u32 vma_id,
	u32 align)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	struct gmu_vma_entry *vma = &gmu->vma[vma_id];
	u32 addr, size = ALIGN(md->size, hfi_get_gmu_sz_alignment(align));

	if (vma_is_dynamic(device, vma_id)) {
		spin_lock(&vma->lock);
		addr = find_unmapped_va(vma, size, hfi_get_gmu_va_alignment(align));
		spin_unlock(&vma->lock);
		if (addr == 0)
			goto error;
	} else {
		addr = ALIGN(vma->next_va, hfi_get_gmu_va_alignment(align));
		if ((addr + size) >= (vma->start + vma->size))
			goto error;
		vma->next_va = addr + size;
	}

	md->gmuaddr = addr;

	return 0;

error:
	dev_err_ratelimited(GMU_PDEV_DEV(device),
		"Insufficient VA space size: %x in vma:%u\n", size, vma_id);
	return -ENOMEM;
}

int gmu_core_map_gmu(struct kgsl_device *device, struct kgsl_memdesc *md,
	u32 addr, u32 vma_id, int attrs, u32 align)
{
	return vma_is_dynamic(device, vma_id) ?
			_map_gmu_dynamic(device, md, addr, vma_id, attrs, align) :
			_map_gmu_static(device, md, addr, vma_id, attrs, align);
}

int gmu_core_get_attrs(u32 flags)
{
	int attrs = IOMMU_READ;

	if (flags & HFI_MEMFLAG_GMU_PRIV)
		attrs |= IOMMU_PRIV;

	if (flags & HFI_MEMFLAG_GMU_WRITEABLE)
		attrs |= IOMMU_WRITE;

	return attrs;
}

int gmu_core_import_buffer(struct kgsl_device *device, struct hfi_mem_alloc_entry *entry)
{
	struct hfi_mem_alloc_desc *desc = &entry->desc;
	u32 attrs = gmu_core_get_attrs(desc->flags);
	u32 vma_id = (desc->flags & HFI_MEMFLAG_GMU_CACHEABLE) ? GMU_CACHE : GMU_NONCACHED_KERNEL;

	/*
	 * GMU Tx/Rx queues are mapped as I/O-coherent on both SOCCP and CPU,
	 * mark the buffer I/O-coherent on GMU side as well to prevent stale
	 * data and immediate updates in DDR.
	 */
	if (desc->mem_kind == HFI_MEMKIND_HW_FENCE &&
		kgsl_mmu_has_feature(device, KGSL_MMU_IO_COHERENT)) {
		entry->md->flags |= KGSL_MEMFLAGS_IOCOHERENT;
		attrs |= IOMMU_CACHE;
	}

	return gmu_core_map_gmu(device, entry->md, 0, vma_id, attrs, desc->align);
}

struct kgsl_memdesc *gmu_core_reserve_kernel_block(struct kgsl_device *device,
	u32 addr, u32 size, u32 vma_id, u32 align)
{
	int ret;
	u64 memflags = 0;
	struct kgsl_memdesc *md;
	struct gmu_core_device *gmu = &device->gmu_core;
	int attrs = IOMMU_READ | IOMMU_WRITE | IOMMU_PRIV;
	struct adreno_device *adreno_dev = ADRENO_DEVICE(device);

	if (gmu->global_entries == ARRAY_SIZE(gmu->gmu_globals))
		return ERR_PTR(-ENOMEM);

	md = &gmu->gmu_globals[gmu->global_entries];

	/*
	 * Apply WB cache policy to fetch GMU FW successfully for A622.
	 * A622 has specific cache coherency requirements that can lead to data
	 * inconsistency if not using writeback cache policy.
	 */
	if (adreno_is_a622(adreno_dev))
		memflags = FIELD_PREP(KGSL_CACHEMODE_MASK, KGSL_CACHEMODE_WRITEBACK);

	ret = kgsl_allocate_kernel(device, md, size, memflags, KGSL_MEMDESC_SYSMEM);
	if (ret) {
		memset(md, 0x0, sizeof(*md));
		return ERR_PTR(-ENOMEM);
	}

	ret = gmu_core_map_gmu(device, md, addr, vma_id, attrs, align);
	if (ret) {
		kgsl_sharedmem_free(md);
		memset(md, 0x0, sizeof(*md));
		return ERR_PTR(ret);
	}

	gmu->global_entries++;

	return md;
}

struct kgsl_memdesc *gmu_core_reserve_kernel_block_fixed(struct kgsl_device *device,
	u32 addr, u32 size, u32 vma_id, const char *resource, int attrs, u32 align)
{
	int ret;
	struct kgsl_memdesc *md;
	struct gmu_core_device *gmu = &device->gmu_core;

	if (gmu->global_entries == ARRAY_SIZE(gmu->gmu_globals))
		return ERR_PTR(-ENOMEM);

	md = &gmu->gmu_globals[gmu->global_entries];

	ret = kgsl_memdesc_init_fixed(device, GMU_PDEV(device), resource, md);
	if (ret)
		return ERR_PTR(ret);

	ret = gmu_core_map_gmu(device, md, addr, vma_id, attrs, align);

	sg_free_table(md->sgt);
	kfree(md->sgt);
	md->sgt = NULL;

	if (!ret) {
		gmu->global_entries++;
	} else {
		dev_err(GMU_PDEV_DEV(device),
			"Unable to map GMU kernel block: addr:0x%08x size:0x%llx :%d\n",
			addr, md->size, ret);
		memset(md, 0x0, sizeof(*md));
		md = ERR_PTR(ret);
	}
	return md;
}

int gmu_core_alloc_kernel_block(struct kgsl_device *device,
	struct kgsl_memdesc *md, u32 size, u32 vma_id, int attrs)
{
	int ret;

	ret = kgsl_allocate_kernel(device, md, size, 0, KGSL_MEMDESC_SYSMEM);
	if (ret)
		return ret;

	ret = gmu_core_map_gmu(device, md, 0, vma_id, attrs, 0);
	if (ret)
		kgsl_sharedmem_free(md);

	return ret;
}

void gmu_core_free_block(struct kgsl_device *device, struct kgsl_memdesc *md)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	int vma_id = gmu_core_find_vma_block(device, md->gmuaddr, md->size);
	struct gmu_vma_entry *vma;
	struct gmu_vma_node *vma_node;

	if ((vma_id < 0) || !vma_is_dynamic(device, vma_id))
		return;

	vma = &gmu->vma[vma_id];

	/*
	 * Do not remove the vma node if we failed to unmap the entire buffer. This is because the
	 * iommu driver considers remapping an already mapped iova as fatal.
	 */
	if (md->size != iommu_unmap(device->gmu_core.domain, md->gmuaddr, md->size))
		goto free;

	spin_lock(&vma->lock);
	vma_node = find_va(vma, md->gmuaddr, md->size);
	if (vma_node)
		rb_erase(&vma_node->node, &vma->vma_root);
	spin_unlock(&vma->lock);
	kfree(vma_node);
free:
	kgsl_sharedmem_free(md);
}

int gmu_core_process_prealloc(struct kgsl_device *device, struct gmu_block_header *blk)
{
	struct kgsl_memdesc *md;
	int id = gmu_core_find_vma_block(device, blk->addr, blk->value);

	if (id < 0) {
		dev_err(GMU_PDEV_DEV(device),
			"Invalid prealloc block addr: 0x%x value:%d\n",
			blk->addr, blk->value);
		return id;
	}

	/* Nothing to do for TCM blocks or user uncached */
	if (id == GMU_ITCM || id == GMU_DTCM || id == GMU_NONCACHED_USER)
		return 0;

	/* Check if the block is already allocated */
	md = gmu_core_find_memdesc(device, blk->addr, blk->value);
	if (md != NULL)
		return 0;

	md = gmu_core_reserve_kernel_block(device, blk->addr, blk->value, id, 0);

	return PTR_ERR_OR_ZERO(md);
}

static int gmu_core_iommu_fault_handler(struct iommu_domain *domain,
		struct device *dev, unsigned long addr, int flags, void *token)
{
	char *fault_type = "unknown";

	if (flags & IOMMU_FAULT_TRANSLATION)
		fault_type = "translation";
	else if (flags & IOMMU_FAULT_PERMISSION)
		fault_type = "permission";
	else if (flags & IOMMU_FAULT_EXTERNAL)
		fault_type = "external";
	else if (flags & IOMMU_FAULT_TRANSACTION_STALLED)
		fault_type = "transaction stalled";

	dev_err(dev, "GMU fault addr = %lX, context=kernel (%s %s fault)\n",
			addr, (flags & IOMMU_FAULT_WRITE) ? "write" : "read", fault_type);

	return 0;
}

#if (KERNEL_VERSION(6, 13, 0) <= LINUX_VERSION_CODE)
static struct iommu_domain *gmu_core_iommu_domain_alloc(struct device *dev)
{
	return iommu_paging_domain_alloc(dev);
}
#else
#include <linux/platform_device.h>
static struct iommu_domain *gmu_core_iommu_domain_alloc(struct device *dev)
{
	return iommu_domain_alloc(&platform_bus_type);
}
#endif

int gmu_core_iommu_init(struct kgsl_device *device)
{
	struct device *gmu_pdev_dev = GMU_PDEV_DEV(device);
	int ret;

	device->gmu_core.domain = gmu_core_iommu_domain_alloc(gmu_pdev_dev);
	if (!device->gmu_core.domain) {
		dev_err(gmu_pdev_dev, "Unable to allocate GMU IOMMU domain\n");
		return -ENODEV;
	}

	/*
	 * Disable stall on fault for the GMU context bank.
	 * This sets SCTLR.CFCFG = 0.
	 * Also note that, the smmu driver sets SCTLR.HUPCF = 0 by default.
	 */
	qcom_iommu_set_fault_model(device->gmu_core.domain,
		QCOM_IOMMU_FAULT_MODEL_NO_STALL);

	ret = kgsl_attach_iommu_group(gmu_pdev_dev, device->gmu_core.domain,
			&device->gmu_core.group);
	if (!ret) {
		iommu_set_fault_handler(device->gmu_core.domain,
			gmu_core_iommu_fault_handler, device);
		return 0;
	}

	dev_err(gmu_pdev_dev, "Unable to attach GMU IOMMU domain: %d\n", ret);
	iommu_domain_free(device->gmu_core.domain);
	device->gmu_core.domain = NULL;

	return ret;
}

void gmu_core_dev_force_first_boot(struct kgsl_device *device)
{
	const struct gmu_dev_ops *ops = GMU_DEVICE_OPS(device);

	if (ops && ops->force_first_boot)
		return ops->force_first_boot(device);
}

int gmu_core_set_vrb_register(struct kgsl_memdesc *vrb, u32 index, u32 val)
{
	u32 *vrb_buf;

	if (WARN_ON(IS_ERR_OR_NULL(vrb)))
		return -ENODEV;

	if (WARN_ON(index >= (vrb->size >> 2))) {
		pr_err("kgsl: Unable to set VRB register for index %u\n", index);
		return -EINVAL;
	}

	vrb_buf = vrb->hostptr;
	vrb_buf[index] = val;

	/* Make sure the vrb write is posted before moving ahead */
	wmb();

	return 0;
}

int gmu_core_get_vrb_register(struct kgsl_memdesc *vrb, u32 index, u32 *val)
{
	u32 *vrb_buf;

	if (IS_ERR_OR_NULL(vrb))
		return -ENODEV;

	if (WARN_ON(index >= (vrb->size >> 2))) {
		pr_err("kgsl: Unable to get VRB register for index %u\n", index);
		return -EINVAL;
	}

	vrb_buf = vrb->hostptr;
	*val = vrb_buf[index];

	return 0;
}

static void _gmu_trace_dcvs_pwrlevel(struct kgsl_device *device, struct gmu_trace_packet *pkt)
{
	struct trace_dcvs_pwrlvl *data = (struct trace_dcvs_pwrlvl *)pkt->payload;
	struct kgsl_pwrctrl *pwr = &device->pwrctrl;

	/*
	 * After a slumber, gmu will have the previous power level as num_pwrlevels.
	 * Set the previous power level as the current level for the trace to be
	 * accurate.
	 */
	if (data->prev_pwrlvl == pwr->num_pwrlevels)
		data->prev_pwrlvl = pwr->active_pwrlevel;

	if (pwr->active_pwrlevel != data->new_pwrlvl) {
		u32 penalty = FIELD_PREP(GENMASK(31, 16), data->penalty_down) |
				FIELD_PREP(GENMASK(15, 0), data->penalty_up);
		u32 step_down_cnt = FIELD_PREP(GENMASK(31, 16), data->subsequent_step_down_count) |
				FIELD_PREP(GENMASK(15, 0), data->first_step_down_count);
		u32 freq_cap = FIELD_PREP(GENMASK(31, 16), data->max_freq) |
				FIELD_PREP(GENMASK(15, 0), data->min_freq);
		u32 num_samples = FIELD_PREP(GENMASK(31, 16), data->num_samples_down) |
				FIELD_PREP(GENMASK(15, 0), data->num_samples_up);

		trace_kgsl_pwrlevel(device, data->new_pwrlvl,
					pwr->pwrlevels[data->new_pwrlvl].gpu_freq,
					data->prev_pwrlvl,
					pwr->pwrlevels[data->prev_pwrlvl].gpu_freq,
					pkt->ticks);
		KGSL_TRACE_GPU_FREQ(pwr->pwrlevels[data->new_pwrlvl].gpu_freq/1000,
					0, pkt->ticks);

		trace_adreno_gpu_vote_params(data->new_pwrlvl, data->prev_pwrlvl,
				data->avg_busy, data->flag, penalty, step_down_cnt, freq_cap,
				num_samples, data->target_fps, data->mod_percent, pkt->ticks);
	}

	pwr->active_pwrlevel = data->new_pwrlvl;
	pwr->previous_pwrlevel = data->prev_pwrlvl;
}

static void _gmu_trace_dcvs_buslevel(struct kgsl_device *device, struct gmu_trace_packet *pkt)
{
	struct trace_dcvs_buslvl *data = (struct trace_dcvs_buslvl *)pkt->payload;
	struct kgsl_pwrctrl *pwr = &device->pwrctrl;

	trace_kgsl_buslevel(device, data->gpu_pwrlvl, data->buslvl,
				data->cur_abmbps, pkt->ticks);

	pwr->cur_dcvs_buslevel = data->buslvl;
	pwr->bus_ab_mbytes = data->cur_abmbps;
}

static void _gmu_trace_dcvs_pwrstats(struct kgsl_device *device, struct gmu_trace_packet *pkt)
{
	struct trace_dcvs_pwrstats *data = (struct trace_dcvs_pwrstats *)pkt->payload;
	struct kgsl_pwrctrl *pwr = &device->pwrctrl;
	struct kgsl_power_stats stats;

	kgsl_pwrctrl_busy_time(device, data->total_time, data->gpu_time, pkt->ticks);

	stats.busy_time = data->gpu_time;
	stats.ram_time = data->ram_time;
	stats.ram_wait = data->ram_wait;
	trace_kgsl_pwrstats(device, data->total_time, &stats,
				device->active_context_count, pkt->ticks);

	pwr->clock_times[pwr->active_pwrlevel] += data->gpu_time;
	pwr->time_in_pwrlevel[pwr->active_pwrlevel] += data->total_time;
	if (pwr->thermal_pwrlevel)
		pwr->thermal_time += data->gpu_time;

	pwr->aggr_max_pwrlevel = data->aggr_max_pwrlevel;

	spin_lock(&pwr->stats_lock);
	pwr->accum_busy_stats += data->gpu_time;
	pwr->accum_total_time += data->total_time;
	spin_unlock(&pwr->stats_lock);
}

static void stream_trace_data(struct kgsl_device *device, struct gmu_trace_packet *pkt)
{
	switch (pkt->trace_id) {
	case GMU_TRACE_PREEMPT_TRIGGER: {
		struct trace_preempt_trigger *data =
				(struct trace_preempt_trigger *)pkt->payload;

		trace_adreno_preempt_trigger(data->cur_rb, data->next_rb,
			data->ctx_switch_cntl, pkt->ticks);
		break;
		}
	case GMU_TRACE_PREEMPT_DONE: {
		struct trace_preempt_done *data =
				(struct trace_preempt_done *)pkt->payload;

		trace_adreno_preempt_done(data->prev_rb, data->next_rb,
			data->ctx_switch_cntl, pkt->ticks);
		break;
		}
	case GMU_TRACE_EXTERNAL_HW_FENCE_SIGNAL: {
		struct trace_ext_hw_fence_signal *data =
				(struct trace_ext_hw_fence_signal *)pkt->payload;

		trace_adreno_ext_hw_fence_signal(data->context, data->seq_no,
			data->flags, pkt->ticks);
		break;
		}
	case GMU_TRACE_SYNCOBJ_RETIRE: {
		struct trace_syncobj_retire *data =
				(struct trace_syncobj_retire *)pkt->payload;

		trace_adreno_syncobj_retired(data->gmu_ctxt_id, data->timestamp, pkt->ticks);
		break;
		}
	case GMU_TRACE_DCVS_PWRLVL: {
		_gmu_trace_dcvs_pwrlevel(device, pkt);
		break;
		}
	case GMU_TRACE_DCVS_BUSLVL: {
		_gmu_trace_dcvs_buslevel(device, pkt);
		break;
		}
	case GMU_TRACE_DCVS_PWRSTATS: {
		_gmu_trace_dcvs_pwrstats(device, pkt);
		break;
		}
	case GMU_TRACE_PWR_CONSTRAINT: {
		struct trace_pwr_constraint *data =
			(struct trace_pwr_constraint *)pkt->payload;

		trace_kgsl_constraint(device, data->type, data->value, data->status, pkt->ticks);
		break;
		}
	case GMU_TRACE_DCVS_PROFILE: {
		struct trace_dcvs_profile *data =
				(struct trace_dcvs_profile *)pkt->payload;
		trace_adreno_gpu_dcvs_profile(data, pkt->ticks);
		break;
		}
	default: {
		char str[64];

		snprintf(str, sizeof(str),
			 "Unsupported GMU trace id %d\n", pkt->trace_id);
		trace_kgsl_msg(str);
		}
	}
}

void gmu_core_process_trace_data(struct kgsl_device *device,
	struct device *dev, struct kgsl_gmu_trace *trace)
{
	struct gmu_trace_header *trace_hdr;
	u32 size, *buffer;
	struct gmu_trace_packet *pkt;
	u16 seq_num, num_pkts = 0;
	u32 ridx, widx;

	if (IS_ERR_OR_NULL(trace->md))
		return;

	trace_hdr = trace->md->hostptr;
	buffer = trace->md->hostptr;

	ridx = readl(&trace_hdr->read_index);
	widx = readl(&trace_hdr->write_index);

	if (ridx == widx)
		return;

	/*
	 * Don't process any traces and force set read_index to write_index if
	 * previously encountered invalid trace packet
	 */
	if (trace->reset_hdr) {
		/* update read index to let f2h daemon to go to sleep */
		writel(trace_hdr->write_index, &trace_hdr->read_index);
		return;
	}

	/* start reading trace buffer data */
	pkt = (struct gmu_trace_packet *)&buffer[trace_hdr->payload_offset + ridx];

	/* Validate packet header */
	if (TRACE_PKT_GET_VALID_FIELD(pkt->hdr) != TRACE_PKT_VALID) {
		char str[128];

		snprintf(str, sizeof(str),
			"Invalid trace packet found at read index: %d resetting trace header\n",
			trace_hdr->read_index);
		/*
		 * GMU is not expected to write an invalid trace packet. This
		 * condition can be true in case there is memory corruption. In
		 * such scenario fastforward readindex to writeindex so the we
		 * don't process any trace packets until we reset the trace
		 * header in next slumber exit.
		 */
		dev_err_ratelimited(device->dev, "%s\n", str);
		trace_kgsl_msg(str);
		writel(trace_hdr->write_index, &trace_hdr->read_index);
		trace->reset_hdr = true;
		return;
	}

	size = TRACE_PKT_GET_SIZE(pkt->hdr);

	if (TRACE_PKT_GET_SKIP_FIELD(pkt->hdr))
		goto done;

	seq_num = TRACE_PKT_GET_SEQNUM(pkt->hdr);
	num_pkts = seq_num - trace->seq_num;

	/* Detect trace packet loss by tracking any gaps in the sequence number */
	if (num_pkts > 1) {
		char str[128];

		snprintf(str, sizeof(str),
			"%d GMU trace packets dropped from sequence number: %d\n",
			num_pkts - 1, trace->seq_num);
		trace_kgsl_msg(str);
	}

	trace->seq_num = seq_num;
	stream_trace_data(device, pkt);
done:
	ridx = (ridx + size) % trace_hdr->payload_size;
	writel(ridx, &trace_hdr->read_index);
}

bool gmu_core_is_trace_empty(struct gmu_trace_header *hdr)
{
	return (readl(&hdr->read_index) == readl(&hdr->write_index)) ? true : false;
}

void gmu_core_trace_header_init(struct kgsl_gmu_trace *trace)
{
	struct gmu_trace_header *hdr = trace->md->hostptr;

	hdr->threshold = TRACE_BUFFER_THRESHOLD;
	hdr->timeout = TRACE_TIMEOUT_MSEC;
	hdr->metadata = FIELD_PREP(GENMASK(31, 30), TRACE_MODE_DROP) |
			FIELD_PREP(GENMASK(3, 0), TRACE_HEADER_VERSION_1);
	hdr->cookie = trace->md->gmuaddr;
	hdr->size = trace->md->size;
	hdr->log_type = TRACE_LOGTYPE_HWSCHED;
}

void gmu_core_reset_trace_header(struct kgsl_gmu_trace *trace)
{
	if (!trace->reset_hdr || IS_ERR_OR_NULL(trace->md))
		return;

	memset(trace->md->hostptr, 0, sizeof(struct gmu_trace_header));
	/* Reset sequence number to detect trace packet loss */
	trace->seq_num = 0;
	gmu_core_trace_header_init(trace);
	trace->reset_hdr = false;
}

int gmu_core_soccp_vote(struct kgsl_device *device, bool pwr_on)
{
	int ret;

	if (!(test_bit(GMU_SOCCP_VOTE_ON, &device->gmu_core.flags) ^ pwr_on))
		return 0;

	ret = kgsl_hw_fence_soccp_vote(pwr_on);
	if (!ret) {
		change_bit(GMU_SOCCP_VOTE_ON, &device->gmu_core.flags);
		return 0;
	}

	dev_err(GMU_PDEV_DEV(device), "soccp power %s failed: %d. Disabling hw fences\n",
		pwr_on ? "on" : "off", ret);

	return ret;
}

bool gmu_core_capabilities_enabled(struct firmware_capabilities *caps, u32 field)
{
	if (!caps->length || !caps->data)
		return false;

	/* Capabilities payload data stored in 1 byte */
	if (caps->data[field / BITS_PER_BYTE] & BIT(field % BITS_PER_BYTE))
		return true;

	return false;
}

void gmu_core_mark_for_coldboot(struct kgsl_device *device)
{
	struct gmu_core_device *gmu_core = &device->gmu_core;

	if (!gmu_core->warmboot_enabled)
		return;

	set_bit(GMU_FORCE_COLDBOOT, &gmu_core->flags);
}

void gmu_core_rdpm_probe(struct kgsl_device *device)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	struct resource *res;

	res = platform_get_resource_byname(device->pdev, IORESOURCE_MEM, "rdpm_cx");
	if (res)
		gmu->rdpm_cx_virt = devm_ioremap(&device->pdev->dev,
				res->start, resource_size(res));

	res = platform_get_resource_byname(device->pdev, IORESOURCE_MEM, "rdpm_mx");
	if (res)
		gmu->rdpm_mx_virt = devm_ioremap(&device->pdev->dev,
				res->start, resource_size(res));
}

void gmu_core_rdpm_mx_freq_update(struct kgsl_device *device, u32 freq)
{
	struct gmu_core_device *gmu = &device->gmu_core;

	if (!gmu->rdpm_mx_virt)
		return;

	writel_relaxed(freq / 1000, (gmu->rdpm_mx_virt + gmu->rdpm_mx_offset));

	/* Ensure previous writes post before this one, i.e. act like normal writel() */
	wmb();
}

void gmu_core_rdpm_cx_freq_update(struct kgsl_device *device, u32 freq)
{
	struct gmu_core_device *gmu = &device->gmu_core;

	if (!gmu->rdpm_cx_virt)
		return;

	writel_relaxed(freq / 1000, (gmu->rdpm_cx_virt + gmu->rdpm_cx_offset));

	/* Ensure previous writes post before this one, i.e. act like normal writel() */
	wmb();
}

static void build_hub_opp_table(struct kgsl_device *device)
{
	struct adreno_device *adreno_dev = ADRENO_DEVICE(device);
	struct gmu_core_device *gmu = &device->gmu_core;
	struct device_node *opp_table, *opp;
	int i = 0;

	opp_table = of_find_node_by_name(NULL, "hub_opp_table");
	if (!opp_table)
		goto err;

	for_each_child_of_node(opp_table, opp) {
		if (of_property_read_u64(opp, "opp-hz", (u64 *)&gmu->hub_freqs[i]))
			goto err;

		if (of_property_read_u32(opp, "opp-level", &gmu->hub_vlvls[i]))
			goto err;

		i++;
	}

	gmu->num_hub_freqs = i;
	of_node_put(opp_table);
	return;

err:
	if (opp_table)
		of_node_put(opp_table);

	gmu->hub_freqs[0] = adreno_dev->gmu_hub_clk_freq;
	gmu->num_hub_freqs = 1;
}

#define GMU_FREQ_MIN   200000000
#define GMU_FREQ_MAX   500000000

int gmu_core_clk_probe(struct kgsl_device *device)
{
	struct adreno_device *adreno_dev = ADRENO_DEVICE(device);
	struct platform_device *gmu_pdev = GMU_PDEV(device);
	struct gmu_core_device *gmu = &device->gmu_core;
	int tbl_size, num_freqs, num_perf_ddr_bw, offset, ret, i;

	build_hub_opp_table(device);

	ret = devm_clk_bulk_get_all(GMU_PDEV_DEV(device), &gmu->clks);
	if (ret < 0)
		return ret;

	/*
	 * Voting for apb_pclk will enable power and clocks required for
	 * QDSS path to function. However, if QCOM_KGSL_QDSS_STM is not enabled,
	 * QDSS is essentially unusable. Hence, if QDSS cannot be used,
	 * don't vote for this clock.
	 */
	if (!IS_ENABLED(CONFIG_QCOM_KGSL_QDSS_STM)) {
		for (i = 0; i < ret; i++) {
			if (!strcmp(gmu->clks[i].id, "apb_pclk")) {
				gmu->clks[i].clk = NULL;
				break;
			}
		}
	}

	gmu->num_clks = ret;

	if (of_get_property(gmu_pdev->dev.of_node,
		"qcom,gmu-perf-ddr-bw", &tbl_size) == NULL)
		goto read_gmu_freq;

	num_perf_ddr_bw = (tbl_size / sizeof(u32));
	if (num_perf_ddr_bw >= ARRAY_SIZE(gmu->perf_ddr_bw))
		goto read_gmu_freq;

	for (i = 0; i < num_perf_ddr_bw; i++) {
		ret = of_property_read_u32_index(gmu_pdev->dev.of_node,
			"qcom,gmu-perf-ddr-bw", i, &gmu->perf_ddr_bw[i]);
		if (ret)
			goto read_gmu_freq;
	}

read_gmu_freq:
	/* Read the optional list of GMU frequencies */
	if (of_get_property(gmu_pdev->dev.of_node,
		"qcom,gmu-freq-table", &tbl_size) == NULL)
		goto default_gmu_freq;

	num_freqs = (tbl_size / sizeof(u32)) / 2;
	if (num_freqs >= ARRAY_SIZE(gmu->freqs))
		goto default_gmu_freq;

	for (i = 0; i < num_freqs; i++) {
		offset = i * 2;
		ret = of_property_read_u32_index(gmu_pdev->dev.of_node,
			"qcom,gmu-freq-table", offset, &gmu->freqs[i]);
		if (ret)
			goto default_gmu_freq;
		ret = of_property_read_u32_index(gmu_pdev->dev.of_node,
			"qcom,gmu-freq-table", offset + 1, &gmu->vlvls[i]);
		if (ret)
			goto default_gmu_freq;
	}

	gmu->num_freqs = num_freqs;

	return 0;

default_gmu_freq:
	/* The GMU frequency table is missing or invalid. Go with a default */
	gmu->freqs[0] = GMU_FREQ_MIN;
	gmu->vlvls[0] = RPMH_REGULATOR_LEVEL_LOW_SVS;
	gmu->freqs[1] = GMU_FREQ_MAX;
	gmu->vlvls[1] = RPMH_REGULATOR_LEVEL_SVS;

	gmu->num_freqs = 2;

	if (adreno_is_a6xx(adreno_dev) && !adreno_is_a660(adreno_dev))
		gmu->vlvls[0] = RPMH_REGULATOR_LEVEL_MIN_SVS;

	return 0;
}

static int scale_hub_clock(struct kgsl_device *device, u32 cx_voltage)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	int ret, i;

	for (i = 0; i < gmu->num_hub_freqs; i++) {
		if (gmu->hub_vlvls[i] <= cx_voltage)
			break;
	}

	/* Default to minimum hub frequency if no match found */
	if (i == gmu->num_hub_freqs)
		i = gmu->num_hub_freqs - 1;

	if (i == gmu->cur_hub_level)
		return 0;

	ret = kgsl_clk_set_rate(gmu->clks, gmu->num_clks, "hub_clk", gmu->hub_freqs[i]);
	if (ret && ret != -ENODEV) {
		dev_err(GMU_PDEV_DEV(device), "Unable to set the HUB clock ret %d\n", ret);
		return ret;
	}

	gmu->cur_hub_level = i;
	return 0;
}

int gmu_core_clock_set_rate(struct kgsl_device *device, u32 gmu_level)
{
	struct gmu_core_device *gmu_core = &device->gmu_core;
	int ret;
	u32 req_freq = gmu_core->freqs[gmu_level];

	gmu_core_rdpm_cx_freq_update(device, req_freq / 1000);

	ret = kgsl_clk_set_rate(gmu_core->clks, gmu_core->num_clks, "gmu_clk", req_freq);
	if (ret) {
		dev_err(GMU_PDEV_DEV(device), "GMU clock:%d set failed:%d\n", req_freq, ret);
		return ret;
	}

	trace_kgsl_gmu_pwrlevel(req_freq, gmu_core->freqs[gmu_core->cur_level]);

	gmu_core->cur_level = gmu_level;

	return scale_hub_clock(device, gmu_core->vlvls[gmu_level]);
}

int gmu_core_enable_clks(struct kgsl_device *device, u32 level)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	int ret;

	/* Reset hub clock level */
	gmu->cur_hub_level = gmu->num_hub_freqs;

	ret = gmu_core_clock_set_rate(device, level);
	if (ret)
		return ret;

	ret = clk_bulk_prepare_enable(gmu->num_clks, gmu->clks);
	if (ret) {
		dev_err(GMU_PDEV_DEV(device), "Cannot enable GMU clocks ret %d\n", ret);
		return ret;
	}

	device->state = KGSL_STATE_AWARE;

	return 0;
}

void gmu_core_disable_clks(struct kgsl_device *device)
{
	struct gmu_core_device *gmu = &device->gmu_core;

	clk_bulk_disable_unprepare(gmu->num_clks, gmu->clks);
}

void gmu_core_scale_gmu_frequency(struct kgsl_device *device, int buslevel)
{
	struct gmu_core_device *gmu = &device->gmu_core;
	struct kgsl_pwrctrl *pwr = &device->pwrctrl;
	u32 i, gmu_level = 0;

	if (!gmu->perf_ddr_bw[0])
		return;

	/* Check if IB threshold has been breached to scale gmu */
	for (i = 0; i < MAX_CX_LEVELS; i++) {
		if ((pwr->ddr_table[buslevel] >= gmu->perf_ddr_bw[i]) && (gmu->perf_ddr_bw[i] != 0))
			gmu_level = (i + 1);
	}

	if ((gmu_level < MAX_CX_LEVELS) && (gmu->cur_level != gmu_level))
		gmu_core_clock_set_rate(device, gmu_level);

}

int gmu_core_hwsched_memory_init(struct kgsl_device *device)
{
	int ret;

	/* GMU Virtual register bank */
	if (IS_ERR_OR_NULL(device->gmu_core.vrb)) {
		device->gmu_core.vrb = gmu_core_reserve_kernel_block(device, 0, GMU_VRB_SIZE,
				GMU_NONCACHED_KERNEL, 0);

		if (IS_ERR(device->gmu_core.vrb))
			return PTR_ERR(device->gmu_core.vrb);

		/* Populate size of the virtual register bank */
		ret = gmu_core_set_vrb_register(device->gmu_core.vrb, VRB_SIZE_IDX,
					device->gmu_core.vrb->size >> 2);
		if (ret)
			return ret;
	}

	/* GMU trace log */
	if (IS_ERR_OR_NULL(device->gmu_core.trace.md)) {
		device->gmu_core.trace.md = gmu_core_reserve_kernel_block(device, 0,
					GMU_TRACE_SIZE, GMU_NONCACHED_KERNEL, 0);

		if (IS_ERR(device->gmu_core.trace.md))
			return PTR_ERR(device->gmu_core.trace.md);

		/* Pass trace buffer address to GMU through the VRB */
		ret = gmu_core_set_vrb_register(device->gmu_core.vrb, VRB_TRACE_BUFFER_ADDR_IDX,
					device->gmu_core.trace.md->gmuaddr);
		if (ret)
			return ret;

		/* Initialize the GMU trace buffer header */
		gmu_core_trace_header_init(&device->gmu_core.trace);
	}

	return 0;
}

struct platform_device *get_gmu_wrapper_pdev(void)
{
	struct device_node *node;
	struct platform_device *pdev = NULL;

	node = of_find_compatible_node(NULL, NULL, "qcom,adreno-gmu-wrapper");
	if (!node)
		return NULL;

	if (!of_device_is_available(node)) {
		of_node_put(node);
		return NULL;
	}

	pdev = of_find_device_by_node(node);
	of_node_put(node);
	return pdev;
}

bool is_gmu_wrapper_available(void)
{
	struct platform_device *pdev = get_gmu_wrapper_pdev();

	platform_device_put(pdev);

	return pdev != NULL;
}
