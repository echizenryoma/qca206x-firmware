/* Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _CNSS_PCI_H
#define _CNSS_PCI_H

#ifdef CONFIG_NAPIER_X86
#include <linux/iommu.h>
#include "msm_mhi.h"
#else
#include <asm/dma-iommu.h>
#include <linux/iommu.h>
#include <linux/msm_mhi.h>
#include <linux/msm_pcie.h>
#endif
#include <linux/pci.h>

#include "main.h"

enum cnss_mhi_state {
	CNSS_MHI_INIT,
	CNSS_MHI_DEINIT,
	CNSS_MHI_SUSPEND,
	CNSS_MHI_RESUME,
	CNSS_MHI_POWER_OFF,
	CNSS_MHI_POWER_ON,
	CNSS_MHI_TRIGGER_RDDM,
	CNSS_MHI_RDDM,
	CNSS_MHI_RDDM_KERNEL_PANIC,
	CNSS_MHI_NOTIFY_LINK_ERROR,
	CNSS_MHI_RDDM_DONE,
};

struct cnss_msi_user {
	char *name;
	int num_vectors;
	u32 base_vector;
};

struct cnss_msi_config {
	int total_vectors;
	int total_users;
	struct cnss_msi_user *users;
};

struct cnss_pci_data {
	struct pci_dev *pci_dev;
	struct cnss_plat_data *plat_priv;
	const struct pci_device_id *pci_device_id;
	u32 device_id;
	u16 revision_id;
	struct cnss_wlan_driver *driver_ops;
	bool pci_link_state;
	bool pci_link_down_ind;
	struct pci_saved_state *saved_state;
	struct pci_saved_state *default_state;
#ifndef CONFIG_NAPIER_X86
	struct msm_pcie_register_event msm_pci_event;
#endif
	atomic_t auto_suspended;
	u8 drv_connected_last;
	bool monitor_wake_intr;
	struct dma_iommu_mapping *smmu_mapping;
	dma_addr_t smmu_iova_start;
	size_t smmu_iova_len;
	dma_addr_t smmu_iova_ipa_start;
	size_t smmu_iova_ipa_len;
	void __iomem *bar;
	struct cnss_msi_config *msi_config;
	u32 msi_ep_base_data;
	struct mhi_device mhi_dev;
	unsigned long mhi_state;
};

static inline void cnss_set_pci_priv(struct pci_dev *pci_dev, void *data)
{
	pci_set_drvdata(pci_dev, data);
}

static inline struct cnss_pci_data *cnss_get_pci_priv(struct pci_dev *pci_dev)
{
	return pci_get_drvdata(pci_dev);
}

static inline struct cnss_plat_data *cnss_pci_priv_to_plat_priv(void *bus_priv)
{
	struct cnss_pci_data *pci_priv = bus_priv;

	return pci_priv->plat_priv;
}

static inline void cnss_pci_set_monitor_wake_intr(void *bus_priv, bool val)
{
	struct cnss_pci_data *pci_priv = bus_priv;

	pci_priv->monitor_wake_intr = val;
}

static inline bool cnss_pci_get_monitor_wake_intr(void *bus_priv)
{
	struct cnss_pci_data *pci_priv = bus_priv;

	return pci_priv->monitor_wake_intr;
}

static inline void cnss_pci_set_auto_suspended(void *bus_priv, int val)
{
	struct cnss_pci_data *pci_priv = bus_priv;

	atomic_set(&pci_priv->auto_suspended, val);
}

static inline int cnss_pci_get_auto_suspended(void *bus_priv)
{
	struct cnss_pci_data *pci_priv = bus_priv;

	return atomic_read(&pci_priv->auto_suspended);
}

int cnss_pci_get_bar_info(struct cnss_pci_data *pci_priv, void __iomem **va,
			  phys_addr_t *pa);
void cnss_pci_stop_mhi(struct cnss_pci_data *pci_priv);
void cnss_pci_clear_dump_info(struct cnss_pci_data *pci_priv);
int cnss_pm_request_resume(struct cnss_pci_data *pci_priv);
int cnss_pci_dev_ramdump(struct cnss_pci_data *pci_priv);
void cnss_pci_dump_qdss_reg(struct cnss_pci_data *pci_priv);
void cnss_pci_enable_l1(struct cnss_pci_data *pci_priv);

#ifdef CONFIG_CNSS2_PCIE
int cnss_suspend_pci_link(struct cnss_pci_data *pci_priv);
int cnss_resume_pci_link(struct cnss_pci_data *pci_priv);
void cnss_pci_collect_dump_info(struct cnss_pci_data *pci_priv);
int cnss_pci_fw_sram_dump_to_file(struct cnss_pci_data *pci_priv,
		uint32_t fw_sram_start,
		uint32_t fw_sram_end,
		const char *fw_sram_dump_path);
int cnss_pci_dump_fw_remote_mem_to_file(struct cnss_pci_data *pci_priv);
int cnss_pci_dump_fw_paging_to_file(struct cnss_pci_data *pci_priv);
u32 cnss_pci_get_wake_msi(struct cnss_pci_data *pci_priv);
int cnss_pci_dev_crash_shutdown(struct cnss_pci_data *pci_priv);
int cnss_pci_call_driver_probe(struct cnss_pci_data *pci_priv);
int cnss_pci_call_driver_remove(struct cnss_pci_data *pci_priv);
int cnss_pci_call_driver_modem_status(struct cnss_pci_data *pci_priv,
				      int modem_current_status);
int cnss_pci_set_mhi_state(struct cnss_pci_data *pci_priv,
			   enum cnss_mhi_state state);
int cnss_pci_dev_powerup(struct cnss_pci_data *pci_priv);
int cnss_pci_dev_shutdown(struct cnss_pci_data *pci_priv);
int cnss_pci_force_fw_assert_hdlr(struct cnss_pci_data *pci_priv);
int cnss_pci_load_m3(struct cnss_pci_data *pci_priv);
void cnss_pci_free_m3_mem(struct cnss_pci_data *pci_priv);
void cnss_pci_fw_boot_timeout_hdlr(struct cnss_pci_data *pci_priv);
int cnss_pci_recovery_update_status(struct cnss_pci_data *pci_priv);
int cnss_pci_init(struct cnss_plat_data *plat_priv);
void cnss_pci_deinit(struct cnss_plat_data *plat_priv);
int cnss_pci_register_driver_hdlr(struct cnss_pci_data *pci_priv, void *data);
int cnss_pci_unregister_driver_hdlr(struct cnss_pci_data *pci_priv);
int cnss_pci_alloc_fw_mem(struct cnss_pci_data *pci_priv);
int cnss_pci_start_mhi(struct cnss_pci_data *pci_priv);
void cnss_pci_shutdown(struct pci_dev *pci_dev);
#else
static inline int cnss_suspend_pci_link(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_resume_pci_link(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline void cnss_pci_collect_dump_info(struct cnss_pci_data *pci_priv)
{ }

static inline int cnss_pci_fw_sram_dump_to_file(struct cnss_pci_data *pci_priv,
		uint32_t fw_sram_start,
		uint32_t fw_sram_end,
		const char *fw_sram_dump_path)
{
	return 0;
}

static inline
int cnss_pci_dump_fw_remote_mem_to_file(struct cnss_pci_data *pci_priv)
{
	return 0;
}

static inline
int cnss_pci_dump_fw_paging_to_file(struct cnss_pci_data *pci_priv)
{
	return 0;
}

static inline u32 cnss_pci_get_wake_msi(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_dev_crash_shutdown(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_call_driver_probe(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_call_driver_remove(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_call_driver_modem_status(struct cnss_pci_data *pci_priv,
				      int modem_current_status)
{
	return 0;
}
static inline int cnss_pci_set_mhi_state(struct cnss_pci_data *pci_priv,
			   enum cnss_mhi_state state)
{
	return 0;
}
static inline int cnss_pci_dev_powerup(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_dev_shutdown(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_force_fw_assert_hdlr(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_load_m3(struct cnss_pci_data *pci_priv)
{
	return 0;
}

static inline void cnss_pci_free_m3_mem(struct cnss_pci_data *pci_priv)
{
}

static inline void cnss_pci_fw_boot_timeout_hdlr(struct cnss_pci_data *pci_priv)
{ }
static inline int cnss_pci_recovery_update_status(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_init(struct cnss_plat_data *plat_priv)
{
	return 0;
}
static inline void cnss_pci_deinit(struct cnss_plat_data *plat_priv)
{ }
static inline int cnss_pci_register_driver_hdlr(struct cnss_pci_data *pci_priv, void *data)
{
	return 0;
}
static inline int cnss_pci_unregister_driver_hdlr(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_alloc_fw_mem(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline int cnss_pci_start_mhi(struct cnss_pci_data *pci_priv)
{
	return 0;
}
static inline void cnss_pci_shutdown(struct pci_dev *pci_dev)
{
}
#endif
#endif /* _CNSS_PCI_H */
