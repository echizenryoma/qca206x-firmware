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

#include <linux/firmware.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/pm_runtime.h>
#include <linux/memblock.h>
#include <linux/completion.h>

#include "main.h"
#include "bus.h"
#include "debug.h"
#include "pci.h"
#include "mhi.h"
#include "cnss_module.h"

#define PCI_LINK_UP			1
#define PCI_LINK_DOWN			0

#define SAVE_PCI_CONFIG_SPACE		1
#define RESTORE_PCI_CONFIG_SPACE	0

#define PM_OPTIONS_DEFAULT		0
#define PM_OPTIONS_LINK_DOWN \
	(MSM_PCIE_CONFIG_NO_CFG_RESTORE | MSM_PCIE_CONFIG_LINKDOWN)

#define PCI_BAR_NUM			0

#define PCI_DMA_MASK_32_BIT		32
#define PCI_DMA_MASK_36_BIT		36

#define FW_MEM_DEFAULT_ALIGNMENT (0x4000)

#define MHI_NODE_NAME			"qcom,mhi"
#define MHI_MSI_NAME			"MHI"

#define MAX_M3_FILE_NAME_LENGTH		64
#define DEFAULT_M3_FILE_NAME		FW_PREFIX "m3.bin"

#define WAKE_MSI_NAME			"WAKE"

#define FW_ASSERT_TIMEOUT		20000

#define QCA6390_PCIE_REMAP_BAR_CTRL_OFFSET	0x310c

#define QDSS_APB_DEC_CSR_BASE			0x1C01000
#define QDSS_APB_DEC_CSR_ETRIRQCTRL_OFFSET	0x6C
#define QDSS_APB_DEC_CSR_PRESERVEETF_OFFSET	0x70
#define QDSS_APB_DEC_CSR_PRESERVEETR0_OFFSET	0x74
#define QDSS_APB_DEC_CSR_PRESERVEETR1_OFFSET	0x78

#define MAX_UNWINDOWED_ADDRESS			0x80000
#define WINDOW_ENABLE_BIT			0x40000000
#define WINDOW_SHIFT				19
#define WINDOW_VALUE_MASK			0x3F
#define WINDOW_START				MAX_UNWINDOWED_ADDRESS
#define WINDOW_RANGE_MASK			0x7FFFF

static DEFINE_SPINLOCK(pci_link_down_lock);
static DEFINE_SPINLOCK(pci_reg_window_lock);

static unsigned int pci_link_down_panic;
module_param(pci_link_down_panic, uint, 0600);
MODULE_PARM_DESC(pci_link_down_panic,
		 "Trigger kernel panic when PCI link down is detected");

static bool fbc_bypass;
#ifdef CONFIG_CNSS2_DEBUG
module_param(fbc_bypass, bool, 0600);
MODULE_PARM_DESC(fbc_bypass,
		 "Bypass firmware download when loading WLAN driver");
#endif

static bool rddm_support = 1;
module_param(rddm_support, bool, 0600);
MODULE_PARM_DESC(rddm_support, "RDDM support or not");

struct cnss_pci_reg {
	char *name;
	u32 offset;
};

static struct cnss_pci_reg qdss_csr[] = {
	{ "QDSSCSR_ETRIRQCTRL", QDSS_APB_DEC_CSR_ETRIRQCTRL_OFFSET },
	{ "QDSSCSR_PRESERVEETF", QDSS_APB_DEC_CSR_PRESERVEETF_OFFSET },
	{ "QDSSCSR_PRESERVEETR0", QDSS_APB_DEC_CSR_PRESERVEETR0_OFFSET },
	{ "QDSSCSR_PRESERVEETR1", QDSS_APB_DEC_CSR_PRESERVEETR1_OFFSET },
	{ NULL },
};

#ifdef CONFIG_CNSS_QCA6390
#define CLEAR_MASTER(pci_dev) pci_clear_master(pci_dev)
#else
#define CLEAR_MASTER(pci_dev) /* no-op */
#endif

/* For reg out of BAR's basic range */
static u32 cnss_pci_window_reg_read(struct cnss_pci_data *pci_priv, u32 offset)
{
	if (offset < MAX_UNWINDOWED_ADDRESS) {
		return readl_relaxed(pci_priv->bar + offset);
	}
	else {
		u32 window = (offset >> WINDOW_SHIFT) & WINDOW_VALUE_MASK;

		writel_relaxed(WINDOW_ENABLE_BIT | window,
			       QCA6390_PCIE_REMAP_BAR_CTRL_OFFSET +
			       pci_priv->bar);
		cnss_pr_dbg("Config PCIe remap window register to 0x%x\n",
			    WINDOW_ENABLE_BIT | window);

		return readl_relaxed(pci_priv->bar + WINDOW_START +
				     (offset & WINDOW_RANGE_MASK));
	}
}

void cnss_pci_dump_qdss_reg(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	int i, array_size = ARRAY_SIZE(qdss_csr) - 1;
	gfp_t gfp = GFP_KERNEL;
	u32 reg_offset;

	if (in_interrupt() || irqs_disabled())
		gfp = GFP_ATOMIC;

	if (!plat_priv->qdss_reg)
		plat_priv->qdss_reg = devm_kzalloc(&pci_priv->pci_dev->dev,
						   sizeof(*plat_priv->qdss_reg)
						   * array_size, gfp);

	for (i = 0; qdss_csr[i].name; i++) {
		reg_offset = QDSS_APB_DEC_CSR_BASE + qdss_csr[i].offset;
		plat_priv->qdss_reg[i] = cnss_pci_window_reg_read(pci_priv,
								  reg_offset);
		cnss_pr_err("%s[0x%x] = 0x%x\n", qdss_csr[i].name, reg_offset,
			    plat_priv->qdss_reg[i]);
	}
}

void cnss_pci_enable_l1(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pdev = pci_priv->pci_dev;
	u32 lnkctl_offset;
	u32 val;

	lnkctl_offset = pdev->pcie_cap + PCI_EXP_LNKCTL;
	pci_read_config_dword(pdev, lnkctl_offset, &val);
	cnss_pr_dbg("lnkctl 0x%x\n", val);

	val |= PCI_EXP_LNKCTL_ASPM_L1;
	pci_write_config_dword(pdev, lnkctl_offset, val);
	pci_read_config_dword(pdev, lnkctl_offset, &val);
	cnss_pr_dbg("after enable l1 lnkctl 0x%x\n", val);
}

static void cnss_pci_disable_l1(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pdev = pci_priv->pci_dev;
	u32 lnkctl_offset;
	u32 val;

	lnkctl_offset = pdev->pcie_cap + PCI_EXP_LNKCTL;
	pci_read_config_dword(pdev, lnkctl_offset, &val);
	cnss_pr_dbg("lnkctl 0x%x\n", val);

	val &= ~PCI_EXP_LNKCTL_ASPM_L1;
	pci_write_config_dword(pdev, lnkctl_offset, val);
}

static int cnss_set_pci_config_space(struct cnss_pci_data *pci_priv, bool save)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	bool link_down_or_recovery;

	if (!plat_priv)
		return -ENODEV;

	link_down_or_recovery = pci_priv->pci_link_down_ind ||
		(test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state));

	if (save) {
		if (link_down_or_recovery) {
			pci_priv->saved_state = NULL;
		} else {
			pci_save_state(pci_dev);
			pci_priv->saved_state = pci_store_saved_state(pci_dev);
		}
	} else {
		if (link_down_or_recovery) {
#ifndef CONFIG_NAPIER_X86
			ret = msm_pcie_recover_config(pci_dev);
			if (ret) {
				cnss_pr_err("Failed to recover PCI config space, err = %d\n",
					    ret);
				return ret;
			}
#else
			pci_load_saved_state(pci_dev, pci_priv->default_state);
			pci_restore_state(pci_dev);
#endif
		} else if (pci_priv->saved_state) {
			pci_load_and_free_saved_state(pci_dev,
						      &pci_priv->saved_state);
			pci_restore_state(pci_dev);
		}
		if (!test_bit(ENABLE_PCI_LINK_PS, &quirks))
			cnss_pci_disable_l1(pci_priv);
	}

	return 0;
}

static int cnss_set_pci_link(struct cnss_pci_data *pci_priv, bool link_up)
{
	int ret = 0;
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	bool link_down_or_recovery;

	if (!plat_priv)
		return -ENODEV;

	link_down_or_recovery = pci_priv->pci_link_down_ind ||
		(test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state));

#ifndef CONFIG_NAPIER_X86
	ret = msm_pcie_pm_control(link_up ? MSM_PCIE_RESUME :
				  MSM_PCIE_SUSPEND,
				  pci_dev->bus->number,
				  pci_dev, NULL,
				  link_down_or_recovery ?
				  PM_OPTIONS_LINK_DOWN :
				  PM_OPTIONS_DEFAULT);
#else
	UNUSED(ret);
	UNUSED(pci_dev);
#endif
	if (ret) {
		cnss_pr_err("Failed to %s PCI link with %s option, err = %d\n",
			    link_up ? "resume" : "suspend",
			    link_down_or_recovery ? "link down" : "default",
			    ret);
		return ret;
	}

	return 0;
}

int cnss_pci_is_device_down(struct device *dev)
{
#ifdef CONFIG_NAPIER_X86
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(NULL);
#else
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(dev);
#endif
	struct cnss_pci_data *pci_priv;

	if (!plat_priv) {
		cnss_pr_err("plat_priv is NULL\n");
		return -ENODEV;
	}

	pci_priv = plat_priv->bus_priv;
	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	return test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state) |
			pci_priv->pci_link_down_ind;
}
cnss_export_symbol(cnss_pci_is_device_down);

void cnss_pci_lock_reg_window(struct device *dev, unsigned long *flags)
{
	spin_lock_bh(&pci_reg_window_lock);
}
cnss_export_symbol(cnss_pci_lock_reg_window);

void cnss_pci_unlock_reg_window(struct device *dev, unsigned long *flags)
{
	spin_unlock_bh(&pci_reg_window_lock);
}
cnss_export_symbol(cnss_pci_unlock_reg_window);

int cnss_suspend_pci_link(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv)
		return -ENODEV;

	if (!pci_priv->pci_link_state) {
		cnss_pr_info("PCI link is already suspended!\n");
		goto out;
	}

	CLEAR_MASTER(pci_priv->pci_dev);

	ret = cnss_set_pci_config_space(pci_priv, SAVE_PCI_CONFIG_SPACE);
	if (ret)
		goto out;

	pci_disable_device(pci_priv->pci_dev);

	ret = pci_set_power_state(pci_priv->pci_dev, PCI_D3hot);
	if (ret)
		cnss_pr_err("Failed to set D3Hot, err =  %d\n", ret);

	ret = cnss_set_pci_link(pci_priv, PCI_LINK_DOWN);
	if (ret)
		goto out;

	pci_priv->pci_link_state = PCI_LINK_DOWN;

	return 0;
out:
	return ret;
}

int cnss_resume_pci_link(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv)
		return -ENODEV;

	if (pci_priv->pci_link_state) {
		cnss_pr_info("PCI link is already resumed!\n");
		goto out;
	}

	ret = cnss_set_pci_link(pci_priv, PCI_LINK_UP);
	if (ret)
		goto out;

	pci_priv->pci_link_state = PCI_LINK_UP;

	ret = pci_enable_device(pci_priv->pci_dev);
	if (ret) {
		cnss_pr_err("Failed to enable PCI device, err = %d\n", ret);
		goto out;
	}

	ret = cnss_set_pci_config_space(pci_priv, RESTORE_PCI_CONFIG_SPACE);
	if (ret)
		goto out;

	pci_set_master(pci_priv->pci_dev);

	if (pci_priv->pci_link_down_ind)
		pci_priv->pci_link_down_ind = false;

	return 0;
out:
	return ret;
}

int cnss_pci_prevent_l1(struct device *dev)
{
	return 0;
}
cnss_export_symbol(cnss_pci_prevent_l1);

void cnss_pci_allow_l1(struct device *dev)
{
	//empty body
}
cnss_export_symbol(cnss_pci_allow_l1);

int cnss_pci_link_down(struct device *dev)
{
	unsigned long flags;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL!\n");
		return -EINVAL;
	}

	if (pci_link_down_panic)
		panic("cnss: PCI link is down!\n");

	spin_lock_irqsave(&pci_link_down_lock, flags);
	if (pci_priv->pci_link_down_ind) {
		cnss_pr_dbg("PCI link down recovery is in progress, ignore!\n");
		spin_unlock_irqrestore(&pci_link_down_lock, flags);
		return -EINVAL;
	}
	pci_priv->pci_link_down_ind = true;
	spin_unlock_irqrestore(&pci_link_down_lock, flags);

	cnss_pr_err("PCI link down is detected by host driver, schedule recovery!\n");

	cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_NOTIFY_LINK_ERROR);
	cnss_schedule_recovery(dev, CNSS_REASON_LINK_DOWN);

	return 0;
}
cnss_export_symbol(cnss_pci_link_down);

int cnss_pci_recovery_update_status(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;

	plat_priv = pci_priv->plat_priv;

	if (pci_priv->driver_ops &&
	    test_bit(CNSS_DRIVER_PROBED, &plat_priv->driver_state))
		pci_priv->driver_ops->update_status(pci_priv->pci_dev,
						     CNSS_RECOVERY);
	return 0;
}

int cnss_pci_call_driver_probe(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -ENODEV;

	plat_priv = pci_priv->plat_priv;

	if (test_bit(CNSS_DRIVER_DEBUG, &plat_priv->driver_state)) {
		clear_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state);
		cnss_pr_dbg("Skip driver probe\n");
		goto out;
	}

	if (!pci_priv->driver_ops) {
		cnss_pr_err("driver_ops is NULL\n");
		ret = -EINVAL;
		goto out;
	}

	if (test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state) &&
	    test_bit(CNSS_DRIVER_PROBED, &plat_priv->driver_state)) {
		ret = pci_priv->driver_ops->reinit(pci_priv->pci_dev,
						   pci_priv->pci_device_id);
		if (ret) {
			cnss_pr_err("Failed to reinit host driver, err = %d\n",
				    ret);
			goto out;
		}
		clear_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state);
	} else if (test_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state)) {
		ret = pci_priv->driver_ops->probe(pci_priv->pci_dev,
						  pci_priv->pci_device_id);
		if (ret) {
			cnss_pr_err("Failed to probe host driver, err = %d\n",
				    ret);
			/* Clearing the driver loading state in driver probe
			   failure case as well. Otherwise target reset won't
			   happen during MHI power off */
			clear_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state);
			goto out;
		}
		clear_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state);
		clear_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state);
		set_bit(CNSS_DRIVER_PROBED, &plat_priv->driver_state);
	}

	return 0;

out:
	return ret;
}

int cnss_pci_call_driver_remove(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -ENODEV;

	plat_priv = pci_priv->plat_priv;

	if (test_bit(CNSS_COLD_BOOT_CAL, &plat_priv->driver_state) ||
	    test_bit(CNSS_FW_BOOT_RECOVERY, &plat_priv->driver_state) ||
	    test_bit(CNSS_DRIVER_DEBUG, &plat_priv->driver_state)) {
		cnss_pr_dbg("Skip driver remove\n");
		return 0;
	}

	if (!pci_priv->driver_ops) {
		cnss_pr_err("driver_ops is NULL\n");
		return -EINVAL;
	}

	if (test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state) &&
	    test_bit(CNSS_DRIVER_PROBED, &plat_priv->driver_state)) {
		pci_priv->driver_ops->shutdown(pci_priv->pci_dev);
	} else if (test_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state)) {
		pci_priv->driver_ops->remove(pci_priv->pci_dev);
		clear_bit(CNSS_DRIVER_PROBED, &plat_priv->driver_state);
	}

	return 0;
}

int cnss_pci_call_driver_modem_status(struct cnss_pci_data *pci_priv,
				      int modem_current_status)
{
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		return -ENODEV;

	driver_ops = pci_priv->driver_ops;
	if (!driver_ops || !driver_ops->modem_status)
		return -EINVAL;

	driver_ops->modem_status(pci_priv->pci_dev, modem_current_status);

	return 0;
}

static int cnss_qca6174_powerup(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	ret = cnss_power_on_device(plat_priv);
	if (ret) {
		cnss_pr_err("Failed to power on device, err = %d\n", ret);
		goto out;
	}

	ret = cnss_resume_pci_link(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to resume PCI link, err = %d\n", ret);
		goto power_off;
	}

	ret = cnss_pci_call_driver_probe(pci_priv);
	if (ret)
		goto suspend_link;

	return 0;
suspend_link:
	cnss_suspend_pci_link(pci_priv);
power_off:
	cnss_power_off_device(plat_priv);
out:
	return ret;
}

static int cnss_qca6174_shutdown(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	cnss_pm_request_resume(pci_priv);

	cnss_pci_call_driver_remove(pci_priv);

#ifdef CONFIG_NAPIER_X86
	cnss_request_bus_bandwidth(&pci_priv->pci_dev->dev,
                                   CNSS_BUS_WIDTH_NONE);	
#else	
	cnss_request_bus_bandwidth(&plat_priv->plat_dev->dev,
				   CNSS_BUS_WIDTH_NONE);
#endif
	cnss_pci_set_monitor_wake_intr(pci_priv, false);
	cnss_pci_set_auto_suspended(pci_priv, 0);

	ret = cnss_suspend_pci_link(pci_priv);
	if (ret)
		cnss_pr_err("Failed to suspend PCI link, err = %d\n", ret);

	cnss_power_off_device(plat_priv);

	clear_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state);

	return ret;
}

static void cnss_qca6174_crash_shutdown(struct cnss_pci_data *pci_priv)
{
	if (pci_priv->driver_ops && pci_priv->driver_ops->crash_shutdown)
		pci_priv->driver_ops->crash_shutdown(pci_priv->pci_dev);
}

#ifndef CONFIG_NAPIER_X86
static int cnss_qca6174_ramdump(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_ramdump_info *ramdump_info;
	struct ramdump_segment segment;

	ramdump_info = &plat_priv->ramdump_info;
	if (!ramdump_info->ramdump_size)
		return -EINVAL;

	memset(&segment, 0, sizeof(segment));
	segment.v_address = ramdump_info->ramdump_va;
	segment.size = ramdump_info->ramdump_size;
	ret = do_ramdump(ramdump_info->ramdump_dev, &segment, 1);

	return ret;
}
#endif

static int cnss_qca6290_powerup(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	unsigned int timeout;

	if (plat_priv->ramdump_info_v2.dump_data_valid ||
	    test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state)) {
		cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_DEINIT);
		cnss_pci_clear_dump_info(pci_priv);
	}

	ret = cnss_power_on_device(plat_priv);
	if (ret) {
		cnss_pr_err("Failed to power on device, err = %d\n", ret);
		goto out;
	}

	ret = cnss_resume_pci_link(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to resume PCI link, err = %d\n", ret);
		goto power_off;
	}

	timeout = cnss_get_qmi_timeout();

	ret = cnss_pci_start_mhi(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to start MHI, err = %d\n", ret);
		if (!test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state) &&
		    !pci_priv->pci_link_down_ind && timeout)
			mod_timer(&plat_priv->fw_boot_timer,
				  jiffies + msecs_to_jiffies(timeout >> 1));
		return 0;
	}

	if (test_bit(USE_CORE_ONLY_FW, cnss_get_debug_quirks())) {
		clear_bit(CNSS_FW_BOOT_RECOVERY, &plat_priv->driver_state);
		clear_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state);
		return 0;
	}

	cnss_set_pin_connect_status(plat_priv);

	if (*cnss_get_qmi_bypass()) {
		ret = cnss_pci_call_driver_probe(pci_priv);
		if (ret)
			goto stop_mhi;
	} else if (timeout) {
		mod_timer(&plat_priv->fw_boot_timer,
			  jiffies + msecs_to_jiffies(timeout << 1));
	}

	return 0;

stop_mhi:
	cnss_pci_stop_mhi(pci_priv);
	cnss_suspend_pci_link(pci_priv);
power_off:
	cnss_power_off_device(plat_priv);
out:
	return ret;
}

static int cnss_qca6290_shutdown(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	cnss_pm_request_resume(pci_priv);

	cnss_pci_call_driver_remove(pci_priv);
#ifdef CONFIG_NAPIER_X86
	cnss_request_bus_bandwidth(&pci_priv->pci_dev->dev,
				   CNSS_BUS_WIDTH_NONE);
#else
	cnss_request_bus_bandwidth(&plat_priv->plat_dev->dev,
				   CNSS_BUS_WIDTH_NONE);
#endif
	cnss_pci_set_monitor_wake_intr(pci_priv, false);
	cnss_pci_set_auto_suspended(pci_priv, 0);

	cnss_pci_stop_mhi(pci_priv);

	ret = cnss_suspend_pci_link(pci_priv);
	if (ret)
		cnss_pr_err("Failed to suspend PCI link, err = %d\n", ret);

	cnss_power_off_device(plat_priv);

	clear_bit(CNSS_FW_READY, &plat_priv->driver_state);
	clear_bit(CNSS_FW_MEM_READY, &plat_priv->driver_state);
	clear_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state);

	return ret;
}

static void cnss_qca6290_crash_shutdown(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	int ret = 0;

	cnss_pr_dbg("Crash shutdown with driver_state 0x%lx\n",
		    plat_priv->driver_state);

#ifndef CONFIG_NAPIER_X86	
	if (test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state) ||
	    test_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state) ||
	    test_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state)) {
		cnss_pr_dbg("Ignore crash shutdown\n");
		return;
	}
#endif

	ret = cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_RDDM_KERNEL_PANIC);
	if (ret) {
		cnss_pr_err("Fail to complete RDDM, err = %d\n", ret);
		/* Try to dump QDSS reg after RDDM dump fail */
		cnss_pci_dump_qdss_reg(pci_priv);
		return;
	}

	if (test_bit(CNSS_MHI_RDDM_DONE, &plat_priv->driver_state)) {
		cnss_pr_dbg("RDDM already collected, return\n");
		return;
	}

	cnss_pci_collect_dump_info(pci_priv);
}

#ifndef CONFIG_NAPIER_X86
static int cnss_qca6290_ramdump(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_ramdump_info_v2 *info_v2 = &plat_priv->ramdump_info_v2;
	struct cnss_dump_data *dump_data = &info_v2->dump_data;
	struct cnss_dump_seg *dump_seg = info_v2->dump_data_vaddr;
	struct ramdump_segment *ramdump_segs, *s;
	int i, ret = 0;

	if (!info_v2->dump_data_valid ||
	    dump_data->nentries == 0)
		return 0;

	ramdump_segs = kcalloc(dump_data->nentries,
			       sizeof(*ramdump_segs),
			       GFP_KERNEL);
	if (!ramdump_segs)
		return -ENOMEM;

	s = ramdump_segs;
	for (i = 0; i < dump_data->nentries; i++) {
		s->address = dump_seg->address;
		s->v_address = dump_seg->v_address;
		s->size = dump_seg->size;
		s++;
		dump_seg++;
	}

	ret = do_elf_ramdump(info_v2->ramdump_dev, ramdump_segs,
			     dump_data->nentries);
	kfree(ramdump_segs);

	cnss_pci_set_mhi_state(plat_priv->bus_priv, CNSS_MHI_DEINIT);
	cnss_pci_clear_dump_info(plat_priv->bus_priv);

	return ret;
}
#endif

int cnss_pci_dev_powerup(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	switch (pci_priv->device_id) {
	case QCA6174_DEVICE_ID:
		ret = cnss_qca6174_powerup(pci_priv);
		break;
	case QCA6290_EMULATION_DEVICE_ID:
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case QCN7605_DEVICE_ID:
		ret = cnss_qca6290_powerup(pci_priv);
		break;
	default:
		cnss_pr_err("Unknown device_id found: 0x%x\n",
			    pci_priv->device_id);
		ret = -ENODEV;
	}

	return ret;
}

int cnss_pci_dev_shutdown(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	switch (pci_priv->device_id) {
	case QCA6174_DEVICE_ID:
		ret = cnss_qca6174_shutdown(pci_priv);
		break;
	case QCA6290_EMULATION_DEVICE_ID:
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case QCN7605_DEVICE_ID:
		ret = cnss_qca6290_shutdown(pci_priv);
		break;
	default:
		cnss_pr_err("Unknown device_id found: 0x%x\n",
			    pci_priv->device_id);
		ret = -ENODEV;
	}

	return ret;
}

int cnss_pci_dev_crash_shutdown(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	switch (pci_priv->device_id) {
	case QCA6174_DEVICE_ID:
		cnss_qca6174_crash_shutdown(pci_priv);
		break;
	case QCA6290_EMULATION_DEVICE_ID:
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case QCN7605_DEVICE_ID:
		cnss_qca6290_crash_shutdown(pci_priv);
		break;
	default:
		cnss_pr_err("Unknown device_id found: 0x%x\n",
			    pci_priv->device_id);
		ret = -ENODEV;
	}

	return ret;
}

#ifndef CONFIG_NAPIER_X86
int cnss_pci_dev_ramdump(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	switch (pci_priv->device_id) {
	case QCA6174_DEVICE_ID:
		ret = cnss_qca6174_ramdump(pci_priv);
		break;
	case QCA6290_EMULATION_DEVICE_ID:
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case QCN7605_DEVICE_ID:
		ret = cnss_qca6290_ramdump(pci_priv);
		break;
	default:
		cnss_pr_err("Unknown device_id found: 0x%x\n",
			    pci_priv->device_id);
		ret = -ENODEV;
	}

	return ret;
}
#endif

int cnss_wlan_register_driver(struct cnss_wlan_driver *driver_ops)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(NULL);
	struct cnss_pci_data *pci_priv;

	if (!plat_priv) {
		cnss_pr_err("plat_priv is NULL\n");
		return -ENODEV;
	}

	pci_priv = plat_priv->bus_priv;
	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	if (pci_priv->driver_ops) {
		cnss_pr_err("Driver has already registered\n");
		return -EEXIST;
	}

	ret = cnss_driver_event_post(plat_priv,
				     CNSS_DRIVER_EVENT_REGISTER_DRIVER,
				     CNSS_EVENT_SYNC_UNINTERRUPTIBLE,
				     driver_ops);
	return ret;
}
cnss_export_symbol(cnss_wlan_register_driver);

void cnss_wlan_unregister_driver(struct cnss_wlan_driver *driver_ops)
{
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(NULL);

	if (!plat_priv) {
		cnss_pr_err("plat_priv is NULL\n");
		return;
	}

	cnss_driver_event_post(plat_priv,
			       CNSS_DRIVER_EVENT_UNREGISTER_DRIVER,
			       CNSS_EVENT_SYNC_UNINTERRUPTIBLE, NULL);
}
cnss_export_symbol(cnss_wlan_unregister_driver);

int cnss_pci_register_driver_hdlr(struct cnss_pci_data *pci_priv,
				  void *data)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	set_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state);
	pci_priv->driver_ops = data;

	ret = cnss_pci_dev_powerup(pci_priv);
	if (ret) {
		clear_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state);
		pci_priv->driver_ops = NULL;
	} else {
		cnss_pci_free_m3_mem(pci_priv);
	}

	return ret;
}

int cnss_pci_unregister_driver_hdlr(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	set_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state);
	cnss_pci_dev_shutdown(pci_priv);
	pci_priv->driver_ops = NULL;

	return 0;
}

#ifndef CONFIG_NAPIER_X86
static int cnss_pci_init_smmu(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct device *dev;
	struct dma_iommu_mapping *mapping;
	int atomic_ctx = 1;
	int s1_bypass = 1;

	dev = &pci_priv->pci_dev->dev;

	mapping = arm_iommu_create_mapping(&platform_bus_type,
					   pci_priv->smmu_iova_start,
					   pci_priv->smmu_iova_len);
	if (IS_ERR(mapping)) {
		ret = PTR_ERR(mapping);
		cnss_pr_err("Failed to create SMMU mapping, err = %d\n", ret);
		goto out;
	}

	ret = iommu_domain_set_attr(mapping->domain,
				    DOMAIN_ATTR_ATOMIC,
				    &atomic_ctx);
	if (ret) {
		pr_err("Failed to set SMMU atomic_ctx attribute, err = %d\n",
		       ret);
		goto release_mapping;
	}

	ret = iommu_domain_set_attr(mapping->domain,
				    DOMAIN_ATTR_S1_BYPASS,
				    &s1_bypass);
	if (ret) {
		pr_err("Failed to set SMMU s1_bypass attribute, err = %d\n",
		       ret);
		goto release_mapping;
	}

	ret = arm_iommu_attach_device(dev, mapping);
	if (ret) {
		pr_err("Failed to attach SMMU device, err = %d\n", ret);
		goto release_mapping;
	}

	pci_priv->smmu_mapping = mapping;

	return ret;
release_mapping:
	arm_iommu_release_mapping(mapping);
out:
	return ret;
}

static void cnss_pci_deinit_smmu(struct cnss_pci_data *pci_priv)
{
	arm_iommu_detach_device(&pci_priv->pci_dev->dev);
	arm_iommu_release_mapping(pci_priv->smmu_mapping);

	pci_priv->smmu_mapping = NULL;
}

static void cnss_pci_event_cb(struct msm_pcie_notify *notify)
{
	unsigned long flags;
	struct pci_dev *pci_dev;
	struct cnss_pci_data *pci_priv;

	if (!notify)
		return;

	pci_dev = notify->user;
	if (!pci_dev)
		return;

	pci_priv = cnss_get_pci_priv(pci_dev);
	if (!pci_priv)
		return;

	switch (notify->event) {
	case MSM_PCIE_EVENT_LINKDOWN:
		if (pci_link_down_panic)
			panic("cnss: PCI link is down!\n");

		spin_lock_irqsave(&pci_link_down_lock, flags);
		if (pci_priv->pci_link_down_ind) {
			cnss_pr_dbg("PCI link down recovery is in progress, ignore!\n");
			spin_unlock_irqrestore(&pci_link_down_lock, flags);
			return;
		}
		pci_priv->pci_link_down_ind = true;
		spin_unlock_irqrestore(&pci_link_down_lock, flags);

		cnss_pr_err("PCI link down, schedule recovery!\n");
		cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_NOTIFY_LINK_ERROR);
		if (pci_dev->device == QCA6174_DEVICE_ID)
			disable_irq(pci_dev->irq);
		cnss_schedule_recovery(&pci_dev->dev, CNSS_REASON_LINK_DOWN);
		break;
	case MSM_PCIE_EVENT_WAKEUP:
		if (cnss_pci_get_monitor_wake_intr(pci_priv) &&
		    cnss_pci_get_auto_suspended(pci_priv)) {
			cnss_pci_set_monitor_wake_intr(pci_priv, false);
			pm_request_resume(&pci_dev->dev);
		}
		break;
	default:
		cnss_pr_err("Received invalid PCI event: %d\n", notify->event);
	}
}

static int cnss_reg_pci_event(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct msm_pcie_register_event *pci_event;

	pci_event = &pci_priv->msm_pci_event;
	pci_event->events = MSM_PCIE_EVENT_LINKDOWN |
		MSM_PCIE_EVENT_WAKEUP;
	pci_event->user = pci_priv->pci_dev;
	pci_event->mode = MSM_PCIE_TRIGGER_CALLBACK;
	pci_event->callback = cnss_pci_event_cb;
	pci_event->options = MSM_PCIE_CONFIG_NO_RECOVERY;

	ret = msm_pcie_register_event(pci_event);
	if (ret)
		cnss_pr_err("Failed to register MSM PCI event, err = %d\n",
			    ret);

	return ret;
}

static void cnss_dereg_pci_event(struct cnss_pci_data *pci_priv)
{
	msm_pcie_deregister_event(&pci_priv->msm_pci_event);
}
#endif

int cnss_pci_is_drv_connected(struct device *dev)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));

	if (!pci_priv)
		return -ENODEV;

	return pci_priv->drv_connected_last;
}
cnss_export_symbol(cnss_pci_is_drv_connected);

static int cnss_pci_suspend(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct cnss_wlan_driver *driver_ops;

	pm_message_t state = { .event = PM_EVENT_SUSPEND };

	if (!pci_priv)
		goto out;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		goto out;

	driver_ops = pci_priv->driver_ops;
	if (driver_ops && driver_ops->suspend) {
		ret = driver_ops->suspend(pci_dev, state);
		if (ret) {
			cnss_pr_err("Failed to suspend host driver, err = %d\n",
				    ret);
			ret = -EAGAIN;
			goto out;
		}
	}

	if (pci_priv->pci_link_state) {
		ret = cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_SUSPEND);
		if (ret) {
			if(driver_ops && driver_ops->resume)
				driver_ops->resume(pci_dev);
			ret = -EAGAIN;
			goto out;
		}

		CLEAR_MASTER(pci_dev);

		cnss_set_pci_config_space(pci_priv,
					  SAVE_PCI_CONFIG_SPACE);
		pci_disable_device(pci_dev);

		ret = pci_set_power_state(pci_dev, PCI_D3hot);
		if (ret)
			cnss_pr_err("Failed to set D3Hot, err =  %d\n",
				    ret);
	}

	cnss_pci_set_monitor_wake_intr(pci_priv, false);

	return 0;

out:
	return ret;
}

static int cnss_pci_resume(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		goto out;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		goto out;

	if (pci_priv->pci_link_down_ind)
		goto out;

	if (pci_priv->pci_link_state) {
		ret = pci_enable_device(pci_dev);
		if (ret)
			cnss_pr_err("Failed to enable PCI device, err = %d\n",
				    ret);

		if (pci_priv->saved_state)
			cnss_set_pci_config_space(pci_priv,
						  RESTORE_PCI_CONFIG_SPACE);

		pci_set_master(pci_dev);
		cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_RESUME);
	}

	driver_ops = pci_priv->driver_ops;
	if (driver_ops && driver_ops->resume) {
		ret = driver_ops->resume(pci_dev);
		if (ret)
			cnss_pr_err("Failed to resume host driver, err = %d\n",
				    ret);
	}

	return 0;

out:
	return ret;
}

static int cnss_pci_suspend_noirq(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		goto out;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		goto out;

	driver_ops = pci_priv->driver_ops;
	if (driver_ops && driver_ops->suspend_noirq)
		ret = driver_ops->suspend_noirq(pci_dev);

out:
	return ret;
}

static int cnss_pci_resume_noirq(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		goto out;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		goto out;

	driver_ops = pci_priv->driver_ops;
	if (driver_ops && driver_ops->resume_noirq &&
	    !pci_priv->pci_link_down_ind)
		ret = driver_ops->resume_noirq(pci_dev);

out:
	return ret;
}

static int cnss_pci_runtime_suspend(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		return -EAGAIN;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -EAGAIN;

	if (pci_priv->pci_link_down_ind) {
		cnss_pr_dbg("PCI link down recovery is in progress!\n");
		return -EAGAIN;
	}

	cnss_pr_dbg("Runtime suspend start\n");

	driver_ops = pci_priv->driver_ops;
	if (driver_ops && driver_ops->runtime_ops &&
	    driver_ops->runtime_ops->runtime_suspend)
		ret = driver_ops->runtime_ops->runtime_suspend(pci_dev);

	cnss_pr_info("Runtime suspend status: %d\n", ret);

	return ret;
}

static int cnss_pci_runtime_resume(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		return -EAGAIN;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -EAGAIN;

	if (pci_priv->pci_link_down_ind) {
		cnss_pr_dbg("PCI link down recovery is in progress!\n");
		return -EAGAIN;
	}

	cnss_pr_dbg("Runtime resume start\n");

	driver_ops = pci_priv->driver_ops;
	if (driver_ops && driver_ops->runtime_ops &&
	    driver_ops->runtime_ops->runtime_resume)
		ret = driver_ops->runtime_ops->runtime_resume(pci_dev);

	cnss_pr_info("Runtime resume status: %d\n", ret);

	return ret;
}

static int cnss_pci_runtime_idle(struct device *dev)
{
	cnss_pr_dbg("Runtime idle\n");

	pm_request_autosuspend(dev);

	return -EBUSY;
}

int cnss_wlan_pm_control(struct device *dev, bool vote)
{
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(dev);
	struct cnss_pci_data *pci_priv;
	struct pci_dev *pci_dev;

	if (!plat_priv)
		return -ENODEV;

	pci_priv = plat_priv->bus_priv;
	if (!pci_priv)
		return -ENODEV;

	pci_dev = pci_priv->pci_dev;
#ifndef CONFIG_NAPIER_X86
	return msm_pcie_pm_control(vote ? MSM_PCIE_DISABLE_PC :
				   MSM_PCIE_ENABLE_PC,
				   pci_dev->bus->number, pci_dev,
				   NULL, PM_OPTIONS_DEFAULT);
#endif
	return 0;
}
cnss_export_symbol(cnss_wlan_pm_control);

int cnss_auto_suspend(struct device *dev)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(dev);
	struct pci_dev *pci_dev;
	struct cnss_pci_data *pci_priv;
	struct cnss_bus_bw_info *bus_bw_info;

	if (!plat_priv)
		return -ENODEV;

	pci_priv = plat_priv->bus_priv;
	if (!pci_priv)
		return -ENODEV;

	pci_dev = pci_priv->pci_dev;

	if (pci_priv->pci_link_state) {
		if (cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_SUSPEND)) {
			ret = -EAGAIN;
			goto out;
		}

		CLEAR_MASTER(pci_dev);
		cnss_set_pci_config_space(pci_priv, SAVE_PCI_CONFIG_SPACE);
		pci_disable_device(pci_dev);

		ret = pci_set_power_state(pci_dev, PCI_D3hot);
		if (ret)
			cnss_pr_err("Failed to set D3Hot, err =  %d\n", ret);
		if (cnss_set_pci_link(pci_priv, PCI_LINK_DOWN)) {
			cnss_pr_err("Failed to shutdown PCI link!\n");
			ret = -EAGAIN;
			goto resume_mhi;
		}
	}

	pci_priv->pci_link_state = PCI_LINK_DOWN;
	cnss_pci_set_auto_suspended(pci_priv, 1);
	cnss_pci_set_monitor_wake_intr(pci_priv, true);

	bus_bw_info = &plat_priv->bus_bw_info;
#ifndef CONFIG_NAPIER_X86
	msm_bus_scale_client_update_request(bus_bw_info->bus_client,
					    CNSS_BUS_WIDTH_NONE);
#endif
	return 0;

resume_mhi:
	if (pci_enable_device(pci_dev))
		cnss_pr_err("Failed to enable PCI device!\n");
	cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_RESUME);
out:
	return ret;
}
cnss_export_symbol(cnss_auto_suspend);

int cnss_auto_resume(struct device *dev)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(dev);
	struct pci_dev *pci_dev;
	struct cnss_pci_data *pci_priv;
	struct cnss_bus_bw_info *bus_bw_info;

	if (!plat_priv)
		return -ENODEV;

	pci_priv = plat_priv->bus_priv;
	if (!pci_priv)
		return -ENODEV;

	pci_dev = pci_priv->pci_dev;
	if (!pci_priv->pci_link_state) {
		if (cnss_set_pci_link(pci_priv, PCI_LINK_UP)) {
			cnss_pr_err("Failed to resume PCI link!\n");
			ret = -EAGAIN;
			goto out;
		}
		pci_priv->pci_link_state = PCI_LINK_UP;
		ret = pci_enable_device(pci_dev);
		if (ret)
			cnss_pr_err("Failed to enable PCI device, err = %d\n",
				    ret);
	}

	cnss_set_pci_config_space(pci_priv, RESTORE_PCI_CONFIG_SPACE);
	pci_set_master(pci_dev);
	cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_RESUME);
	cnss_pci_set_auto_suspended(pci_priv, 0);

	bus_bw_info = &plat_priv->bus_bw_info;
#ifndef CONFIG_NAPIER_X86
	msm_bus_scale_client_update_request(bus_bw_info->bus_client,
					    bus_bw_info->current_bw_vote);
#endif
out:
	return ret;
}
cnss_export_symbol(cnss_auto_resume);

#ifdef CONFIG_CNSS_QCA6390
int cnss_pci_force_wake_request(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct mhi_device *mhi_dev;

	if (!pci_priv)
		return -ENODEV;

	if ((pci_priv->device_id != QCA6390_DEVICE_ID) &&
	    (pci_priv->device_id != QCA6490_DEVICE_ID))
		return 0;

	mhi_dev = &(pci_priv->mhi_dev);
	if (!mhi_dev)
		return -EINVAL;

	mhi_force_wake_request(mhi_dev);

	return 0;
}
cnss_export_symbol(cnss_pci_force_wake_request);

int cnss_pci_is_device_awake(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct mhi_device *mhi_dev;

	if (!pci_priv)
		return -ENODEV;

	if ((pci_priv->device_id != QCA6390_DEVICE_ID) &&
	    (pci_priv->device_id != QCA6490_DEVICE_ID))
		return true;

	mhi_dev = &(pci_priv->mhi_dev);
	if (!mhi_dev)
		return -EINVAL;

	return mhi_is_device_awake(mhi_dev);
}
cnss_export_symbol(cnss_pci_is_device_awake);

int cnss_pci_force_wake_release(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct mhi_device *mhi_dev;

	if (!pci_priv)
		return -ENODEV;

	if ((pci_priv->device_id != QCA6390_DEVICE_ID) &&
	    (pci_priv->device_id != QCA6490_DEVICE_ID))
		return 0;

	mhi_dev = &(pci_priv->mhi_dev);
	if (!mhi_dev)
		return -EINVAL;

	mhi_force_wake_release(mhi_dev);

	return 0;
}
cnss_export_symbol(cnss_pci_force_wake_release);
#else
int cnss_pci_force_wake_request(struct device *dev)
{
	return 0;
}
cnss_export_symbol(cnss_pci_force_wake_request);

int cnss_pci_is_device_awake(struct device *dev)
{
	return true;
}
cnss_export_symbol(cnss_pci_is_device_awake);

int cnss_pci_force_wake_release(struct device *dev)
{
	return 0;
}
cnss_export_symbol(cnss_pci_force_wake_release);
#endif

int cnss_pm_request_resume(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pci_dev;

	if (!pci_priv)
		return -ENODEV;
	
	pci_dev = pci_priv->pci_dev;
	if (!pci_dev)
		return -ENODEV;

	return pm_request_resume(&pci_dev->dev);
}

int cnss_pci_alloc_fw_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *fw_mem = plat_priv->fw_mem;
	int i;
	size_t alloc_size;
	const uint32_t align = FW_MEM_DEFAULT_ALIGNMENT - 1;

	for (i = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (!fw_mem[i].va && fw_mem[i].size) {
			alloc_size = fw_mem[i].size + align;
			fw_mem[i].pre_aligned=
				cnss_dma_alloc_coherent(&pci_priv->pci_dev->dev,
						   alloc_size,
						   &fw_mem[i].phys_addr, GFP_KERNEL);
			if (!fw_mem[i].pre_aligned) {
				cnss_pr_err("Failed to allocate memory for FW, size: 0x%zx, type: %u\n",
					    fw_mem[i].size, fw_mem[i].type);

				return -ENOMEM;
			}

			cnss_pr_dbg("pre_aligned %p, phys_addr %llx\n", fw_mem[i].pre_aligned, (u64)fw_mem[i].phys_addr);
			fw_mem[i].pa = (fw_mem[i].phys_addr + align) & ~align;
			cnss_pr_dbg("pa %llx\n", (u64)fw_mem[i].pa);

			fw_mem[i].va = fw_mem[i].pre_aligned + (fw_mem[i].pa - fw_mem[i].phys_addr);

#ifdef CONFIG_NAPIER_X86
			/*
			 * This needs to be revisited if FW requests multiple
			 * segments for DDR memory as remote heap. For now
			 * it's fine since FW only asks for one single chunk.
			 */
			if (fw_mem[i].type == QMI_WLFW_MEM_TYPE_DDR_V01)
				mhi_set_fw_remote_mem(&(pci_priv->mhi_dev),
						      fw_mem[i].va,
						      fw_mem[i].size);
#endif
		}
	}

	return 0;
}

static void cnss_pci_free_fw_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *fw_mem = plat_priv->fw_mem;
	int i;
	size_t alloc_size;
	const uint32_t align = FW_MEM_DEFAULT_ALIGNMENT - 1;

	for (i = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (fw_mem[i].pre_aligned && fw_mem[i].size) {
			cnss_pr_dbg("Freeing memory for FW, va: 0x%pK, pa: %pa, size: 0x%zx, type: %u\n",
				    fw_mem[i].va, &fw_mem[i].pa,
				    fw_mem[i].size, fw_mem[i].type);
			alloc_size = fw_mem[i].size + align;
			cnss_dma_free_coherent(&pci_priv->pci_dev->dev,
					  alloc_size, fw_mem[i].pre_aligned,
					  fw_mem[i].phys_addr);
			fw_mem[i].va = NULL;
			fw_mem[i].pa = 0;
			fw_mem[i].size = 0;
			fw_mem[i].type = 0;
			fw_mem[i].pre_aligned = NULL;
			fw_mem[i].phys_addr = 0;
		}
	}

	plat_priv->fw_mem_seg_len = 0;
}

extern unsigned int qmi_lvl_version;
int cnss_pci_load_m3(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *m3_mem = &plat_priv->m3_mem;
	char filename[MAX_M3_FILE_NAME_LENGTH];
	const struct firmware *fw_entry;
	int ret = 0;

	if (!m3_mem->va && !m3_mem->size) {
		snprintf(filename, sizeof(filename), DEFAULT_M3_FILE_NAME);
		if(qmi_lvl_version == 0x266){
		ret = request_firmware(&fw_entry, filename,
				       &pci_priv->pci_dev->dev);
		if (ret) {
			cnss_pr_err("Failed to load M3 image: %s\n", filename);
			return ret;
		  }
	        }
		m3_mem->va = cnss_dma_alloc_coherent(&pci_priv->pci_dev->dev,
						fw_entry->size, &m3_mem->pa,
						GFP_KERNEL);
		if (!m3_mem->va) {
			cnss_pr_err("Failed to allocate memory for M3, size: 0x%zx\n",
				    fw_entry->size);
			release_firmware(fw_entry);
			return -ENOMEM;
		}

		memcpy(m3_mem->va, fw_entry->data, fw_entry->size);
		m3_mem->size = fw_entry->size;
		release_firmware(fw_entry);
	}

	return 0;
}

void cnss_pci_free_m3_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *m3_mem = &plat_priv->m3_mem;

	if (m3_mem->va && m3_mem->size) {
		cnss_pr_dbg("Freeing memory for M3, va: 0x%pK, pa: %pa, size: 0x%zx\n",
			    m3_mem->va, &m3_mem->pa, m3_mem->size);
		cnss_dma_free_coherent(&pci_priv->pci_dev->dev, m3_mem->size,
				  m3_mem->va, m3_mem->pa);
	}

	m3_mem->va = NULL;
	m3_mem->pa = 0;
	m3_mem->size = 0;
}

int cnss_pci_force_fw_assert_hdlr(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;
	int ret;

	if (!pci_priv)
		return -ENODEV;
	
	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -ENODEV;

	if (test_bit(CNSS_MHI_RDDM_DONE, &pci_priv->mhi_state)) {
		cnss_pr_err("RDDM already collected 0x%lx, return\n",
			pci_priv->mhi_state);
		return 0;
	}

	ret = cnss_pci_set_mhi_state(pci_priv,
				     CNSS_MHI_TRIGGER_RDDM);
	if (ret) {
		cnss_pr_err("Failed to trigger RDDM, err = %d\n", ret);
		cnss_schedule_recovery(&pci_priv->pci_dev->dev, CNSS_REASON_DEFAULT);
		return 0;
	}

	if (!test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state)) {
		mod_timer(&plat_priv->fw_boot_timer,
			  jiffies + msecs_to_jiffies(FW_ASSERT_TIMEOUT));
	}
	return 0;
}

void cnss_pci_fw_boot_timeout_hdlr(struct cnss_pci_data *pci_priv)
{
	if (!pci_priv)
		return;
	cnss_pr_err("Timeout waiting for FW ready indication\n");

	cnss_schedule_recovery(&pci_priv->pci_dev->dev, CNSS_REASON_TIMEOUT);
}

int cnss_get_soc_info(struct device *dev, struct cnss_soc_info *info)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(dev);
	void *bus_priv = cnss_bus_dev_to_bus_priv(dev);

	if (!plat_priv)
		return -ENODEV;

	if (!bus_priv)
		return -ENODEV;

	ret = cnss_pci_get_bar_info(bus_priv, &info->va, &info->pa);
	if (ret)
		return ret;

	return 0;
}
cnss_export_symbol(cnss_get_soc_info);

int cnss_pci_get_bar_info(struct cnss_pci_data *pci_priv, void __iomem **va,
			  phys_addr_t *pa)
{
	if (!pci_priv)
		return -ENODEV;

	*va = pci_priv->bar;
	*pa = pci_resource_start(pci_priv->pci_dev, PCI_BAR_NUM);

	return 0;
}

struct dma_iommu_mapping *cnss_smmu_get_mapping(struct device *dev)
{
#ifndef CONFIG_NAPIER_X86
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));

	if (!pci_priv)
		return NULL;

	return pci_priv->smmu_mapping;
#else
	return NULL;
#endif
}
cnss_export_symbol(cnss_smmu_get_mapping);

int cnss_smmu_map(struct device *dev,
		  phys_addr_t paddr, uint32_t *iova_addr, size_t size)
{
#ifndef CONFIG_NAPIER_X86
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));
	unsigned long iova;
	size_t len;
	int ret = 0;

	if (!pci_priv)
		return -ENODEV;

	if (!iova_addr) {
		cnss_pr_err("iova_addr is NULL, paddr %pa, size %zu\n",
			    &paddr, size);
		return -EINVAL;
	}

	len = roundup(size + paddr - rounddown(paddr, PAGE_SIZE), PAGE_SIZE);
	iova = roundup(pci_priv->smmu_iova_ipa_start, PAGE_SIZE);

	if (iova >=
	    (pci_priv->smmu_iova_ipa_start + pci_priv->smmu_iova_ipa_len)) {
		cnss_pr_err("No IOVA space to map, iova %lx, smmu_iova_ipa_start %pad, smmu_iova_ipa_len %zu\n",
			    iova,
			    &pci_priv->smmu_iova_ipa_start,
			    pci_priv->smmu_iova_ipa_len);
		return -ENOMEM;
	}

	ret = iommu_map(pci_priv->smmu_mapping->domain, iova,
			rounddown(paddr, PAGE_SIZE), len,
			IOMMU_READ | IOMMU_WRITE);
	if (ret) {
		cnss_pr_err("PA to IOVA mapping failed, ret %d\n", ret);
		return ret;
	}

	pci_priv->smmu_iova_ipa_start = iova + len;
	*iova_addr = (uint32_t)(iova + paddr - rounddown(paddr, PAGE_SIZE));
#endif
	return 0;
}
cnss_export_symbol(cnss_smmu_map);

struct iommu_domain *cnss_smmu_get_domain(struct device *dev)
{
	return NULL;
}
cnss_export_symbol(cnss_smmu_get_domain);

#ifndef CONFIG_ONE_MSI_VECTOR
static struct cnss_msi_config msi_config = {
	.total_vectors = 32,
	.total_users = 4,
	.users = (struct cnss_msi_user[]) {
		{ .name = "MHI", .num_vectors = 2, .base_vector = 0 },
		{ .name = "CE", .num_vectors = 11, .base_vector = 2 },
		{ .name = "WAKE", .num_vectors = 1, .base_vector = 13 },
		{ .name = "DP", .num_vectors = 18, .base_vector = 14 },
	},
};
#else
static struct cnss_msi_config msi_config = {
	.total_vectors = 1,
	.total_users = 4,
	.users = (struct cnss_msi_user[]) {
		{ .name = "MHI", .num_vectors = 1, .base_vector = 0 },
		{ .name = "CE", .num_vectors = 1, .base_vector = 0 },
		{ .name = "WAKE", .num_vectors = 1, .base_vector = 0 },
		{ .name = "DP", .num_vectors = 1, .base_vector = 0 },
	},
};
#endif

static int cnss_pci_get_msi_assignment(struct cnss_pci_data *pci_priv)
{
	pci_priv->msi_config = &msi_config;

	return 0;
}

static int cnss_pci_enable_msi(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	int num_vectors;
	struct cnss_msi_config *msi_config;
	struct msi_desc *msi_desc;

	ret = cnss_pci_get_msi_assignment(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to get MSI assignment, err = %d\n", ret);
		goto out;
	}

	msi_config = pci_priv->msi_config;
	if (!msi_config) {
		cnss_pr_err("msi_config is NULL!\n");
		ret = -EINVAL;
		goto out;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0))
	num_vectors = pci_alloc_irq_vectors(pci_dev,
					    msi_config->total_vectors,
					    msi_config->total_vectors,
					    PCI_IRQ_MSI);
#else

	num_vectors = pci_enable_msi_range(pci_dev,
					  msi_config->total_vectors,
					  msi_config->total_vectors);
#endif
	if (num_vectors != msi_config->total_vectors) {
		cnss_pr_err("Failed to get enough MSI vectors (%d), available vectors = %d",
			    msi_config->total_vectors, num_vectors);
		ret = -EINVAL;
		goto reset_msi_config;
	}

	msi_desc = irq_get_msi_desc(pci_dev->irq);
	if (!msi_desc) {
		cnss_pr_err("msi_desc is NULL!\n");
		ret = -EINVAL;
		goto disable_msi;
	}

	pci_priv->msi_ep_base_data = msi_desc->msg.data;
#ifndef CONFIG_NAPIER_X86
	if (!pci_priv->msi_ep_base_data) {
		cnss_pr_err("Got 0 MSI base data!\n");
		CNSS_ASSERT(0);
	}
#endif

	cnss_pr_dbg("MSI base data is %d\n", pci_priv->msi_ep_base_data);

	return 0;

disable_msi:
	pci_disable_msi(pci_priv->pci_dev);
reset_msi_config:
	pci_priv->msi_config = NULL;
out:
	return ret;
}

static void cnss_pci_disable_msi(struct cnss_pci_data *pci_priv)
{
	pci_disable_msi(pci_priv->pci_dev);
}

int cnss_get_user_msi_assignment(struct device *dev, char *user_name,
				 int *num_vectors, u32 *user_base_data,
				 u32 *base_vector)
{
	struct cnss_pci_data *pci_priv = dev_get_drvdata(dev);
	struct cnss_msi_config *msi_config;
	int idx;

	if (!pci_priv)
		return -ENODEV;

	msi_config = pci_priv->msi_config;
	if (!msi_config) {
		cnss_pr_err("MSI is not supported.\n");
		return -EINVAL;
	}

	for (idx = 0; idx < msi_config->total_users; idx++) {
		if (strcmp(user_name, msi_config->users[idx].name) == 0) {
			*num_vectors = msi_config->users[idx].num_vectors;
			*user_base_data = msi_config->users[idx].base_vector
				+ pci_priv->msi_ep_base_data;
			*base_vector = msi_config->users[idx].base_vector;

			cnss_pr_dbg("Assign MSI to user: %s, num_vectors: %d, user_base_data: %u, base_vector: %u\n",
				    user_name, *num_vectors, *user_base_data,
				    *base_vector);

			return 0;
		}
	}

	cnss_pr_err("Failed to find MSI assignment for %s!\n", user_name);

	return -EINVAL;
}
cnss_export_symbol(cnss_get_user_msi_assignment);

int cnss_get_msi_irq(struct device *dev, unsigned int vector)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);

	return pci_dev->irq + vector;
}
cnss_export_symbol(cnss_get_msi_irq);

void cnss_get_msi_address(struct device *dev, u32 *msi_addr_low,
			  u32 *msi_addr_high)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	u16 control;

	pci_read_config_word(pci_dev, pci_dev->msi_cap + PCI_MSI_FLAGS,
			     &control);
	pci_read_config_dword(pci_dev, pci_dev->msi_cap + PCI_MSI_ADDRESS_LO,
			      msi_addr_low);
	/*return msi high addr only when device support 64 BIT MSI */
	if (control & PCI_MSI_FLAGS_64BIT)
		pci_read_config_dword(pci_dev,
				      pci_dev->msi_cap + PCI_MSI_ADDRESS_HI,
				      msi_addr_high);
	else
		*msi_addr_high = 0;
	cnss_pr_dbg("msi low addr %x high addr %x\n", *msi_addr_low, *msi_addr_high);
}
cnss_export_symbol(cnss_get_msi_address);

static char *get_wake_msi_name(void)
{
	return (char *)WAKE_MSI_NAME;
}

u32 cnss_pci_get_wake_msi(struct cnss_pci_data *pci_priv)
{
	int ret, num_vectors;
	u32 user_base_data, base_vector;
	char *wake_msi_name = get_wake_msi_name();

	ret = cnss_get_user_msi_assignment(&pci_priv->pci_dev->dev,
					   wake_msi_name, &num_vectors,
					   &user_base_data, &base_vector);
	if (ret) {
		cnss_pr_err("WAKE MSI is not valid\n");
		return 0;
	}

	return user_base_data;
}

static int cnss_pci_enable_bus(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	u16 device_id;
	u32 pci_dma_mask = PCI_DMA_MASK_32_BIT;

	pci_read_config_word(pci_dev, PCI_DEVICE_ID, &device_id);
	if (device_id != pci_priv->pci_device_id->device)  {
		cnss_pr_err("PCI device ID mismatch, config ID: 0x%x, probe ID: 0x%x\n",
			    device_id, pci_priv->pci_device_id->device);
		ret = -EIO;
		goto out;
	}

	ret = pci_assign_resource(pci_dev, PCI_BAR_NUM);
	if (ret) {
		pr_err("Failed to assign PCI resource, err = %d\n", ret);
		goto out;
	}

	ret = pci_enable_device(pci_dev);
	if (ret) {
		cnss_pr_err("Failed to enable PCI device, err = %d\n", ret);
		goto out;
	}

	ret = pci_request_region(pci_dev, PCI_BAR_NUM, "cnss");
	if (ret) {
		cnss_pr_err("Failed to request PCI region, err = %d\n", ret);
		goto disable_device;
	}

	if (device_id == QCA6174_DEVICE_ID)
		pci_dma_mask = PCI_DMA_MASK_32_BIT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	ret = dma_set_mask_and_coherent(&pci_dev->dev, DMA_BIT_MASK(pci_dma_mask));
	if (ret) {
		cnss_pr_err("Failed to set PCI DMA mask (%d), err = %d\n",
				ret, pci_dma_mask);
		goto release_region;
	}
#else
	ret = pci_set_dma_mask(pci_dev, DMA_BIT_MASK(pci_dma_mask));
	if (ret) {
		cnss_pr_err("Failed to set PCI DMA mask (%d), err = %d\n",
			    ret, pci_dma_mask);
		goto release_region;
	}
#endif//turbo add

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	ret = dma_set_mask_and_coherent(&pci_dev->dev, DMA_BIT_MASK(pci_dma_mask));
#else
	ret = pci_set_consistent_dma_mask(pci_dev, DMA_BIT_MASK(pci_dma_mask));
#endif//tubo add
	if (ret) {
		cnss_pr_err("Failed to set PCI consistent DMA mask (%d), err = %d\n",
			    ret, pci_dma_mask);
		goto release_region;
	}

	pci_set_master(pci_dev);

	pci_priv->bar = pci_iomap(pci_dev, PCI_BAR_NUM, 0);
	if (!pci_priv->bar) {
		cnss_pr_err("Failed to do PCI IO map!\n");
		ret = -EIO;
		goto clear_master;
	}
	return 0;

clear_master:
	pci_clear_master(pci_dev);
release_region:
	pci_release_region(pci_dev, PCI_BAR_NUM);
disable_device:
	pci_disable_device(pci_dev);
out:
	return ret;
}

static void cnss_pci_disable_bus(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;

	if (pci_priv->bar) {
		pci_iounmap(pci_dev, pci_priv->bar);
		pci_priv->bar = NULL;
	}

	pci_clear_master(pci_dev);
	pci_release_region(pci_dev, PCI_BAR_NUM);
	if (pci_is_enabled(pci_dev))
		pci_disable_device(pci_dev);
}

static int cnss_mhi_pm_runtime_get(struct pci_dev *pci_dev)
{
	return pm_runtime_get(&pci_dev->dev);
}

static void cnss_mhi_pm_runtime_put_noidle(struct pci_dev *pci_dev)
{
	pm_runtime_put_noidle(&pci_dev->dev);
}

static char *cnss_mhi_state_to_str(enum cnss_mhi_state mhi_state)
{
	switch (mhi_state) {
	case CNSS_MHI_INIT:
		return "INIT";
	case CNSS_MHI_DEINIT:
		return "DEINIT";
	case CNSS_MHI_POWER_ON:
		return "POWER_ON";
	case CNSS_MHI_POWER_OFF:
		return "POWER_OFF";
	case CNSS_MHI_SUSPEND:
		return "SUSPEND";
	case CNSS_MHI_RESUME:
		return "RESUME";
	case CNSS_MHI_TRIGGER_RDDM:
		return "TRIGGER_RDDM";
	case CNSS_MHI_RDDM:
		return "RDDM";
	case CNSS_MHI_RDDM_KERNEL_PANIC:
		return "RDDM_KERNEL_PANIC";
	case CNSS_MHI_NOTIFY_LINK_ERROR:
		return "NOTIFY_LINK_ERROR";
	case CNSS_MHI_RDDM_DONE:
		return "RDDM_DONE";
	default:
		return "UNKNOWN";
	}
};

static void *cnss_pci_collect_dump_seg(struct cnss_pci_data *pci_priv,
				       enum mhi_rddm_segment type,
				       void *start_addr)
{
	int count;
	struct scatterlist *sg_list, *s;
	unsigned int i;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_dump_data *dump_data =
		&plat_priv->ramdump_info_v2.dump_data;
	struct cnss_dump_seg *dump_seg = start_addr, header_seg = {0};
	int index = 0;

	count = mhi_xfer_rddm(&pci_priv->mhi_dev, type, &sg_list);
	if (count <= 0 || !sg_list) {
		cnss_pr_err("Invalid dump_seg for type %u, count %u, sg_list %pK\n",
			    type, count, sg_list);
		return start_addr;
	}

	cnss_pr_dbg("Collect dump seg: type %u, nentries %d\n", type, count);

	for_each_sg(sg_list, s, count, i) {
		if (i == 0) {
			header_seg.address = sg_dma_address(s);
			header_seg.v_address = sg_virt(s);
			header_seg.size = s->length;
			header_seg.type = type;
			continue;
		}
		dump_seg->address = sg_dma_address(s);
		dump_seg->v_address = sg_virt(s);
		dump_seg->size = s->length;
		dump_seg->type = type;
		cnss_pr_dbg("seg-%d: address 0x%lx, v_address %pK, size 0x%lx\n",
			    index, dump_seg->address,
			    dump_seg->v_address, dump_seg->size);
		dump_seg++;
		index++;
	}

	dump_seg->address = header_seg.address;
	dump_seg->v_address = header_seg.v_address;
	dump_seg->size = header_seg.size;
	dump_seg->type = header_seg.type;
	cnss_pr_dbg("seg-%d: address 0x%lx, v_address %pK, size 0x%lx\n",
			index, dump_seg->address,
			dump_seg->v_address, dump_seg->size);
	dump_seg++;
	index++;

	dump_data->nentries += count;

	return dump_seg;
}

void cnss_pci_collect_dump_info(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_dump_data *dump_data =
		&plat_priv->ramdump_info_v2.dump_data;
	void *start_addr, *end_addr;
	struct cnss_fw_mem *fw_mem = plat_priv->fw_mem;
	struct cnss_dump_seg *dump_seg;
	int i;

	dump_data->nentries = 0;

	start_addr = plat_priv->ramdump_info_v2.dump_data_vaddr;
	end_addr = cnss_pci_collect_dump_seg(pci_priv,
					     MHI_RDDM_FW_SEGMENT, start_addr);

	start_addr = end_addr;
	end_addr = cnss_pci_collect_dump_seg(pci_priv,
					     MHI_RDDM_RD_SEGMENT, start_addr);

	cnss_pr_dbg("Collect remote heap dump segment\n");
	dump_seg = end_addr;

	for (i = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (fw_mem[i].type == QMI_WLFW_MEM_TYPE_DDR_V01) {
			dump_seg->address = fw_mem[i].pa;
			dump_seg->v_address = fw_mem[i].va;
			dump_seg->size = fw_mem[i].size;
			dump_seg->type = 2;
			cnss_pr_dbg("seg-%d: address 0x%lx, v_address %pK, size 0x%lx\n",
				    i, dump_seg->address, dump_seg->v_address,
				    dump_seg->size);
			dump_seg++;
			dump_data->nentries++;
		}
	}

	if (dump_data->nentries > 0)
		plat_priv->ramdump_info_v2.dump_data_valid = true;

	cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_RDDM_DONE);
	complete(&plat_priv->rddm_complete);

	/* Dump QDSS reg after RDDM dump complete */
	cnss_pci_dump_qdss_reg(pci_priv);
}

void cnss_pci_clear_dump_info(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	plat_priv->ramdump_info_v2.dump_data.nentries = 0;
	plat_priv->ramdump_info_v2.dump_data_valid = false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#define vfs_write kernel_write
#endif

int cnss_pci_fw_sram_dump_to_file(struct cnss_pci_data *pci_priv,
		uint32_t fw_sram_start,
		uint32_t fw_sram_end,
		const char *fw_sram_dump_path)
{
	struct mhi_device_ctxt *mhi_dev_ctxt;
	struct file *fp = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) || (defined(CONFIG_SET_FS))
	mm_segment_t fs;
#endif
	uint32_t offset;
	loff_t pos = 0;
	int status;

	if (!pci_priv) {
		cnss_pr_err("FW sram dump pci_priv is NULL\n");
		return -ENODEV;
	}

	mhi_dev_ctxt = pci_priv->mhi_dev.mhi_dev_ctxt;
	if (!mhi_dev_ctxt) {
		cnss_pr_err("FW sram dump pci_priv is NULL\n");
		return -ENODEV;
	}

	fp = filp_open(fw_sram_dump_path, O_RDWR | O_CREAT, 0644);
	if (IS_ERR(fp)) {
		cnss_pr_err("FW sram dump create file %s failed\n",
				fw_sram_dump_path);
		return -EACCES;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) || (defined(CONFIG_SET_FS))
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	pos = 0;

	for (offset = fw_sram_start; offset < fw_sram_end; offset += 4) {
		uint32_t val = mhi_reg_read_remap(mhi_dev_ctxt,
				mhi_dev_ctxt->mmio_info.mmio_addr, offset);

		status = vfs_write(fp, (char *)&val, sizeof(uint32_t), &pos);
		if (status < 0) {
			cnss_pr_err("FW sram dump write file %s failed: %d\n",
					fw_sram_dump_path, status);
			goto out;
		}
	}

	vfs_fsync(fp, 0);

out:
	status = filp_close(fp, NULL);
	if (status < 0) {
		cnss_pr_err("FW sram dump close file %s failed: %d\n",
				fw_sram_dump_path, status);
		return status;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) || (defined(CONFIG_SET_FS))
	set_fs(fs);
#endif

	return status;
}

int cnss_pci_dump_fw_remote_mem_to_file(struct cnss_pci_data *pci_priv)
{
	struct mhi_device_ctxt *mhi_dev_ctxt = pci_priv->mhi_dev.mhi_dev_ctxt;
	struct bhi_ctxt_t *bhi_ctxt = &mhi_dev_ctxt->bhi_ctxt;

	return fw_remote_mem_dump(mhi_dev_ctxt, &bhi_ctxt->fw_mem, "/var/crash/remote.bin");
}

int cnss_pci_dump_fw_paging_to_file(struct cnss_pci_data *pci_priv)
{
	struct mhi_device_ctxt *mhi_dev_ctxt = pci_priv->mhi_dev.mhi_dev_ctxt;
	struct bhi_ctxt_t *bhi_ctxt = &mhi_dev_ctxt->bhi_ctxt;
	struct bhie_vec_table *fw_table = &bhi_ctxt->fw_table;

	return fw_paging_dump(mhi_dev_ctxt, fw_table, "/var/crash/paging.bin");
}

static void cnss_mhi_notify_status(enum MHI_CB_REASON reason, void *priv)
{
	struct cnss_pci_data *pci_priv = priv;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	enum cnss_recovery_reason cnss_reason = CNSS_REASON_RDDM;

	if (!pci_priv)
		return;

	cnss_pr_dbg("MHI status cb is called with reason %d\n", reason);

	if (test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state)) {
		cnss_pr_dbg("Driver is in recovery, ignore");
		return;
	}

	if (pci_priv->driver_ops && pci_priv->driver_ops->update_status)
		pci_priv->driver_ops->update_status(pci_priv->pci_dev,
						     CNSS_FW_DOWN);

	set_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state);
	del_timer(&plat_priv->fw_boot_timer);

	if (reason == MHI_CB_SYS_ERROR)
		cnss_reason = CNSS_REASON_TIMEOUT;

	cnss_schedule_recovery(&pci_priv->pci_dev->dev,
			       cnss_reason);
}

static int cnss_pci_register_mhi(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct mhi_device *mhi_dev = &pci_priv->mhi_dev;

#ifndef CONFIG_NAPIER_X86
	mhi_dev->dev = &pci_priv->plat_priv->plat_dev->dev;
#endif
	mhi_dev->pci_dev = pci_dev;

	mhi_dev->resources[0].start = (resource_size_t)pci_priv->bar;
	mhi_dev->resources[0].end = (resource_size_t)pci_priv->bar +
		pci_resource_len(pci_dev, PCI_BAR_NUM);
	mhi_dev->resources[0].flags =
		pci_resource_flags(pci_dev, PCI_BAR_NUM);
	mhi_dev->resources[0].name = "BAR";
	cnss_pr_dbg("BAR start is %pa, BAR end is %pa\n",
		    &mhi_dev->resources[0].start, &mhi_dev->resources[0].end);

	if (!mhi_dev->resources[1].start) {
		mhi_dev->resources[1].start = pci_dev->irq;
#ifndef CONFIG_ONE_MSI_VECTOR
		mhi_dev->resources[1].end = pci_dev->irq + 1;
#else
		mhi_dev->resources[1].end = pci_dev->irq;
#endif
		mhi_dev->resources[1].flags = IORESOURCE_IRQ;
		mhi_dev->resources[1].name = "IRQ";
	}
	cnss_pr_dbg("IRQ start is %pa, IRQ end is %pa\n",
		    &mhi_dev->resources[1].start, &mhi_dev->resources[1].end);

	mhi_dev->pm_runtime_get = cnss_mhi_pm_runtime_get;
	mhi_dev->pm_runtime_put_noidle = cnss_mhi_pm_runtime_put_noidle;
	if (rddm_support) {
		mhi_dev->support_rddm = true;
#ifdef CONFIG_NAPIER_X86
#ifdef CONFIG_CNSS_QCA6490
		mhi_dev->rddm_size = 0x420000;
#else
		if (pci_dev->device == QCN7605_DEVICE_ID)
			mhi_dev->rddm_size = 0x300000;
		else
			mhi_dev->rddm_size = 0x400000;
#endif
		pr_err("rddm size %zx", mhi_dev->rddm_size);
#else
		mhi_dev->rddm_size = pci_priv->plat_priv->ramdump_info_v2.ramdump_size;
#endif
	}
	mhi_dev->status_cb = cnss_mhi_notify_status;

	ret = mhi_register_device(mhi_dev, MHI_NODE_NAME, pci_priv);
	if (ret) {
		cnss_pr_err("Failed to register as MHI device, err = %d\n",
			    ret);
		return ret;
	}

	return 0;
}

static void cnss_pci_unregister_mhi(struct cnss_pci_data *pci_priv)
{
	struct mhi_device *mhi_dev = &pci_priv->mhi_dev;

	mhi_deregister_device(mhi_dev);
}

static enum mhi_dev_ctrl cnss_to_mhi_dev_state(enum cnss_mhi_state state)
{
	switch (state) {
	case CNSS_MHI_INIT:
		return MHI_DEV_CTRL_INIT;
	case CNSS_MHI_DEINIT:
		return MHI_DEV_CTRL_DE_INIT;
	case CNSS_MHI_POWER_ON:
		return MHI_DEV_CTRL_POWER_ON;
	case CNSS_MHI_POWER_OFF:
		return MHI_DEV_CTRL_POWER_OFF;
	case CNSS_MHI_SUSPEND:
		return MHI_DEV_CTRL_SUSPEND;
	case CNSS_MHI_RESUME:
		return MHI_DEV_CTRL_RESUME;
	case CNSS_MHI_TRIGGER_RDDM:
		return MHI_DEV_CTRL_TRIGGER_RDDM;
	case CNSS_MHI_RDDM:
		return MHI_DEV_CTRL_RDDM;
	case CNSS_MHI_RDDM_KERNEL_PANIC:
		return MHI_DEV_CTRL_RDDM_KERNEL_PANIC;
	case CNSS_MHI_NOTIFY_LINK_ERROR:
		return MHI_DEV_CTRL_NOTIFY_LINK_ERROR;
	default:
		cnss_pr_err("Unknown CNSS MHI state (%d)\n", state);
		return -EINVAL;
	}
}

static int cnss_pci_check_mhi_state_bit(struct cnss_pci_data *pci_priv,
					enum cnss_mhi_state mhi_state)
{
	switch (mhi_state) {
	case CNSS_MHI_INIT:
		if (!test_bit(CNSS_MHI_INIT, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_DEINIT:
	case CNSS_MHI_POWER_ON:
		if (test_bit(CNSS_MHI_INIT, &pci_priv->mhi_state) &&
		    !test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_POWER_OFF:
	case CNSS_MHI_SUSPEND:
		if (test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state) &&
		    !test_bit(CNSS_MHI_SUSPEND, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_RESUME:
		if (test_bit(CNSS_MHI_SUSPEND, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_TRIGGER_RDDM:
	case CNSS_MHI_RDDM:
	case CNSS_MHI_RDDM_KERNEL_PANIC:
	case CNSS_MHI_NOTIFY_LINK_ERROR:
	case CNSS_MHI_RDDM_DONE:
		return 0;
	default:
		cnss_pr_err("Unhandled MHI state: %s(%d)\n",
			    cnss_mhi_state_to_str(mhi_state), mhi_state);
	}

	cnss_pr_err("Cannot set MHI state %s(%d) in current MHI state (0x%lx)\n",
		    cnss_mhi_state_to_str(mhi_state), mhi_state,
		    pci_priv->mhi_state);

	return -EINVAL;
}

static void cnss_pci_set_mhi_state_bit(struct cnss_pci_data *pci_priv,
				       enum cnss_mhi_state mhi_state)
{
	switch (mhi_state) {
	case CNSS_MHI_INIT:
		set_bit(CNSS_MHI_INIT, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_DEINIT:
		clear_bit(CNSS_MHI_INIT, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_POWER_ON:
		set_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_POWER_OFF:
		clear_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state);
		clear_bit(CNSS_MHI_RDDM_DONE, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_SUSPEND:
		set_bit(CNSS_MHI_SUSPEND, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_RESUME:
		clear_bit(CNSS_MHI_SUSPEND, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_TRIGGER_RDDM:
	case CNSS_MHI_RDDM:
	case CNSS_MHI_RDDM_KERNEL_PANIC:
	case CNSS_MHI_NOTIFY_LINK_ERROR:
		break;
	case CNSS_MHI_RDDM_DONE:
		set_bit(CNSS_MHI_RDDM_DONE, &pci_priv->mhi_state);
		break;
	default:
		cnss_pr_err("Unhandled MHI state (%d)\n", mhi_state);
	}
}

int cnss_pci_set_mhi_state(struct cnss_pci_data *pci_priv,
			   enum cnss_mhi_state mhi_state)
{
	int ret = 0;
	enum mhi_dev_ctrl mhi_dev_state = cnss_to_mhi_dev_state(mhi_state);

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL!\n");
		return -ENODEV;
	}

	if (pci_priv->device_id == QCA6174_DEVICE_ID)
		return 0;

	if (mhi_dev_state < 0) {
		cnss_pr_err("Invalid MHI DEV state (%d)\n", mhi_dev_state);
		return -EINVAL;
	}

	ret = cnss_pci_check_mhi_state_bit(pci_priv, mhi_state);
	if (ret)
		goto out;

	cnss_pr_dbg("Setting MHI state: %s(%d)\n",
		    cnss_mhi_state_to_str(mhi_state), mhi_state);
	ret = mhi_pm_control_device(&pci_priv->mhi_dev, mhi_dev_state);
	if (ret) {
		cnss_pr_err("Failed to set MHI state: %s(%d)\n",
			    cnss_mhi_state_to_str(mhi_state), mhi_state);
		goto out;
	}

	cnss_pci_set_mhi_state_bit(pci_priv, mhi_state);

out:
	return ret;
}

int cnss_pci_start_mhi(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL!\n");
		return -ENODEV;
	}

	if (fbc_bypass)
		return 0;

	ret = cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_INIT);
	if (ret)
		goto out;

	ret = cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_POWER_ON);
	if (ret)
		goto out;

	return 0;

out:
	return ret;
}

void cnss_pci_stop_mhi(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL!\n");
		return;
	}

	if (fbc_bypass)
		return;

	plat_priv = pci_priv->plat_priv;

	cnss_pci_set_mhi_state_bit(pci_priv, CNSS_MHI_RESUME);
	if (!test_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state))
		cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_POWER_OFF);

	if (plat_priv->ramdump_info_v2.dump_data_valid ||
	    test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state))
		return;

	if (!test_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state))
		cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_DEINIT);
}

static int cnss_pci_probe(struct pci_dev *pci_dev,
			  const struct pci_device_id *id)
{
	int ret = 0;
	struct cnss_pci_data *pci_priv;
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(NULL);
	struct resource *res;
	u8 aspm_state;

	cnss_pr_dbg("PCI is probing, vendor ID: 0x%x, device ID: 0x%x\n",
		    id->vendor, pci_dev->device);

	switch (pci_dev->device) {
	case QCA6290_EMULATION_DEVICE_ID:
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case QCN7605_DEVICE_ID:
#ifdef CONFIG_NAPIER_X86
		UNUSED(res);
		if (!mhi_is_device_ready(NULL, MHI_NODE_NAME)) {
#else
		if (!mhi_is_device_ready(&plat_priv->plat_dev->dev,
					 MHI_NODE_NAME)) {
#endif
			cnss_pr_err("MHI driver is not ready, defer PCI probe!\n");
			ret = -EPROBE_DEFER;
			goto out;
		}
		break;
	default:
		break;
	}

	pci_priv = devm_kzalloc(&pci_dev->dev, sizeof(*pci_priv),
				GFP_KERNEL);
	if (!pci_priv) {
		ret = -ENOMEM;
		goto out;
	}

	pci_priv->pci_link_state = PCI_LINK_UP;
	pci_priv->plat_priv = plat_priv;
	pci_priv->pci_dev = pci_dev;
	pci_priv->pci_device_id = id;
	pci_priv->device_id = pci_dev->device;
	cnss_set_pci_priv(pci_dev, pci_priv);
	plat_priv->device_id = pci_dev->device;
	plat_priv->bus_priv = pci_priv;

	ret = cnss_register_subsys(plat_priv);
	if (ret)
		goto reset_ctx;

	ret = cnss_register_ramdump(plat_priv);
	if (ret)
		goto unregister_subsys;
#ifndef CONFIG_NAPIER_X86
	res = platform_get_resource_byname(plat_priv->plat_dev, IORESOURCE_MEM,
					   "smmu_iova_base");
	if (res) {
		pci_priv->smmu_iova_start = res->start;
		pci_priv->smmu_iova_len = resource_size(res);
		cnss_pr_dbg("smmu_iova_start: %pa, smmu_iova_len: %zu\n",
			    &pci_priv->smmu_iova_start,
			    pci_priv->smmu_iova_len);

		res = platform_get_resource_byname(plat_priv->plat_dev,
						   IORESOURCE_MEM,
						   "smmu_iova_ipa");
		if (res) {
			pci_priv->smmu_iova_ipa_start = res->start;
			pci_priv->smmu_iova_ipa_len = resource_size(res);
			cnss_pr_dbg("smmu_iova_ipa_start: %pa, smmu_iova_ipa_len: %zu\n",
				    &pci_priv->smmu_iova_ipa_start,
				    pci_priv->smmu_iova_ipa_len);
		}

		ret = cnss_pci_init_smmu(pci_priv);
		if (ret) {
			cnss_pr_err("Failed to init SMMU, err = %d\n", ret);
			goto unregister_ramdump;
		}
	}

	ret = cnss_reg_pci_event(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to register PCI event, err = %d\n", ret);
		goto deinit_smmu;
	}
#endif

	ret = cnss_pci_enable_bus(pci_priv);
	if (ret)
		goto dereg_pci_event;

	cnss_pci_disable_l1(pci_priv);

	pci_save_state(pci_dev);
	pci_priv->default_state = pci_store_saved_state(pci_dev);

	switch (pci_dev->device) {
	case QCA6174_DEVICE_ID:
		pci_read_config_word(pci_dev, QCA6174_REV_ID_OFFSET,
				     &pci_priv->revision_id);
		ret = cnss_suspend_pci_link(pci_priv);
		if (ret)
			cnss_pr_err("Failed to suspend PCI link, err = %d\n",
				    ret);
		cnss_power_off_device(plat_priv);
		break;
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
		/* Disable L1SS for QCA6390 */
		pci_read_config_byte(pci_dev, 0x1F4, &aspm_state);
		cnss_pr_err("Current L1SS status: 0x%x", aspm_state);
		if ((aspm_state & 0xF) &&
		    (!test_bit(ENABLE_PCI_LINK_PS, &quirks))) {
			pci_write_config_byte(pci_dev, 0x1F4, aspm_state & ~0xF);
			pci_read_config_byte(pci_dev, 0x1F4, &aspm_state);
			cnss_pr_err("L1SS status changed to: 0x%x", aspm_state);
		}
		/* fall-thru */
	case QCA6290_EMULATION_DEVICE_ID:
	case QCA6290_DEVICE_ID:
		/*
		 * Disable L0s/L1 for QCA6290/QCA6390 always.
		 *   For QCA6290(AX), ASPM disable on EP by default.
		 *   For QCA6390, ASPM enabled, and it will cause link unstable
		 *   when attaching to ASPM enabled RC/laptop.
		 */
		pci_read_config_byte(pci_dev, 0x80, &aspm_state);
		cnss_pr_err("Current ASPM status: 0x%x", aspm_state);
		if (aspm_state & 0x3) {
			pci_write_config_byte(pci_dev, 0x80, aspm_state & ~0x3);
			pci_read_config_byte(pci_dev, 0x80, &aspm_state);
			cnss_pr_err("ASPM status changed to: %x", aspm_state);
		}
		/* fall-thru */
	case QCN7605_DEVICE_ID:
		ret = cnss_pci_enable_msi(pci_priv);
		if (ret)
			goto disable_bus;
		ret = cnss_pci_register_mhi(pci_priv);
		if (ret) {
			cnss_pci_disable_msi(pci_priv);
			goto disable_bus;
		}
#ifndef CONFIG_PCIE_EMULATION
		ret = cnss_suspend_pci_link(pci_priv);
		if (ret)
			cnss_pr_err("Failed to suspend PCI link, err = %d\n",
				    ret);
		cnss_power_off_device(plat_priv);
#endif
		break;
	default:
		cnss_pr_err("Unknown PCI device found: 0x%x\n",
			    pci_dev->device);
		ret = -ENODEV;
		goto disable_bus;
	}

	return 0;

disable_bus:
	cnss_pci_disable_bus(pci_priv);
dereg_pci_event:
#ifndef CONFIG_NAPIER_X86
	cnss_dereg_pci_event(pci_priv);
deinit_smmu:
	if (pci_priv->smmu_mapping)
		cnss_pci_deinit_smmu(pci_priv);
unregister_ramdump:
#endif
	cnss_unregister_ramdump(plat_priv);
unregister_subsys:
	cnss_unregister_subsys(plat_priv);
reset_ctx:
	plat_priv->bus_priv = NULL;
out:
	return ret;
}

static void cnss_pci_remove(struct pci_dev *pci_dev)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv =
		cnss_bus_dev_to_plat_priv(&pci_dev->dev);

	cnss_pci_free_m3_mem(pci_priv);
	cnss_pci_free_fw_mem(pci_priv);

	switch (pci_dev->device) {
	case QCA6290_EMULATION_DEVICE_ID:
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
		cnss_pci_unregister_mhi(pci_priv);
		cnss_pci_disable_msi(pci_priv);
		break;
	default:
		break;
	}

	cnss_pci_disable_bus(pci_priv);
#ifndef CONFIG_NAPIER_X86
	cnss_dereg_pci_event(pci_priv);
	if (pci_priv->smmu_mapping)
		cnss_pci_deinit_smmu(pci_priv);
#endif
	cnss_unregister_ramdump(plat_priv);
	cnss_unregister_subsys(plat_priv);
	plat_priv->bus_priv = NULL;
}

#ifdef CONFIG_NAPIER_X86
void cnss_pci_shutdown(struct pci_dev *pci_dev)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct mhi_device *mhi_dev = &pci_priv->mhi_dev;

	mhi_pcie_sw_soc_reset(mhi_dev);
}
#else
void cnss_pci_shutdown(struct pci_dev *pci_dev)
{
	return;
}
#endif

static const struct pci_device_id cnss_pci_id_table[] = {
	{ QCA6174_VENDOR_ID, QCA6174_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ QCA6290_EMULATION_VENDOR_ID, QCA6290_EMULATION_DEVICE_ID,
	  PCI_ANY_ID, PCI_ANY_ID },
	{ QCA6290_VENDOR_ID, QCA6290_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ QCA6390_VENDOR_ID, QCA6390_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ QCA6490_VENDOR_ID, QCA6490_DEVICE_ID, PCI_ANY_ID, QCA6490_SSID },
	{ QCN7605_VENDOR_ID, QCN7605_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, cnss_pci_id_table);

static const struct dev_pm_ops cnss_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(cnss_pci_suspend, cnss_pci_resume)
	SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(cnss_pci_suspend_noirq,
				      cnss_pci_resume_noirq)
	SET_RUNTIME_PM_OPS(cnss_pci_runtime_suspend, cnss_pci_runtime_resume,
			   cnss_pci_runtime_idle)
};

struct pci_driver cnss_pci_driver = {
	.name     = CNSS_PCI_DRIVER_NAME,
	.id_table = cnss_pci_id_table,
	.probe    = cnss_pci_probe,
	.remove   = cnss_pci_remove,
	.shutdown = cnss_pci_shutdown,
	.driver = {
		.pm = &cnss_pm_ops,
	},
};

int cnss_pci_init(struct cnss_plat_data *plat_priv)
{
	int ret = 0;
#ifndef CONFIG_NAPIER_X86
	struct device *dev = &plat_priv->plat_dev->dev;
	u32 rc_num;

	ret = of_property_read_u32(dev->of_node, "qcom,wlan-rc-num", &rc_num);
	if (ret) {
		cnss_pr_err("Failed to find PCIe RC number, err = %d\n", ret);
		goto out;
	}

	ret = msm_pcie_enumerate(rc_num);
	if (ret) {
		cnss_pr_err("Failed to enable PCIe RC%x, err = %d\n",
			    rc_num, ret);
		goto out;
	}
#endif
	ret = pci_register_driver(&cnss_pci_driver);
	if (ret) {
		cnss_pr_err("Failed to register to PCI framework, err = %d\n",
			    ret);
		goto out;
	}

	return 0;
out:
	return ret;
}

void cnss_pci_deinit(struct cnss_plat_data *plat_priv)
{
	pci_unregister_driver(&cnss_pci_driver);
}
