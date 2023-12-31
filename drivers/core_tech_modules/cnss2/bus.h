/* Copyright (c) 2018, The Linux Foundation. All rights reserved.
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

#ifndef _CNSS_BUS_H
#define _CNSS_BUS_H

#include "main.h"

#define QCA6174_VENDOR_ID		0x168C
#define QCA6174_DEVICE_ID		0x003E
#define QCA6174_REV_ID_OFFSET		0x08
#define QCA6174_REV3_VERSION		0x5020000
#define QCA6174_REV3_2_VERSION		0x5030000
#define QCA6290_VENDOR_ID		0x17CB
#define QCA6290_DEVICE_ID		0x1100
#define QCA6290_EMULATION_VENDOR_ID	0x168C
#define QCA6290_EMULATION_DEVICE_ID	0xABCD
#define QCA6390_VENDOR_ID		0x17CB
#define QCA6390_DEVICE_ID		0x1101
#define QCA6490_VENDOR_ID		0x17CB
#define QCA6490_DEVICE_ID		0x1103
#define QCN7605_VENDOR_ID		0x17CB
#define QCN7605_DEVICE_ID		0x1102
#define QCN7605_SDIO_VENDOR_ID		0x70
#define QCN7605_SDIO_DEVICE_ID		0x400B

#define QCN7605_USB_VENDOR_ID             0x05C6
#define QCN7605_COMPOSITE_DEVICE_ID     QCN7605_COMPOSITE_PRODUCT_ID
#define QCN7605_STANDALONE_DEVICE_ID    QCN7605_STANDALONE_PRODUCT_ID
#define QCN7605_VER20_STANDALONE_DEVICE_ID	QCN7605_VER20_STANDALONE_PID
#define QCN7605_VER20_COMPOSITE_DEVICE_ID	QCN7605_VER20_COMPOSITE_PID

#define QCN7605_STANDALONE_PRODUCT_ID    0x9900
#define QCN7605_COMPOSITE_PRODUCT_ID     0x9901

#define QCN7605_VER20_STANDALONE_PID     0x9902
#define QCN7605_VER20_COMPOSITE_PID     0x9903

enum cnss_dev_bus_type cnss_get_dev_bus_type(struct device *dev);
enum cnss_dev_bus_type cnss_get_bus_type(unsigned long device_id);
void *cnss_bus_dev_to_bus_priv(struct device *dev);
struct cnss_plat_data *cnss_bus_dev_to_plat_priv(struct device *dev);
int cnss_bus_init(struct cnss_plat_data *plat_priv);
void cnss_bus_deinit(struct cnss_plat_data *plat_priv);
int cnss_bus_load_m3(struct cnss_plat_data *plat_priv);
int cnss_bus_free_m3(struct cnss_plat_data *plat_priv);
int cnss_bus_alloc_fw_mem(struct cnss_plat_data *plat_priv);
int cnss_bus_get_wake_irq(struct cnss_plat_data *plat_priv);
int cnss_bus_force_fw_assert_hdlr(struct cnss_plat_data *plat_priv);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
void cnss_bus_fw_boot_timeout_hdlr(struct timer_list *t);
#else
void cnss_bus_fw_boot_timeout_hdlr(unsigned long data);
#endif
void cnss_bus_collect_dump_info(struct cnss_plat_data *plat_priv);
int cnss_bus_call_driver_probe(struct cnss_plat_data *plat_priv);
int cnss_bus_call_driver_remove(struct cnss_plat_data *plat_priv);
int cnss_bus_dev_powerup(struct cnss_plat_data *plat_priv);
int cnss_bus_dev_shutdown(struct cnss_plat_data *plat_priv);
int cnss_bus_dev_crash_shutdown(struct cnss_plat_data *plat_priv);
int cnss_bus_dev_ramdump(struct cnss_plat_data *plat_priv);
int cnss_bus_register_driver_hdlr(struct cnss_plat_data *plat_priv, void *data);
int cnss_bus_unregister_driver_hdlr(struct cnss_plat_data *plat_priv);
int cnss_bus_call_driver_modem_status(struct cnss_plat_data *plat_priv,
				      int modem_current_status);
int cnss_bus_recovery_update_status(struct cnss_plat_data *plat_priv);
bool cnss_bus_req_mem_ind_valid(struct cnss_plat_data *plat_priv);
int cnss_bus_fw_sram_dump_to_file(struct cnss_plat_data *plat_priv,
		uint32_t fw_sram_start,
		uint32_t fw_sram_end,
		const char *fw_sram_dump_path);
#endif /* _CNSS_BUS_H */
