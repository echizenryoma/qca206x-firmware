obj-$(CONFIG_CNSS2) += cnss2.o

cnss2-y := main.o
cnss2-y += bus.o
cnss2-y += debug.o
cnss2-$(CONFIG_CNSS2_PCIE) += pci.o
cnss2-$(CONFIG_CNSS2_USB) += usb.o
cnss2-$(CONFIG_CNSS2_SDIO) += sdio.o
cnss2-y += power.o
cnss2-y += qmi.o
cnss2-y += utils.o
cnss2-y += wlan_firmware_service_v01.o

ccflags-y += -I$(src)/../inc
