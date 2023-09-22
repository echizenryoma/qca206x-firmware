#
# Main Makefile
#
export ATH_TOPDIR=$(shell pwd)/..
export BACKPORT_PWD=$(shell pwd)/backports
# different customer want to use different wpa_supplicant
# in board_type config file, we can override it
export WPA_SUPPLICANT_TOPDIR=${ATH_TOPDIR}/apps/hostap

include ./env.makefile
include scripts/${BOARD_TYPE}/config.${BOARD_TYPE}
include scripts/${BOARD_TYPE}/Makefile.${BOARD_TYPE}
ifneq ($(wildcard scripts/${BOARD_TYPE}/Makefile.${BLUETOOTHSTACK}), )
    include scripts/${BOARD_TYPE}/Makefile.${BLUETOOTHSTACK}
endif

#################################################################################################################################
ifndef KERNELPATH
$(error "Must specify KERNELPATH value")
endif

ifndef KERNELARCH
$(error "Must specify KERNELARCH value")
endif

#################################################################################################################################
export MAKEARCH=make ARCH=$(KERNELARCH) CROSS_COMPILE=$(TOOLPREFIX)

export INSTALL_ROOT=${ATH_TOPDIR}/rootfs-$(BOARD_TYPE).build
export ROOTFS_TOPDIR=${ATH_TOPDIR}/rootfs
export WLAN_DRIVER_TOPDIR=${ATH_TOPDIR}/drivers
export PATCH_TOPDIR=${ATH_TOPDIR}/drivers/patches/${BOARD_TYPE}
export IW30_TOPDIR=${ATH_TOPDIR}/apps/iw-3.0
export LIBNL32_TOPDIR=${ATH_TOPDIR}/apps/libnl-3.2.25
export QCMBR_TOPDIR=${ATH_TOPDIR}/apps/qcmbr
export BLUETOPIA_TOPDIR=${ATH_TOPDIR}/apps/Bluetopia
export BTDIAG_TOPDIR=${ATH_TOPDIR}/apps/Btdiag
export ATH_QCACLD_TOPDIR=${WLAN_DRIVER_TOPDIR}/qcacld-new
export ATH_ATH6KL_TOPDIR=${WLAN_DRIVER_TOPDIR}/ath6kl
export ATHDIAG_TOPDIR=${ATH_QCACLD_TOPDIR}/tools/athdiag
export BTBUILD_TOPDIR=${BTPATH}
export BTPATCH_TOPDIR=${ATH_TOPDIR}/../patch/${BOARD_TYPE}/BT
export ATH6KL-UTILS_TOPDIR=${ATH_TOPDIR}/apps/ath6kl-utils
export EMESH_PACK=${ATH_TOPDIR}/emesh_pack
#################################################################################################################################
# qcacld PATH
#################################################################################################################################
export FW_WLAN_NAME=qcacld-new
#################################################################################################################################
# CFG80211 PATH
#################################################################################################################################
export CFG80211_NAME=backports

################################################################################
#################################################
# Get interface type
################################################################################
#################################################
IF_TYPE_LOWERCASE=$(shell echo $(IF_TYPE) | tr A-Z a-z)

#################################################################################################################################
clean: hostapd_clean wpa_supplicant_clean drivers_clean rootfs_clean

#
# rootfs build
#
rootfs_prep:
	@mkdir -p $(INSTALL_ROOT)
	@mkdir -p $(INSTALL_ROOT)/sbin
	@mkdir -p $(INSTALL_ROOT)/usr/sbin
	@mkdir -p $(INSTALL_ROOT)/lib/modules
	@mkdir -p $(INSTALL_ROOT)/etc

rootfs_build:
	@echo Build rootfs
	@cp -Rf $(ROOTFS_TOPDIR)/* $(INSTALL_ROOT)

rootfs_clean:
	@echo Clean rootfs
	@rm -rf $(INSTALL_ROOT)

#
# drivers build
# include WLAN & BT 
#
drivers: rootfs_prep
	@echo Build drivers
	cd ${WLAN_DRIVER_TOPDIR} && ${MAKEARCH}
	find ${WLAN_DRIVER_TOPDIR} -name 'cfg80211.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'compat.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'wlan*.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'wlan_prealloc.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'bluetooth.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'hci_uart.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'btusb.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'ath3k.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'hidp.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'rfcomm.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'cmtp.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'bnep.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'Tuffelo_wlan.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'wlan_cnss_core_$(IF_TYPE_LOWERCASE)*.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'wlan_resident.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	@echo Backup the unstripped modules
	cp -fr $(INSTALL_ROOT)/lib/modules $(INSTALL_ROOT)/lib/unstripped_modules
	@echo Strip modules
	@cd ${INSTALL_ROOT}/lib/modules && ${TOOLPREFIX}strip --strip-unneeded *.ko


drivers_firmware: rootfs_prep
	@echo Install firmware
	cd ${WLAN_DRIVER_TOPDIR} && ${MAKEARCH} firmware_install

drivers_firmware_transfer:
	@echo Transfer driver firmwares
	cd ${WLAN_DRIVER_TOPDIR} && ${MAKEARCH} firmware_toarray

drivers_clean:
	@echo Clean drivers
	cd ${WLAN_DRIVER_TOPDIR} && ${MAKEARCH} clean

common_patch: wpa_supplicant_patch
	@echo Start Common Patches
	@cd ${WLAN_DRIVER_TOPDIR} && patch -s -p0 < patches/001-cfg80211-backports-3.12.8-1.patch
	@echo End of Common Patches

wpa_supplicant_patch:
	@echo Start wpa_supplicant Patches
	@cd ${WLAN_DRIVER_TOPDIR}/../apps/ && patch -s -p0 < ${WLAN_DRIVER_TOPDIR}/patches/002-wpa_supplicant-for-aio.patch
	@cd ${WPA_SUPPLICANT_TOPDIR} && cp wpa_supplicant/android.config wpa_supplicant/.config
	@cd ${WPA_SUPPLICANT_TOPDIR} && cp hostapd/android.config hostapd/.config
	@echo End of wpa_supplicant Patches

strip_modules:
	@echo Strip modules
	@cd ${INSTALL_ROOT}/lib/modules && ${TOOLPREFIX}strip --strip-unneeded *.ko

#
# wpa_supplicant build
#
wpa_supplicant: rootfs_prep wpa_supplicant_clean
ifneq ($(BUILD_APP_WLAN_WPA_SUPPLICANT_8), n)
	@echo Build wpa_supplicant
	cd $(WPA_SUPPLICANT_TOPDIR)/wpa_supplicant && \
	${MAKEARCH} CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	${MAKEARCH} DESTDIR=$(INSTALL_ROOT) BINDIR=/sbin LIBDIR=/lib install
endif

wpa_supplicant_clean:
ifneq ($(BUILD_APP_WLAN_WPA_SUPPLICANT_8), n)
	@echo Clean wpa_supplicant
	cd $(WPA_SUPPLICANT_TOPDIR)/wpa_supplicant && ${MAKEARCH} clean
endif

#
# hostapd build
#
hostapd: rootfs_prep hostapd_clean
ifneq ($(BUILD_APP_WLAN_HOSTAP_2_4), n)
	@echo Build hostapd
	cd $(WPA_SUPPLICANT_TOPDIR)/hostapd && \
	${MAKEARCH} CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	cp -f hostapd $(INSTALL_ROOT)/sbin && \
	cp -f hostapd_cli $(INSTALL_ROOT)/sbin
endif


hostapd_clean:
ifneq ($(BUILD_APP_WLAN_HOSTAP_2_4), n)
	@echo Clean hostapd
	cd $(WPA_SUPPLICANT_TOPDIR)/hostapd && ${MAKEARCH} clean
endif


#
# iw build
#
iw: rootfs_prep iw_clean
	@echo Build iw-3.0
	cd $(IW30_TOPDIR) && \
	${MAKEARCH} CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	${MAKEARCH} DESTDIR=$(INSTALL_ROOT) SBINDIR=/sbin install

iw_clean:
	@echo Clean iw-3.0
	cd $(IW30_TOPDIR) && ${MAKEARCH} clean

#
# libnl build
#
libnl_config:
ifneq ($(BUILD_APP_WLAN_LIBNL_3_2_25), n)
	@echo Config libnl1-3.2.25
	cd $(LIBNL32_TOPDIR) && \
	./configure --host=$(KERNELARCH) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld
endif

libnl: libnl_config libnl_clean
ifneq ($(BUILD_APP_WLAN_LIBNL_3_2_25), n)
	@echo Build libnl1-3.2.25
	cd $(LIBNL32_TOPDIR) && \
	${MAKEARCH}
endif

libnl_clean:
ifneq ($(BUILD_APP_WLAN_LIBNL_3_2_25), n)
	@echo Clean libnl1-3.2.25
	cd $(LIBNL32_TOPDIR) && ${MAKEARCH} clean
endif


#
# qcmbr build
#
qcmbr: qcmbr_clean
	@echo Build qcmbr
	cd $(QCMBR_TOPDIR) && \
	${MAKEARCH} CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	cp -f Qcmbr $(INSTALL_ROOT)/sbin
	
qcmbr_clean:
	@echo Clean qcmbr
	cd $(QCMBR_TOPDIR) && ${MAKEARCH} clean
	
#
# set athdiag build
#
athdiag: athdiag_tool_clean
	@echo Build athdiag
	cd $(ATHDIAG_TOPDIR) && \
	${MAKEARCH} CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	cp -f athdiag $(INSTALL_ROOT)/sbin
	
athdiag_tool_clean:
	@echo Clean athdiag
	cd $(ATHDIAG_TOPDIR) && ${MAKEARCH} clean
	
#
# Bt patch
#
bt_patch:
	@echo Start bt Patches
	@echo ${ATH_TOPDIR}
	@echo ${BTBUILD_TOPDIR}
	@echo ${BTPATCH_TOPDIR}
	@cd ${BTBUILD_TOPDIR} && rm -rf bt_build && mkdir -p bt_build
	@cd ${BTBUILD_TOPDIR}/bt_build && patch -s -p1 < ${BTBUILD_TOPDIR}/bt_dependency.patch
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/external && mkdir bluetooth && cp -rf ${ATH_TOPDIR}/apps/bluedroid bluetooth
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/external/bluetooth/bluedroid && patch -s -p1 < ${BTPATCH_TOPDIR}/Naples-bluedroid.patch
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/hardware && mkdir qcom && cp -rf ${ATH_TOPDIR}/apps/bt qcom
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/hardware/qcom/bt && patch -s -p1 < ${BTPATCH_TOPDIR}/Naples-bt.patch
	@cd ${BTBUILD_TOPDIR}/bt_build && patch -s -p1 < ${BTPATCH_TOPDIR}/Naples-btusb.patch
	@cd ${BTBUILD_TOPDIR}/bt_build && tar xzf ${BTBUILD_TOPDIR}/glib.tgz
	@cd ${BTBUILD_TOPDIR}/bt_build && patch -s -p1 < ${BTPATCH_TOPDIR}/Naples-sil.patch
	@echo End of bt Patches

#
# Bt build
#
bt_build:
	@echo Start bt build
	@cd ${BTBUILD_TOPDIR}/.. && rm -rf build_out && mkdir -p build_out
	@cd ${BTBUILD_TOPDIR}/bt_build/bt_usb_driver && make clean && make
	@cd ${BTBUILD_TOPDIR}/bt_build/bt_usb_driver && cp bt_usb_qcom.ko ${BTBUILD_TOPDIR}/../build_out
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/hardware/qcom/bt/libbt-vendor && cmake -DCMAKE_C_COMPILER=${CROSS_COMPILE}gcc -DCMAKE_CXX_COMPILER=${CROSS_COMPILE}gcc .
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/hardware/qcom/bt/libbt-vendor && make clean && make
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/hardware/qcom/bt/libbt-vendor && cp libbt-vendor_qca.so.1.0.0 ${BTBUILD_TOPDIR}/../build_out
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/external/bluetooth/bluedroid && cmake -DCMAKE_C_COMPILER=${CROSS_COMPILE}gcc -DCMAKE_CXX_COMPILER=${CROSS_COMPILE}g++ .
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/external/bluetooth/bluedroid && make clean && make
	@cd ${BTBUILD_TOPDIR}/bt_build/bluedroid/external/bluetooth/bluedroid && cp main/libbluetooth_qca.default.so.1.0.0 ${BTBUILD_TOPDIR}/../build_out
	@cd ${BTBUILD_TOPDIR}/bt_build/bluetooth-sil-mock && make clean && make
	@cd ${BTBUILD_TOPDIR}/bt_build/bluetooth-sil-mock && cp bluedroid-qct.so ${BTBUILD_TOPDIR}/../build_out
	@echo Result of bt build
	@cd ${BTBUILD_TOPDIR}/../build_out && pwd && ls -la
	@echo End of bt build

#
# Btdiag build
#
btdiag: btdiag_clean
	@echo Build Btdiag
	cd $(BTDIAG_TOPDIR) && \
	${MAKEARCH} CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	cp -f Btdiag $(INSTALL_ROOT)/sbin
	
btdiag_clean:
	@echo Clean Btdiag
	cd $(BTDIAG_TOPDIR) && ${MAKEARCH} clean


drivers_ath6kl: rootfs_prep
	@echo Build drivers
	cd ${WLAN_DRIVER_TOPDIR} && ${MAKEARCH} -f Makefile.ath6kl
	find ${WLAN_DRIVER_TOPDIR} -name 'ath6kl_usb.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'cfg80211.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'compat.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'wlan.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'bluetooth.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'hci_uart.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'btusb.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'ath3k.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'hidp.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'rfcomm.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'cmtp.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'bnep.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	find ${WLAN_DRIVER_TOPDIR} -name 'Tuffelo_wlan.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules ';'
	@echo Strip modules
	@cd ${INSTALL_ROOT}/lib/modules && ${TOOLPREFIX}strip --strip-unneeded *.ko

#
# ath6kl-utils build
#
ath6kl-utils: ath6kl-utils_clean
	@echo Build ath6kl-utils
	cd $(ATH6KL-UTILS_TOPDIR) && \
	${MAKEARCH} CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	cp -f myftm/myftm $(INSTALL_ROOT)/sbin

ath6kl-utils_clean:
	@echo Clean ath6kl-utils
	cd $(ATH6KL-UTILS_TOPDIR) && ${MAKEARCH} clean

#################################################################################################################################
#
# driver patch
#

drivers_patch:
	@echo Patch drivers
ifneq ("$(wildcard ${PATCH_TOPDIR}/qcacld-3.0/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/qcacld-3.0/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR}/qcacld-3.0 && \
		patch -s -p1 < $$file; \
	done
endif
ifneq ("$(wildcard ${PATCH_TOPDIR}/qca-wifi-host-cmn/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/qca-wifi-host-cmn/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR}/qca-wifi-host-cmn && \
		patch -s -p1 < $$file; \
	done
endif
ifneq ("$(wildcard ${PATCH_TOPDIR}/fw-api/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/fw-api/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR}/fw-api && \
		patch -s -p1 < $$file; \
	done
endif
ifneq ("$(wildcard ${PATCH_TOPDIR}/core_tech_modules/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/core_tech_modules/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR}/core_tech_modules && \
		patch -s -p1 < $$file; \
	done
endif
ifneq ("$(wildcard ${PATCH_TOPDIR}/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR} && \
		patch -s -p0 < $$file; \
	done
endif


drivers_patch_R:
	@echo Revert drivers patch
ifneq ("$(wildcard ${PATCH_TOPDIR}/qcacld-3.0/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/qcacld-3.0/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR}/qcacld-3.0 && \
		patch -s -R -p1 < $$file; \
	done
endif
ifneq ("$(wildcard ${PATCH_TOPDIR}/qca-wifi-host-cmn/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/qca-wifi-host-cmn/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR}/qca-wifi-host-cmn && \
		patch -s -R -p1 < $$file; \
	done
endif
ifneq ("$(wildcard ${PATCH_TOPDIR}/fw-api/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/fw-api/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR}/fw-api && \
		patch -s -R -p1 < $$file; \
	done
endif
ifneq ("$(wildcard ${PATCH_TOPDIR}/core_tech_modules/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/core_tech_modules/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR}/core_tech_modules && \
		patch -s -R -p1 < $$file; \
	done
endif
ifneq ("$(wildcard ${PATCH_TOPDIR}/*.patch)","")
	@for file in `ls ${PATCH_TOPDIR}/*.patch`; \
	do \
		cd ${WLAN_DRIVER_TOPDIR} && \
		patch -s -R -p0 < $$file; \
	done
endif

mesh_daemon:
ifeq ($(BUILD_EMESH_STACK),y)
	@echo "Compile Easymesh: make mesh_daemon [MAKECMDGOALS=<target>]"
ifeq ($(MAKECMDGOALS),mesh_daemon)
	@echo "Compile Easymesh with target: all"
	+$(MAKE) -C ${EZMESHDIR} all
else
	@echo "Compile Easymesh with target: $(MAKECMDGOALS)"
	+$(MAKE) -C ${EZMESHDIR} $(MAKECMDGOALS)
endif
else
	@echo "Easymesh stack not enabled"
endif

mesh_scripts:
ifeq ($(BUILD_EMESH_STACK),y)
	@echo "Copy Easymesh init and helper scripts"
	@find ${EZMESHSRC} -name *.sh | xargs chmod 777
	@chmod 777 ${EZMESHSRC}/_sbin/wifi
	@chmod 777 ${EZMESHSRC}/_etc_init_d/rc.common
	@chmod 777 -R ${EZMESHSRC}/_usr_sbin/*
	@sudo install -d /etc/init.d/ && sudo install ${EZMESHSRC}/_etc_init_d/* /etc/init.d/
	@sudo install -d /etc/config/ && sudo install ${EZMESHSRC}/_etc_config/* /etc/config/
	@sudo mv /etc/init.d/rc.common /etc
	@sudo chmod 777 /usr/share/libubox/jshn.sh
	@sudo cp -rf ${EZMESHSRC}/_lib/* /lib
	@sudo cp -rf ${EZMESHSRC}/_sbin/* /sbin
	@sudo cp -rf ${EZMESHSRC}/_usr_sbin/* /usr/sbin
	@sudo ln -fs /usr/local/bin/uci /sbin/
	@touch ${EZMESHDIR}/easymesh_lib.conf
	@find ${EZMESHDIR} -name *lib > ${EZMESHDIR}/easymesh_lib.conf
	@echo "$(WPA_SUPPLICANT_TOPDIR)/wpa_supplicant/" >> ${EZMESHDIR}/easymesh_lib.conf
	@sudo cp ${EZMESHDIR}/easymesh_lib.conf /etc/ld.so.conf.d && sudo ldconfig -v
	@sudo cp ${EZMESHDIR}/qca-ezmesh/install/sbin/ezmeshAgent /usr/sbin/ezmeshAgent
	@sudo cp ${EZMESHDIR}/qca-wsplcd/wsplcd-map /usr/sbin/wsplcd
	@sudo cp ${EZMESHDIR}/qca-hyctl/install/hyctl /usr/bin/hyctl
else
	@echo "Easymesh stack not enabled"
endif

mesh_daemon_install:
ifeq ($(BUILD_EMESH_STACK),y)
	@sudo cp ${EZMESHDIR}/qca-ezmesh/install/sbin/ezmeshAgent /usr/sbin/ezmeshAgent
	@sudo cp ${EZMESHDIR}/qca-wsplcd/wsplcd-map /usr/sbin/wsplcd
	@sudo cp ${EZMESHDIR}/qca-hyctl/install/hyctl /usr/bin/hyctl
else
	@echo "Easymesh stack not enabled"
endif

mesh_pack:
ifeq ($(BUILD_EMESH_STACK),y)
	@sudo rm -rf $(EMESH_PACK)
	@sudo mkdir $(EMESH_PACK)
	@echo "Copy Easymesh init and helper scripts to $(EMESH_PACK)"
	@find ${EZMESHSRC} -name *.sh | xargs sudo chmod 777
	@chmod 777 ${EZMESHSRC}/_sbin/wifi
	@chmod 777 ${EZMESHSRC}/_etc_init_d/rc.common
	@chmod 777 -R ${EZMESHSRC}/_usr_sbin/*
	@sudo mkdir $(EMESH_PACK)/_etc_init_d
	@sudo cp ${EZMESHSRC}/_etc_init_d/* $(EMESH_PACK)/_etc_init_d
	@sudo mkdir $(EMESH_PACK)/_etc_config
	@sudo cp ${EZMESHSRC}/_etc_config/* $(EMESH_PACK)/_etc_config
	@sudo mkdir $(EMESH_PACK)/_lib
	@sudo cp -rf ${EZMESHSRC}/_lib/* $(EMESH_PACK)/_lib
	@sudo mkdir $(EMESH_PACK)/_sbin
	@sudo cp -rf ${EZMESHSRC}/_sbin/* $(EMESH_PACK)/_sbin
	@sudo mkdir $(EMESH_PACK)/_usr_sbin
	@sudo cp -rf ${EZMESHSRC}/_usr_sbin/* $(EMESH_PACK)/_usr_sbin
	@sudo mkdir $(EMESH_PACK)/easymesh_lib
	@sudo find ${EZMESHDIR} -name *lib  | xargs sudo cp -Rt $(EMESH_PACK)/easymesh_lib
	@sudo mkdir $(EMESH_PACK)/daemon
	@sudo cp ${EZMESHDIR}/qca-ezmesh/install/sbin/ezmesh $(EMESH_PACK)/daemon/ezmesh
	@sudo cp ${EZMESHDIR}/qca-wsplcd/wsplcd-map $(EMESH_PACK)/daemon/wsplcd
	@sudo cp ${EZMESHDIR}/qca-hyctl/install/hyctl $(EMESH_PACK)/daemon/hyctl
	@sudo cp ${EZMESHDIR}/netifd/netifd $(EMESH_PACK)/daemon/
	@sudo cp ${EZMESHDIR}/procd/procd $(EMESH_PACK)/daemon/
	@sudo cp ${EZMESHDIR}/ubus/ubusd $(EMESH_PACK)/daemon/
	@sudo cp ${EZMESHDIR}/ubus/ubus $(EMESH_PACK)/daemon/
	@sudo cp ${EZMESHDIR}/uci/uci $(EMESH_PACK)/daemon/
	@sudo cp ${EZMESHDIR}/libubox/jshn $(EMESH_PACK)/daemon/
	@sudo mkdir $(EMESH_PACK)/sh
	@sudo find ${EZMESHDIR} -name jshn.sh | xargs sudo cp -Rt $(EMESH_PACK)/sh/
	@sudo cp ${EZMESHDIR}/libubox/*.so $(EMESH_PACK)/easymesh_lib/lib/
	@sudo cp ${EZMESHDIR}/procd/*.so $(EMESH_PACK)/easymesh_lib/lib/
	@sudo cp ${EZMESHDIR}/uci/*.so $(EMESH_PACK)/easymesh_lib/lib/
	@sudo cp ${EZMESHDIR}/ubus/*.so $(EMESH_PACK)/easymesh_lib/lib/
	@sudo cp $(WPA_SUPPLICANT_TOPDIR)/wpa_supplicant/libwpa_client.so $(EMESH_PACK)/easymesh_lib/lib/
	@sudo mkdir $(EMESH_PACK)/module
	@sudo find ${EZMESHDIR} -name *.ko | xargs sudo cp -Rt $(EMESH_PACK)/module/
	@sudo cp ${EZMESHSRC}/emesh_install.sh $(EMESH_PACK)/
else
	@echo "Easymesh stack not enabled"
endif
