#!/bin/bash -e

# build config
BOARD_TYPE=${BOARD_TYPE:-"ve-f10"}
BT_CONTROLLER_TYPE=${BT_CONTROLLER_TYPE:-"gno_uart"}
HOST_BUILD_ENABLE=${HOST_BUILD_ENABLE:-"y"}
if [ "${HOST_BUILD_ENABLE}" == "y" ]; then
	USER_BUILD_FLAGS="-DX86_BUILD"
	if [ -z "${KERNELPATH}" ]; then
		KERNELPATH=/lib/modules/$(uname -r)/build
	fi
else
	if [ -z "${SDK_TC_DIR}" ]; then
		SDK_TC_DIR=/local/mnt/workspace/root_dir/opt/fsl-imx-xwayland/4.14-sumo
	fi
	if [ -z "${KERNELPATH}" ]; then
		KERNELPATH=/local/mnt/workspace/sumo_imx_env/bit/imx8mmevk/kernel-build-artifacts
	fi
fi

BUILD_TYPE=${BUILD_TYPE:-"E"}
ENABLE_FLUORIDE_TEST=${ENABLE_FLUORIDE_TEST:-"n"}
if grep -i "usb" <<<${BT_CONTROLLER_TYPE} &>/dev/null; then
TP_TYPE_USB=y
else
TP_TYPE_USB=n
fi
echo TP_TYPE_USB=${TP_TYPE_USB}

declare -A -r bt_projs_repositorys=( \
[fluoride]="-b bt-fluoride.le.2.0 git://source.codeaurora.org/quic/la/platform/system/bt" \
[libbt-vendor]="-b bt-fluoride.le.2.0 git://source.codeaurora.org/quic/la/platform/hardware/qcom/bt" \
[apps]="-b bt-fluoride.le.2.0 git://source.codeaurora.org/quic/le/platform/qcom-opensource/bt" \
[third_party/libhardware]="-b le-blast.lnx.1.2 git://source.codeaurora.org/quic/le/platform/hardware/libhardware" \
[third_party/frameworks]="-b le-frameworks.lnx.2.0 git://source.codeaurora.org/quic/le/platform/vendor/qcom-opensource/le-framework" \
[third_party/bluetooth]="-b bt-fluoride.le.2.0 git://source.codeaurora.org/quic/la/platform/vendor/qcom-opensource/bluetooth" \
)

declare -A -r bt_projs_commits=( \
[fluoride]="59a3460ac1983172ed361b8feb2f3638bf3dd98c" \
[libbt-vendor]="a780a473e49bb6554b74c0e0ba03d92e55ae27f0" \
[apps]="0f9bb4a4734c71d90a0bf139bc1b346c714dafb5" \
[third_party/libhardware]="a8822fca7e4bb38eb77a17c407b8c984a1a955bf" \
[third_party/frameworks]="2fd75c825f45b187b27fac0690ee9079e1b8e476" \
[third_party/bluetooth]="7953a964b6944d02c901d2f20cce185abc1c2287" \
[bt_usb_driver]="bt_usb_driver_codebase" \
[wcnss_filter]="wcnss_filter_codebase" \
[BtDiag_O_release]="BtDiag_O_release_codebase" \
)

MY_BASANAME=$(basename $0)
MY_DIRNAME=$(cd $(dirname $0) && pwd)
MY_REAL_PATH=${MY_DIRNAME}/${MY_BASANAME}
echo "MY_BASANAME=${MY_BASANAME}"
echo "MY_DIRNAME=${MY_DIRNAME}"
echo "MY_REAL_PATH=${MY_REAL_PATH}"

GIT_USER_EMAIL_USER="$(git config --get user.email 2>/dev/null | cut -d @ -sf 1)"
echo "GIT_USER_EMAIL_USER=${GIT_USER_EMAIL_USER}"
FIXCE_DIR=$(cd $(dirname $0)/../../../../ && pwd)
echo "FIXCE_DIR=${FIXCE_DIR}"
FIXCE_BT_PATCH_DIR=${FIXCE_DIR}/patch/${BOARD_TYPE}/bt_patches
echo "FIXCE_BT_PATCH_DIR=${FIXCE_BT_PATCH_DIR}"

usage() {
	echo ""
	echo "Usage: ${MY_BASANAME} d [bt_workspace_dir]"
	echo "    Download source to directory @bt_workspace_dir"
	echo ""

	echo "  or: ${MY_BASANAME} u [bt_workspace_dir]"
	echo "    Update patches from CAF to directory @bt_workspace_dir"
	echo ""

	echo "  or: ${MY_BASANAME} p bt_patch_dir [bt_workspace_dir]"
	echo "    Apply patch from directory @bt_patch_dir to @bt_workspace_dir"
	echo ""

	echo "  or: ${MY_BASANAME} b A|k|f|l|w|s|a|d|c [c]"
	echo "    A: build or clean All components"
	echo "    k: build or clean Kernel module bt_usb_driver"
	echo "    f: build or clean Fluoride"
	echo "    l: build or clean Libbt-vendor"
	echo "    w: build or clean wcnss_filter"
	echo "    s: build or clean Server btproperty"
	echo "    a: build or clean Application btapp"
	echo "    d: build or clean Tool Btdiag"
	echo "    c: build or clean Tool btconfig"
	echo ""

	echo "  or: ${MY_BASANAME} dpb [bt_workspace_dir]"
	echo "    Download Patch Build at directory @bt_workspace_dir"
	echo ""

	echo "  or: ${MY_BASANAME} -h"
	echo "    print this help, then exit"
	echo ""
}

do_update_patches() {
	if [ "${BUILD_TYPE}" == "I" ]; then
		if [ ! -e oss_fixce ]; then
			git clone -b master ssh://${GIT_USER_EMAIL_USER}@review-android.quicinc.com:29418/oss/third_party/fixce oss_fixce
		fi
		pushd oss_fixce
			git pull
		popd
	else
		if [ ! -e wlan_patches ]; then
#			git clone --depth 1 -n -b master git://codeaurora.org/external/sba/wlan_patches.git
			git clone --depth 1 -n -b caf_migration/master https://git.codelinaro.org/clo/sba-patches/wlan_patches.git
			pushd wlan_patches
			git config core.sparsecheckout true
			echo "fixce/3rdparty/patches/bt_fle20_patches" > .git/info/sparse-checkout
			git read-tree -m -u HEAD
			popd
		fi
		pushd wlan_patches
		git pull --depth 1
		popd
	fi
}

do_patch_helper() {
        local dst_dir=$1
        local src_dir=$2

        if [ ! -e ${dst_dir} ]; then
                echo "Error: no such directory ${dst_dir}"
                return 1
        fi
        if [ ! -e ${src_dir} ]; then
                return 0
        fi
        local patch_files=$(ls ${src_dir})
        if [ -z "${patch_files}" ]; then
                return 0
        fi

        local patch_cmd="patch -p1 <"
        if [ -d "${dst_dir}/.git" ]; then
                patch_cmd="git am"
        fi

        pushd ${dst_dir}
        for f in ${patch_files}; do
                echo "${patch_cmd} ${src_dir}/$f"
                ${patch_cmd} "${src_dir}/$f"
        done
        popd
}

do_build_helper() {
	if [ "${HOST_BUILD_ENABLE}" == "y" ]; then
		autoreconf --verbose -Wall --force --install
	else
		autoreconf --verbose -Wall --exclude=autopoint --force --install
	fi
	./configure ${CONFIGURE_FLAGS} --disable-silent-rules --disable-dependency-tracking $@
	make
}

do_clean_helper() {
#	make clean
	git clean -f -d ${1:-.}
}

do_install_helper() {
	local img="$1"
	local img_bn=$(basename ${img})
	local img_dn=$(dirname ${img})

	rm -f ${img}
	rm -f ${BT_OUT_DIR}/debug/${img_bn}
	find . -name "${img_bn}" -exec cp -f '{}' ${BT_OUT_DIR}/debug \;
	if [ -e ${BT_OUT_DIR}/debug/${img_bn} ]; then
		cp -f ${BT_OUT_DIR}/debug/${img_bn} ${img_dn}
		${STRIP:-strip} --strip-unneeded ${img}
	fi
}

if [[ $1 == "d" ]]; then
	BT_WORKSPACE_DIR="${2:-$(pwd)}"
	if [ ! -e "${BT_WORKSPACE_DIR}" ]; then
		mkdir -p "${BT_WORKSPACE_DIR}"
	fi
	echo "BT_WORKSPACE_DIR=${BT_WORKSPACE_DIR}"

	pushd ${BT_WORKSPACE_DIR}
	echo "******** START to DOWNLOAD PROJECTS ********"

	for p in ${!bt_projs_repositorys[@]}; do
		if [ ! -d $p ]; then
			git clone ${bt_projs_repositorys[$p]} $p
			pushd $p
			git checkout -b dev
			popd
		fi
	done

	if [ "${TP_TYPE_USB}" == "y" ]; then
		if [ ! -d bt_usb_driver ]; then
			git clone https://source.codeaurora.org/external/qtil/sba_patches
			pushd sba_patches
			git checkout -b dev "827854233157bdf3ce047542ea7bfe0df98c4662"
			popd
			tar -xavf sba_patches/csr851x-usb-driver-v1_1.tgz
			rm -rf sba_patches
			pushd bt_usb_driver
			git init .
			git add .
			git commit -m "initial commit"
			git tag -a -m "bt_usb_driver codebase" bt_usb_driver_codebase
			popd
		fi
	else
		if [ ! -d wcnss_filter ]; then
			unzip ${FIXCE_BT_PATCH_DIR}/wcnss_filter.zip
		fi
	fi

	if [ ! -d BtDiag_O_release ] && [ -e ${FIXCE_BT_PATCH_DIR}/BtDiag_O_release.zip ]; then
		unzip ${FIXCE_BT_PATCH_DIR}/BtDiag_O_release.zip
		pushd BtDiag_O_release
		git init .
		git add .
		git commit -m "initial commit"
		git tag -a -m "BtDiag_O_release codebase" BtDiag_O_release_codebase
		popd
	fi

	do_update_patches

	echo "******** Download PROJECTS Done********"
	popd
elif [[ $1 == "u" ]]; then
	if [ -d "$2" ]; then
		BT_WORKSPACE_DIR=$(cd $2 && pwd)
	else
		BT_WORKSPACE_DIR=$(pwd)
	fi

	echo "******** START to download CAF PATCHES to ${BT_WORKSPACE_DIR} ********"
	pushd ${BT_WORKSPACE_DIR}
	do_update_patches
	popd
	echo "******** Download CAF PATCHES Done ********"
elif [[ $1 == "p" ]]; then
	if [ $# -lt 2 ]; then
		echo "Error: invalid arguments"
		usage
		exit 1
	fi
	if [ ! -e $2 ]; then
		echo "No such directory: $2"
		exit 0
	fi
	BT_PATCH_DIR=$(cd $2 && pwd)

	if [ -e "$3" ]; then
		BT_WORKSPACE_DIR=$(cd $3 && pwd)
	else
		BT_WORKSPACE_DIR=$(pwd)
	fi
	echo "BT_PATCH_DIR=${BT_PATCH_DIR}"
	echo "BT_WORKSPACE_DIR=${BT_WORKSPACE_DIR}"

	pushd ${BT_WORKSPACE_DIR}
	for p in ${!bt_projs_commits[@]}; do
		if [ -d $p ]; then
			pushd $p
			git reset --hard ${bt_projs_commits[$p]}
			popd
			do_patch_helper ${BT_WORKSPACE_DIR}/$p ${BT_PATCH_DIR}/$p
		fi
	done
	popd
elif [[ $1 == "b" ]]; then
	if [ "${HOST_BUILD_ENABLE}" != "y" ]; then
		if [ ! -d "${SDK_TC_DIR}" ]; then
			echo "invald SDK_TC_DIR: ${SDK_TC_DIR}"
			exit 1
		fi
	fi
	echo BT_CONTROLLER_TYPE=${BT_CONTROLLER_TYPE}

	BT_WORKSPACE_DIR=$(pwd)
	APPS_DIR=${BT_WORKSPACE_DIR}/apps
	BT_USB_DRIVER_DIR=${BT_WORKSPACE_DIR}/bt_usb_driver
	WCNSS_FILTER_DIR=${BT_WORKSPACE_DIR}/wcnss_filter
	LIBBT_VENDOR_DIR=${BT_WORKSPACE_DIR}/libbt-vendor
	FLUORIDE_DIR=${BT_WORKSPACE_DIR}/fluoride
	THIRD_PARTY_DIR=${BT_WORKSPACE_DIR}/third_party
	TOOL_BTDIAG_DIR=${BT_WORKSPACE_DIR}/BtDiag_O_release
	TOOL_BTCONFIG_DIR=${THIRD_PARTY_DIR}/bluetooth/btconfig
	if [ "${HOST_BUILD_ENABLE}" == "y" ]; then
		BT_OUT_DIR=${BT_WORKSPACE_DIR}/$(uname -m)_out_rootfs
	else
		BT_OUT_DIR=${BT_WORKSPACE_DIR}/out_rootfs
	fi
	if [ ! -d ${BT_OUT_DIR} ]; then
		mkdir -p ${BT_OUT_DIR}
		mkdir -p ${BT_OUT_DIR}/usr/lib
		mkdir -p ${BT_OUT_DIR}/usr/bin
		mkdir -p ${BT_OUT_DIR}/etc/bluetooth
		mkdir -p ${BT_OUT_DIR}/data/misc/bluetooth
		echo "i am bluetooth scratch directory" >${BT_OUT_DIR}/data/misc/bluetooth/README.txt
		mkdir -p ${BT_OUT_DIR}/lib/firmware/ar3k
		echo "Place bluetooth F/W files at here" >${BT_OUT_DIR}/lib/firmware/ar3k/README.txt
		mkdir -p ${BT_OUT_DIR}/debug
	fi

	if [[ "$2" == "A" ]]; then
		if [ "${TP_TYPE_USB}" == "y" ]; then
			( ${MY_REAL_PATH} "b" "k" "$3" )
		fi
		( ${MY_REAL_PATH} "b" "f" "$3" )
		( ${MY_REAL_PATH} "b" "l" "$3" )
		if [ "${TP_TYPE_USB}" == "n" ]; then
			( ${MY_REAL_PATH} "b" "w" "$3" )
		fi
		( ${MY_REAL_PATH} "b" "s" "$3" )
		( ${MY_REAL_PATH} "b" "a" "$3" )
		( ${MY_REAL_PATH} "b" "d" "$3" )
		( ${MY_REAL_PATH} "b" "c" "$3" )
		exit
	fi

	if [ "${HOST_BUILD_ENABLE}" == "y" ]; then
		export CPPFLAGS="${CPPFLAGS} ${USER_BUILD_FLAGS} "
	else
		source ${SDK_TC_DIR}/environment-setup-*
	fi
	if [[ $2 == "k" ]]; then
		if [ ! -d "${KERNELPATH}" ]; then
			echo "invald KERNELPATH: ${KERNELPATH}"
			exit 1
		fi
		unset LDFLAGS

		BUILD_TARGET=bt_usb_driver
		pushd ${BT_USB_DRIVER_DIR}
		if [[ $3 == "c" ]]; then
			echo "#### START to clean ${BUILD_TARGET} ####"
			make V=1 KDIR=${KERNELPATH} clean
			echo "#### clean ${BUILD_TARGET} Done ####"
		else
			echo "#### START to build ${BUILD_TARGET} ####"
			make V=1 KDIR=${KERNELPATH}
			do_install_helper ${BT_OUT_DIR}/bt_usb_qcom.ko
			echo "#### build ${BUILD_TARGET} stack Done ####"
		fi
		popd
	elif [[ $2 == "f" ]]; then
		BUILD_TARGET=fluoride
		pushd ${FLUORIDE_DIR}
		if [[ $3 == "c" ]]; then
			pushd ${THIRD_PARTY_DIR}/bluetooth/system_bt_ext
			do_clean_helper
			popd

			echo "#### START to clean ${BUILD_TARGET} ####"
			do_clean_helper
			echo "#### clean ${BUILD_TARGET} Done ####"
		else
			echo "#### START to build ${BUILD_TARGET} ####"
			if [ "${ENABLE_FLUORIDE_TEST}" == "y" ]; then
				do_build_helper --with-bt-workspace-dir=${BT_WORKSPACE_DIR} --with-bt-controller-type=${BT_CONTROLLER_TYPE} --enable-audio-hal=yes --enable-stack-test=yes
			else
				do_build_helper --with-bt-workspace-dir=${BT_WORKSPACE_DIR} --with-bt-controller-type=${BT_CONTROLLER_TYPE} --enable-audio-hal=yes
			fi
			do_install_helper ${BT_OUT_DIR}/usr/lib/libbluetoothdefault_qca.so
			do_install_helper ${BT_OUT_DIR}/usr/lib/libaudioa2dpdefault_qca.so
			cp -f conf/*.conf ${BT_OUT_DIR}/etc/bluetooth/
			if [ "${ENABLE_FLUORIDE_TEST}" == "y" ]; then
				do_install_helper ${BT_OUT_DIR}/usr/bin/gatt_test
				do_install_helper ${BT_OUT_DIR}/usr/bin/l2cap_test
				do_install_helper ${BT_OUT_DIR}/usr/bin/rfcomm_test
				do_install_helper ${BT_OUT_DIR}/usr/bin/bdt
			fi
			echo "#### build ${BUILD_TARGET} Done ####"
		fi
		popd
	elif [[ $2 == "l" ]]; then
		BUILD_TARGET=libbt-vendor
		if [[ $3 == "c" ]]; then
			echo "#### START to clean ${BUILD_TARGET} ####"
			pushd ${LIBBT_VENDOR_DIR}
			do_clean_helper
			popd
			echo "#### clean ${BUILD_TARGET} Done ####"
		else
			echo "#### START to build ${BUILD_TARGET} ####"
			pushd ${LIBBT_VENDOR_DIR}/libbt-vendor
			do_build_helper --with-bt-workspace-dir=${BT_WORKSPACE_DIR} --with-bt-controller-type=${BT_CONTROLLER_TYPE}
			do_install_helper ${BT_OUT_DIR}/usr/lib/libbt-vendor_qca.so
			popd
			echo "#### build ${BUILD_TARGET} Done ####"
		fi
	elif [[ $2 == "w" ]]; then
		BUILD_TARGET=wcnss_filter
		pushd ${WCNSS_FILTER_DIR}
		if [[ $3 == "c" ]]; then
			echo "#### START to clean ${BUILD_TARGET} ####"
			do_clean_helper
			echo "#### clean ${BUILD_TARGET} Done ####"
		else
			echo "#### START to build ${BUILD_TARGET} ####"
			do_build_helper --with-bt-workspace-dir=${BT_WORKSPACE_DIR} --with-bt-controller-type=${BT_CONTROLLER_TYPE}
			do_install_helper ${BT_OUT_DIR}/usr/bin/wcnssfilter
			echo "#### build ${BUILD_TARGET} Done ####"
		fi
		popd
	elif [[ $2 == "s" ]]; then
		BUILD_TARGET=btproperty
		pushd ${APPS_DIR}/property-ops
		if [[ $3 == "c" ]]; then
			echo "#### START to clean ${BUILD_TARGET} ####"
			do_clean_helper
			echo "#### clean ${BUILD_TARGET} Done ####"
		else
			echo "#### START to build ${BUILD_TARGET} ####"
			do_build_helper --with-bt-workspace-dir=${BT_WORKSPACE_DIR} --with-bt-controller-type=${BT_CONTROLLER_TYPE}
			do_install_helper ${BT_OUT_DIR}/usr/bin/btproperty
			echo "#### build ${BUILD_TARGET} Done ####"
		fi
		popd
	elif [[ $2 == "a" ]]; then
		BUILD_TARGET=btapp
		pushd ${APPS_DIR}/bt-app
		if [[ $3 == "c" ]]; then
			pushd ${APPS_DIR}/obex_profiles
			do_clean_helper
			popd

			echo "#### START to clean ${BUILD_TARGET} ####"
			do_clean_helper
			echo "#### clean ${BUILD_TARGET} Done ####"
		else
			pushd ${APPS_DIR}/obex_profiles
			do_build_helper
			popd

			echo "#### START to build ${BUILD_TARGET} ####"
			do_build_helper --with-btobex --with-bt-workspace-dir=${BT_WORKSPACE_DIR} --with-bt-controller-type=${BT_CONTROLLER_TYPE} --enable-audio-hal=no --with-common-libraries=${APPS_DIR}/obex_profiles/.libs
			do_install_helper ${BT_OUT_DIR}/usr/bin/btapp
			cp -f conf/*.conf ${BT_OUT_DIR}/etc/bluetooth/
			echo "#### build ${BUILD_TARGET} Done ####"
		fi
		popd
	elif [[ $2 == "d" ]]; then
		BUILD_TARGET=Btdiag
		if [ -d ${TOOL_BTDIAG_DIR} ]; then
			pushd ${TOOL_BTDIAG_DIR}
			if [[ $3 == "c" ]]; then
				echo "#### START to clean ${BUILD_TARGET} ####"
				make -f Makefile.cc clean
				echo "#### clean ${BUILD_TARGET} Done ####"
			else
				echo "#### START to build ${BUILD_TARGET} ####"
				if [ "${TP_TYPE_USB}" == "y" ]; then
					make -f Makefile.cc CONFIG_BT_STACK=fluoride
				else
					make -f Makefile.cc CONFIG_BT_STACK=fluoride USE_VENDOR_LIB=y
				fi
				do_install_helper ${BT_OUT_DIR}/usr/bin/Btdiag
				echo "#### build ${BUILD_TARGET} Done ####"
			fi
			popd
		fi
	elif [[ $2 == "c" ]]; then
		BUILD_TARGET=btconfig
		pushd ${TOOL_BTCONFIG_DIR}
		if [[ $3 == "c" ]]; then
			echo "#### START to clean ${BUILD_TARGET} ####"
			make clean
			echo "#### clean ${BUILD_TARGET} Done ####"
		else
			echo "#### START to build ${BUILD_TARGET} ####"
			if [ "${TP_TYPE_USB}" == "y" ]; then
				make
			else
				make USE_VENDOR_LIB=y
			fi
			do_install_helper ${BT_OUT_DIR}/usr/bin/btconfig
			echo "#### build ${BUILD_TARGET} Done ####"
		fi
		popd
	else
		echo "ERROR: invalid parameter: \"$2\""
		usage
		exit 1
	fi
elif [[ "$1" == "dpb" ]]; then
	BT_WORKSPACE_DIR="${2:-$(pwd)}"
	if [ ! -e "${BT_WORKSPACE_DIR}" ]; then
		mkdir -p "${BT_WORKSPACE_DIR}"
	fi

	pushd ${BT_WORKSPACE_DIR}
	${MY_REAL_PATH} "d"
	if [ "${BUILD_TYPE}" == "I" ]; then
		${MY_REAL_PATH} "p" "oss_fixce/patch/bt_fle20_patches"
	else
		${MY_REAL_PATH} "p" "wlan_patches/fixce/3rdparty/patches/bt_fle20_patches"
	fi
	if [ "${TP_TYPE_USB}" == "n" ]; then
		do_patch_helper wcnss_filter "${FIXCE_BT_PATCH_DIR}/wcnss_filter"
	fi
	if [ -d "${FIXCE_BT_PATCH_DIR}/BtDiag_O_release" ]; then
		do_patch_helper BtDiag_O_release "${FIXCE_BT_PATCH_DIR}/BtDiag_O_release"
	fi

	${MY_REAL_PATH} "b" "A" "c"
	${MY_REAL_PATH} "b" "A"
	popd
elif [[ "$1" == "-h" ]]; then
	usage
else
	echo "ERROR: invalid parameter: \"$1\""
	usage
	exit 1
fi
