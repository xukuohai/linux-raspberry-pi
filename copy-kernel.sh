#! /bin/bash

#env PATH=$PATH make ARCH=arm64 \
#	CROSS_COMPILE=aarch64-linux-gnu- \
#	INSTALL_MOD_PATH=/mnt/ext4 \
#	modules_install

SRC=arch/arm64/boot/Image
DST=vmlinuz-5.18.0-rc3+
sudo cp ${SRC} /media/xkh/RASPIFIRM/${DST}
sudo cp ${SRC} /media/xkh/RASPIROOT/boot/${DST}
