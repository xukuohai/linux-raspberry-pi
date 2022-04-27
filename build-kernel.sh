#! /bin/bash

#TOPDIR=${HOME}/raspberrypi/linux
#INCDIR=${TOPDIR}/arm64le-libs/include
#LIBDIR=${TOPDIR}/arm64le-libs/lib

make \
	ARCH=arm64 \
	CROSS_COMPILE=aarch64-linux-gnu- \
	$@
# Image modules dtbs
