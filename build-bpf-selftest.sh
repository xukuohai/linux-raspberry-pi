#! /bin/bash

TOPDIR=${HOME}/raspberry-pi4b/linux
#INCDIR=${TOPDIR}/arm64le-libs/include
LIBDIR=${TOPDIR}/pi4libs
INSTALL_PATH=${TOPDIR}/bpf_selftests

make \
	ARCH=arm64 \
	CROSS_COMPILE=aarch64-linux-gnu- \
	LDFLAGS=-L${LIBDIR} \
	-C tools/testing/selftests/bpf
# Image modules dtbs
