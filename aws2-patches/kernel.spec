%define buildid 133.644

# We have to override the new %%install behavior because, well... the kernel is special.
%global __spec_install_pre %%{___build_pre}

Summary: The Linux kernel

# Amazon: Enable module signing and disable efi
%global signmodules 1
%global usingefi 0

# Save original buildid for later if it's defined
%if 0%{?buildid:1}
%global orig_buildid %{buildid}
%undefine buildid
%endif

###################################################################
# Polite request for people who spin their own kernel rpms:
# please modify the "buildid" define in a way that identifies
# that the kernel isn't the stock distribution kernel, for example,
# by setting the define to ".local" or ".bz123456". This will be
# appended to the full kernel version.
#
# (Uncomment the '#' and both spaces below to set the buildid.)
#
# %% define buildid .local
###################################################################

# The buildid can also be specified on the rpmbuild command line
# by adding --define="buildid .whatever". If both the specfile and
# the environment define a buildid they will be concatenated together.
%if 0%{?orig_buildid:1}
%if 0%{?buildid:1}
%global srpm_buildid %{buildid}
%define buildid %{srpm_buildid}%{orig_buildid}
%else
%define buildid %{orig_buildid}
%endif
%endif

# what kernel is it we are building
%global kversion 5.10.149
%define rpmversion %{kversion}

# What parts do we want to build?  We must build at least one kernel.
# These are the kernels that are built IF the architecture allows it.
# All should default to 1 (enabled) and be flipped to 0 (disabled)
# by later arch-specific checks.

# The following build options are enabled by default.
# Use either --without <opt> in your rpmbuild command or force values
# to 0 in here to disable them.
#
# standard kernel
%define with_up        %{?_without_up:        0} %{?!_without_up:        1}
# kernel-debug
%define with_debug     %{?_without_debug:     0} %{?!_without_debug:     0}
# kernel-doc
%define with_doc       %{?_without_doc:       0} %{?!_without_doc:       0}
# kernel-headers
%define with_headers   %{?_without_headers:   0} %{?!_without_headers:   1}
# perf
%define with_perf      %{?_without_perf:      0} %{?!_without_perf:      1}
# tools
%define with_tools     %{?_without_tools:     0} %{?!_without_tools:     1}
# bpf tool
%define with_bpftool   %{?_without_bpftool:   0} %{?!_without_bpftool:   1}
# kernel-debuginfo
%define with_debuginfo %{?_without_debuginfo: 0} %{?!_without_debuginfo: 1}
# Want to build a the vsdo directories installed
%define with_vdso_install %{?_without_vdso_install: 0} %{?!_without_vdso_install: 1}
# Control whether we build the hmac for fips mode
%define with_fips      %{?_without_fips:       0} %{?!_without_fips:   1}

# Build the kernel-doc package, but don't fail the build if it botches.
# Here "true" means "continue" and "false" means "fail the build".
%define doc_build_fail true

# should we do C=1 builds with sparse
%define with_sparse	%{?_with_sparse:      1} %{?!_with_sparse:      0}

# Set debugbuildsenabled to 1 for production (build separate debug kernels)
#  and 0 for rawhide (all kernels are debug kernels).
# See also 'make debug' and 'make release'.
%define debugbuildsenabled 0

# do we want the oldconfig run over the config files (when regenerating
# configs this should be avoided in order to save duplicate work...)
%define with_oldconfig     %{?_without_oldconfig:      0} %{?!_without_oldconfig:      1}

# pkg_release is what we'll fill in for the rpm Release: field
%define pkg_release %{?buildid}%{?dist}

%define make_target bzImage

%define KVERREL %{rpmversion}-%{pkg_release}.%{_target_cpu}
%define hdrarch %_target_cpu
%define asmarch %_target_cpu

%if !%{debugbuildsenabled}
%define with_debug 0
%endif

%if !%{with_debuginfo}
%define _enable_debug_packages 0
%endif
%define debuginfodir /usr/lib/debug

%define all_x86 i386 i686

%if %{with_vdso_install}
# These arches install vdso/ directories.
%define vdso_arches x86_64 aarch64
%endif

# Overrides for generic default options

# don't do debug builds on anything but x86_64 and aarch64
%ifnarch x86_64 aarch64
%define with_debug 0
%endif

# only package docs noarch
%ifnarch noarch
%define with_doc 0
%endif

# don't build noarch kernels or headers (duh)
%ifarch noarch
%define with_up 0
%define with_headers 0
%define with_tools 0
%define with_perf 0
%define signmodules 0
%define all_arch_configs kernel-%{version}-*.config
%endif

# Per-arch tweaks

%ifarch %{all_x86}
%define asmarch x86
%define hdrarch i386
%define all_arch_configs kernel-%{version}-i?86*.config
%define image_install_path boot
%define kernel_image arch/%{asmarch}/boot/bzImage
%endif

%ifarch x86_64
%define asmarch x86
%define all_arch_configs kernel-%{version}-x86_64*.config
%define image_install_path boot
%define kernel_image arch/%{asmarch}/boot/bzImage
%endif

%ifarch aarch64
%define all_arch_configs kernel-%{version}-aarch64*.config
%define asmarch arm64
%define hdrarch arm64
%define image_install_path boot
%define make_target Image.gz
%define kernel_image arch/%{asmarch}/boot/Image.gz
%define with_perf 1
%endif

# amazon: don't use nonint config target - we want to know when our config files are
# not complete
%define oldconfig_target olddefconfig
# To temporarily exclude an architecture from being built, add it to
# %%nobuildarches. Do _NOT_ use the ExclusiveArch: line, because if we
# don't build kernel-headers then the new build system will no longer let
# us use the previous build of that package -- it'll just be completely AWOL.
# Which is a BadThing(tm).

%global GCC_VER gcc10-

# We don't build a kernel on i386; we only do kernel-headers there
%define nobuildarches i386 i486 i586 i686 noarch

%ifarch %nobuildarches
%define with_up 0
%define with_debug 0
%define with_debuginfo 0
%define with_perf 0
%define with_bpftool 0
%define with_tools 0
%define _enable_debug_packages 0
%define signmodules 0
%endif

# Architectures we build tools/cpupower on
%define cpupowerarchs %{ix86} x86_64 aarch64
#define cpupowerarchs none

#
# Three sets of minimum package version requirements in the form of Conflicts:
# to versions below the minimum
#

#
# Packages that need to be installed before the kernel is, because the %%post
# scripts use them.
#
%if 0%{?amzn} >= 2022
%define kernel_prereq  coreutils, systemd >= 203-2, /usr/bin/kernel-install
%define initrd_prereq  dracut >= 027
%define microcode_ctl_version 2:2.1-43
%define __python %{__python3}
%define py_pkg_prefix python3
%else
%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, grubby >= 7.0.15-2.5
%define initrd_prereq  dracut >= 004-336.27
%define microcode_ctl_version 2:2.1-47.amzn2.0.4
%define __python %{__python2}
%define py_pkg_prefix python
%endif

#
# This macro does requires, provides, conflicts, obsoletes for a kernel package.
#	%%kernel_reqprovconf <subpackage>
# It uses any kernel_<subpackage>_conflicts and kernel_<subpackage>_obsoletes
# macros defined above.
#
%define kernel_reqprovconf \
Provides: kernel = %{rpmversion}-%{pkg_release}\
Provides: kernel-%{_target_cpu} = %{rpmversion}-%{pkg_release}%{?1:.%{1}}\
Provides: kernel-drm-nouveau = 16\
Provides: kernel-modeset = 1\
Provides: kernel-uname-r = %{KVERREL}%{?variant}%{?1:.%{1}}\
Requires(pre): %{kernel_prereq}\
Requires(pre): %{initrd_prereq}\
%if 0%{?amzn} < 2022\
Requires(post): %{_sbindir}/new-kernel-pkg\
Requires(preun): %{_sbindir}/new-kernel-pkg\
%endif\
%{expand:%%{?kernel%{?1:_%{1}}_conflicts:Conflicts: %%{kernel%{?1:_%{1}}_conflicts}}}\
%{expand:%%{?kernel%{?1:_%{1}}_obsoletes:Obsoletes: %%{kernel%{?1:_%{1}}_obsoletes}}}\
%{expand:%%{?kernel%{?1:_%{1}}_provides:Provides: %%{kernel%{?1:_%{1}}_provides}}}\
# We can't let RPM do the dependencies automatic because it'll then pick up\
# a correct but undesirable perl dependency from the module headers which\
# isn't required for the kernel proper to function\
AutoReq: no\
AutoProv: yes\
%{nil}

Name: kernel%{?variant}
Group: System Environment/Kernel
License: GPLv2 and Redistributable, no modification permitted
URL: http://www.kernel.org/
Version: %{rpmversion}
Release: %{pkg_release}
# DO NOT CHANGE THE 'ExclusiveArch' LINE TO TEMPORARILY EXCLUDE AN ARCHITECTURE BUILD.
# SET %%nobuildarches (ABOVE) INSTEAD
ExclusiveArch: noarch %{all_x86} x86_64 aarch64
ExclusiveOS: Linux

%kernel_reqprovconf
%ifarch x86_64
Requires(pre): microcode_ctl >= %{microcode_ctl_version}
%endif

%ifarch x86_64
Obsoletes: kernel-smp
%endif

Provides: kmod-lustre-client = 2.12.8

#
# List the packages used during the kernel build
#
BuildRequires: kmod, patch, bash, tar
BuildRequires: bzip2, xz, findutils, gzip, m4, perl, make, diffutils, gawk
BuildRequires: hostname, openssl rsync, python3, python3-devel, dwarves >= 1.16
BuildRequires: glibc-static
%if 0%{?amzn} >= 2022
BuildRequires: gcc
%else
BuildRequires: gcc10, gcc10-binutils >= 2.35
%endif
# Required for kernel documentation build
%if %{with_doc}
BuildRequires: %{py_pkg_prefix}-virtualenv, %{py_pkg_prefix}-sphinx
%endif
#defines based on the compiler version we need to use
%if 0%{?amzn} >= 2022
%global _gcc gcc
%global _gxx g++
%else
%global _gcc %{GCC_VER}gcc
%global _gxx %{GCC_VER}g++
%endif

%global _gccver %(eval %{_gcc} -dumpfullversion 2>/dev/null || :)
%if "%{_gccver}" > "7"
Provides: buildrequires(gcc) = %{_gccver}
%endif
BuildRequires: binutils >= 2.12
BuildRequires: system-rpm-config, gdb, bc
BuildRequires: net-tools
BuildRequires: xmlto, asciidoc
BuildRequires: openssl-devel
%if %{with_sparse}
BuildRequires: sparse >= 0.4.1
%endif
%if %{with_perf}
BuildRequires: elfutils-devel zlib-devel binutils-devel newt-devel %{py_pkg_prefix}-devel bison
BuildRequires: audit-libs-devel
BuildRequires: java-devel
BuildRequires: libzstd-devel
BuildRequires: numactl-devel
%endif
%if %{with_tools}
BuildRequires: pciutils-devel gettext
BuildRequires: libcap-devel
%endif
%if %{with_bpftool}
BuildRequires: %{py_pkg_prefix}-docutils
BuildRequires: zlib-devel binutils-devel
%endif
BuildConflicts: rhbuildsys(DiskFree) < 3000Mb
%if %{with_debuginfo}
BuildRequires: rpm-build >= 4.11.3-40.amzn2.0.4, elfutils
# Most of these should be enabled after more investigation
%undefine _include_minidebuginfo
%undefine _find_debuginfo_dwz_opts
%if 0%{?amzn} >= 2022
%undefine _unique_build_ids
%undefine _unique_debug_names
%undefine _unique_debug_srcs
%undefine _debugsource_packages
%endif
%undefine _debuginfo_subpackages
%global _find_debuginfo_opts -r
%global _missing_build_ids_terminate_build 1
%global _no_recompute_build_ids 1
%endif

%if %{signmodules}
BuildRequires: pesign >= 0.10-4
%endif

%if %{with_fips}
BuildRequires: hmaccalc
%endif

Source0: linux-5.10.149.tar
Source1: linux-5.10.149-patches.tar

# this is for %%{signmodules}
Source11: x509.genkey

Source15: kconfig.py
Source16: mod-extra.list
Source17: mod-extra.sh
Source18: mod-extra-sign.sh
%define modsign_cmd %{SOURCE18}

Source19: Makefile.config
Source20: config-x86_64
Source21: config-x86_64-debug
Source30: config-aarch64
Source31: config-aarch64-debug
Source50: split-man.pl
Source60: Makefile.module 
%define split_man_cmd %{SOURCE50}

# Sources for kernel-tools
Source2000: cpupower.init
Source2001: cpupower.config

# __PATCHFILE_TEMPLATE__
Patch0001: 0001-scsi-sd_revalidate_disk-prevent-NULL-ptr-deref.patch
Patch0002: 0002-not-for-upstream-testmgr-config-changes-to-enable-FI.patch
Patch0003: 0003-drivers-introduce-AMAZON_DRIVER_UPDATES.patch
Patch0004: 0004-drivers-amazon-add-network-device-drivers-support.patch
Patch0005: 0005-drivers-amazon-introduce-AMAZON_ENA_ETHERNET.patch
Patch0006: 0006-Importing-Amazon-ENA-driver-1.5.0-into-amazon-4.14.y.patch
Patch0007: 0007-xen-manage-keep-track-of-the-on-going-suspend-mode.patch
Patch0008: 0008-xen-manage-introduce-helper-function-to-know-the-on-.patch
Patch0009: 0009-xenbus-add-freeze-thaw-restore-callbacks-support.patch
Patch0010: 0010-x86-xen-Introduce-new-function-to-map-HYPERVISOR_sha.patch
Patch0011: 0011-x86-xen-add-system-core-suspend-and-resume-callbacks.patch
Patch0012: 0012-xen-blkfront-add-callbacks-for-PM-suspend-and-hibern.patch
Patch0013: 0013-xen-netfront-add-callbacks-for-PM-suspend-and-hibern.patch
Patch0014: 0014-xen-time-introduce-xen_-save-restore-_steal_clock.patch
Patch0015: 0015-x86-xen-save-and-restore-steal-clock.patch
Patch0016: 0016-xen-events-add-xen_shutdown_pirqs-helper-function.patch
Patch0017: 0017-x86-xen-close-event-channels-for-PIRQs-in-system-cor.patch
Patch0018: 0018-PM-hibernate-update-the-resume-offset-on-SNAPSHOT_SE.patch
Patch0019: 0019-Revert-xen-dont-fiddle-with-event-channel-masking-in.patch
Patch0020: 0020-xen-blkfront-Fixed-blkfront_restore-to-remove-a-call.patch
Patch0021: 0021-x86-tsc-avoid-system-instability-in-hibernation.patch
Patch0022: 0022-block-xen-blkfront-consider-new-dom0-features-on-res.patch
Patch0023: 0023-xen-restore-pirqs-on-resume-from-hibernation.patch
Patch0024: 0024-xen-Only-restore-the-ACPI-SCI-interrupt-in-xen_resto.patch
Patch0025: 0025-net-ena-Import-the-ENA-v2-driver-2.0.2g.patch
Patch0026: 0026-xen-netfront-call-netif_device_attach-on-resume.patch
Patch0027: 0027-net-ena-replace-dma_zalloc_coherent-with-dma_alloc_c.patch
Patch0028: 0028-iov_iter-fix-iov_for_each-after-accessor-function-in.patch
Patch0029: 0029-Import-lustre-client-2.10.5.patch
Patch0030: 0030-Config-glue-for-lustre-client.patch
Patch0031: 0031-lustre-change-printf-format-strings-for-64bit-time-i.patch
Patch0032: 0032-lustre-silence-printk-format-warnings-about-timespec.patch
Patch0033: 0033-lustre-use-SB_-instead-of-MS_-as-superblock-flags.patch
Patch0034: 0034-lustre-adapt-to-setup_timer-timer_setup-change.patch
Patch0035: 0035-lustre-adapt-to-struct-posix_acl-atomic_t-refcount_t.patch
Patch0036: 0036-lustre-adapt-to-sys_close-ksys_close-change.patch
Patch0037: 0037-lustre-adapt-to-upstream-struct-address_space-change.patch
Patch0038: 0038-lustre-adapt-to-upstream-atomic_open-interface-chang.patch
Patch0039: 0039-lustre-adapt-to-changed-kernel-socket-interfaces.patch
Patch0040: 0040-lustre-reintroduce-ATTR_ATTR_FLAG.patch
Patch0041: 0041-lustre-adapt-for-totalram_pages-change.patch
Patch0042: 0042-lustre-config.h-file-for-Linux-5.0.patch
Patch0043: 0043-lustre-account-for-the-SO_-TIMEO-SO_-TIME_OLD-rename.patch
Patch0044: 0044-lustre-adapt-for-fault-page_mkwrite-return-type-chan.patch
Patch0045: 0045-lustre-add-HAVE_VM_FAULT_T-to-config.h.patch
Patch0046: 0046-lustre-adapt-to-get_ds-removal.patch
Patch0047: 0047-lustre-fix-ACL-handling.patch
Patch0048: 0048-lustre-adapt-to-stacktrace-infrastructure-change.patch
Patch0049: 0049-lustre-fix-fall-through-warnings.patch
Patch0050: 0050-lustre-fix-file_lock-usage.patch
Patch0051: 0051-lustre-fix-lnet-makefile.patch
Patch0052: 0052-lustre-adapt-to-changed-padata-interfaces.patch
Patch0053: 0053-iommu-use-config-option-to-specify-if-iommu-mode-sho.patch
Patch0054: 0054-xen-Restore-xen-pirqs-on-resume-from-hibernation.patch
Patch0055: 0055-block-xen-blkfront-bump-the-maximum-number-of-indire.patch
Patch0056: 0056-lustre-hold-lock-while-walking-changelog-dev-list.patch
Patch0057: 0057-ena-update-to-2.2.3.patch
Patch0058: 0058-lustre-adapt-to-changed-padata-interfaces-in-5.4-sta.patch
Patch0059: 0059-lustre-llite-ll_fault-fixes.patch
Patch0060: 0060-ena-update-to-2.2.6.patch
Patch0061: 0061-ena-Update-to-2.2.10.patch
Patch0062: 0062-drivers-amazon-config-don-t-use-help-anymore.patch
Patch0063: 0063-lustre-restore-mgc-binding-for-sptlrpc.patch
Patch0064: 0064-Update-lustre-to-tag-v2.10.8-5-in-AmazonFSxLustreCli.patch
Patch0065: 0065-lustre-remove-CRYPTO_TFM_RES_BAD_KEY_LEN.patch
Patch0066: 0066-lustre-add-time_t-define.patch
Patch0067: 0067-lustre-stop-using-struct-timeval.patch
Patch0068: 0068-lustre-handle-removal-of-NR_UNSTABLE_NFS.patch
Patch0069: 0069-lustre-Fix-compilation-with-MOFED-5.1.patch
Patch0070: 0070-lustre-seperate-debugfs-and-procfs-handling.patch
Patch0071: 0071-lustre-fix-fiemap.h-include.patch
Patch0072: 0072-lustre-fixup-for-kernel_-get-set-sockopt-removal.patch
Patch0073: 0073-lustre-mmap_sem-mmap_lock.patch
Patch0074: 0074-lustre-remove-the-pgprot-argument-to-__vmalloc.patch
Patch0075: 0075-lustre-use-uaccess_kernel-instead-of-segment_eq.patch
Patch0076: 0076-Disable-HAVE_LINUX_SELINUX_IS_ENABLED-as-it-s-gone-f.patch
Patch0077: 0077-lustre-disable-compiling-sec_ctx.c.patch
Patch0078: 0078-lustre-remove-get-set_fs-from-ptask-code.patch
Patch0079: 0079-lustre-get-network-interface-configs-directly.patch
Patch0080: 0080-lustre-lprocfs-work-around-set_fs-removal.patch
Patch0081: 0081-ena-Update-to-2.4.0.patch
Patch0082: 0082-lustre-don-t-try-fault-fast-path-if-we-can-t-retry.patch
Patch0083: 0083-NFS-Ensure-contents-of-struct-nfs_open_dir_context-a.patch
Patch0084: 0084-NFS-Clean-up-readdir-struct-nfs_cache_array.patch
Patch0085: 0085-NFS-Clean-up-nfs_readdir_page_filler.patch
Patch0086: 0086-NFS-Clean-up-directory-array-handling.patch
Patch0087: 0087-NFS-Don-t-discard-readdir-results.patch
Patch0088: 0088-NFS-Remove-unnecessary-kmap-in-nfs_readdir_xdr_to_ar.patch
Patch0089: 0089-NFS-Replace-kmap-with-kmap_atomic-in-nfs_readdir_sea.patch
Patch0090: 0090-NFS-Simplify-struct-nfs_cache_array_entry.patch
Patch0091: 0091-NFS-Support-larger-readdir-buffers.patch
Patch0092: 0092-NFS-More-readdir-cleanups.patch
Patch0093: 0093-NFS-nfs_do_filldir-does-not-return-a-value.patch
Patch0094: 0094-NFS-Reduce-readdir-stack-usage.patch
Patch0095: 0095-NFS-Cleanup-to-remove-nfs_readdir_descriptor_t-typed.patch
Patch0096: 0096-NFS-Allow-the-NFS-generic-code-to-pass-in-a-verifier.patch
Patch0097: 0097-NFS-Handle-NFS4ERR_NOT_SAME-and-NFSERR_BADCOOKIE-fro.patch
Patch0098: 0098-NFS-Improve-handling-of-directory-verifiers.patch
Patch0099: 0099-NFS-Optimisations-for-monotonically-increasing-readd.patch
Patch0100: 0100-NFS-Reduce-number-of-RPC-calls-when-doing-uncached-r.patch
Patch0101: 0101-NFS-Do-uncached-readdir-when-we-re-seeking-a-cookie-.patch
Patch0102: 0102-ena-update-to-2.4.1.patch
Patch0103: 0103-Add-Amazon-EFA-driver-version-1.11.1.patch
Patch0104: 0104-mm-Introduce-Data-Access-MONitor-DAMON.patch
Patch0105: 0105-mm-damon-core-Implement-region-based-sampling.patch
Patch0106: 0106-mm-damon-Adaptively-adjust-regions.patch
Patch0107: 0107-mm-idle_page_tracking-Make-PG_idle-reusable.patch
Patch0108: 0108-mm-damon-Implement-primitives-for-the-virtual-memory.patch
Patch0109: 0109-mm-damon-Add-a-tracepoint.patch
Patch0110: 0110-mm-damon-Implement-a-debugfs-based-user-space-interf.patch
Patch0111: 0111-mm-damon-dbgfs-Implement-recording-feature.patch
Patch0112: 0112-mm-damon-dbgfs-Export-kdamond-pid-to-the-user-space.patch
Patch0113: 0113-mm-damon-dbgfs-Support-multiple-contexts.patch
Patch0114: 0114-mm-damon-core-Account-age-of-target-regions.patch
Patch0115: 0115-mm-damon-core-Implement-DAMON-based-Operation-Scheme.patch
Patch0116: 0116-mm-damon-vaddr-Support-DAMON-based-Operation-Schemes.patch
Patch0117: 0117-mm-damon-dbgfs-Support-DAMON-based-Operation-Schemes.patch
Patch0118: 0118-mm-damon-schemes-Implement-statistics-feature.patch
Patch0119: 0119-damon-dbgfs-Allow-users-to-set-initial-monitoring-ta.patch
Patch0120: 0120-mm-damon-vaddr-Separate-commonly-usable-functions.patch
Patch0121: 0121-mm-damon-Implement-primitives-for-physical-address-s.patch
Patch0122: 0122-damon-dbgfs-Support-physical-memory-monitoring.patch
Patch0123: 0123-Revert-vmlinux.lds.h-Add-PGO-and-AutoFDO-input-secti.patch
Patch0124: 0124-arm64-Export-acpi_psci_use_hvc-symbol.patch
Patch0125: 0125-hwrng-Add-Gravition-RNG-driver.patch
Patch0126: 0126-lustre-update-to-AmazonFSxLustreClient-v2.10.8-7.patch
Patch0127: 0127-x86-Disable-KASLR-when-Xen-is-detected.patch
Patch0128: 0128-ena-Update-to-2.5.0.patch
Patch0129: 0129-Revert-crypto-jitterentropy-change-back-to-module_in.patch
Patch0130: 0130-igb_uio-add.patch
Patch0131: 0131-nfs-Subsequent-READDIR-calls-should-carry-non-zero-c.patch
Patch0132: 0132-NFS-Fix-handling-of-cookie-verifier-in-uncached_read.patch
Patch0133: 0133-NFS-Only-change-the-cookie-verifier-if-the-directory.patch
Patch0134: 0134-Sysfs-memory-probe-interface.patch
Patch0135: 0135-arm64-mm-Enable-sysfs-based-memory-hot-remove-probe.patch
Patch0136: 0136-lustre-update-to-AmazonFSxLustreClient-v2.10.8-8.patch
Patch0137: 0137-efi-libstub-arm64-Warn-when-efi_random_alloc-fails.patch
Patch0138: 0138-mm-page_alloc-Print-node-fallback-order.patch
Patch0139: 0139-mm-page_alloc-Use-accumulated-load-when-building-nod.patch
Patch0140: 0140-arm-arm64-Probe-for-the-presence-of-KVM-hypervisor.patch
Patch0141: 0141-KVM-arm64-Advertise-KVM-UID-to-guests-via-SMCCC.patch
Patch0142: 0142-ptp-Reorganize-ptp_kvm.c-to-make-it-arch-independent.patch
Patch0143: 0143-time-Add-mechanism-to-recognize-clocksource-in-time_.patch
Patch0144: 0144-clocksource-Add-clocksource-id-for-arm-arch-counter.patch
Patch0145: 0145-KVM-arm64-Add-support-for-the-KVM-PTP-service.patch
Patch0146: 0146-ptp-arm-arm64-Enable-ptp_kvm-for-arm-arm64.patch
Patch0147: 0147-ptp-Don-t-print-an-error-if-ptp_kvm-is-not-supported.patch
Patch0148: 0148-tools-headers-UAPI-Sync-linux-kvm.h-with-the-kernel-.patch
Patch0149: 0149-drivers-misc-sysgenid-add-system-generation-id-drive.patch
Patch0150: 0150-drivers-virt-vmgenid-add-vm-generation-id-driver.patch
Patch0151: 0151-mm-memcg-throttle-the-memory-reclaim-given-dirty-wri.patch
Patch0152: 0152-perf-sched-Cast-PTHREAD_STACK_MIN-to-int-as-it-may-t.patch
Patch0153: 0153-sysctl-add-proc_dou8vec_minmax.patch
Patch0154: 0154-ipv4-shrink-netns_ipv4-with-sysctl-conversions.patch
Patch0155: 0155-ipv4-convert-ip_forward_update_priority-sysctl-to-u8.patch
Patch0156: 0156-inet-convert-tcp_early_demux-and-udp_early_demux-to-.patch
Patch0157: 0157-tcp-convert-elligible-sysctls-to-u8.patch
Patch0158: 0158-tcp-fix-tcp_min_tso_segs-sysctl.patch
Patch0159: 0159-bpf-Expose-bpf_get_socket_cookie-to-tracing-programs.patch
Patch0160: 0160-bpf-Add-ASSERT_NEQ-ASSERT_FALSE-and-ASSERT_GE-for-se.patch
Patch0161: 0161-net-Introduce-net.ipv4.tcp_migrate_req.patch
Patch0162: 0162-tcp-Add-num_closed_socks-to-struct-sock_reuseport.patch
Patch0163: 0163-tcp-Keep-TCP_CLOSE-sockets-in-the-reuseport-group.patch
Patch0164: 0164-tcp-Add-reuseport_migrate_sock-to-select-a-new-liste.patch
Patch0165: 0165-tcp-Migrate-TCP_ESTABLISHED-TCP_SYN_RECV-sockets-in-.patch
Patch0166: 0166-tcp-Migrate-TCP_NEW_SYN_RECV-requests-at-retransmitt.patch
Patch0167: 0167-tcp-Migrate-TCP_NEW_SYN_RECV-requests-at-receiving-t.patch
Patch0168: 0168-bpf-Support-BPF_FUNC_get_socket_cookie-for-BPF_PROG_.patch
Patch0169: 0169-bpf-Support-socket-migration-by-eBPF.patch
Patch0170: 0170-libbpf-Set-expected_attach_type-for-BPF_PROG_TYPE_SK.patch
Patch0171: 0171-bpf-Test-BPF_SK_REUSEPORT_SELECT_OR_MIGRATE.patch
Patch0172: 0172-tcp-Add-stats-for-socket-migration.patch
Patch0173: 0173-math64.h-Add-mul_s64_u64_shr.patch
Patch0174: 0174-KVM-X86-Store-L1-s-TSC-scaling-ratio-in-struct-kvm_v.patch
Patch0175: 0175-KVM-X86-Rename-kvm_compute_tsc_offset-to-kvm_compute.patch
Patch0176: 0176-KVM-X86-Add-a-ratio-parameter-to-kvm_scale_tsc.patch
Patch0177: 0177-KVM-nVMX-Add-a-TSC-multiplier-field-in-VMCS12.patch
Patch0178: 0178-KVM-X86-Add-functions-for-retrieving-L2-TSC-fields-f.patch
Patch0179: 0179-KVM-X86-Add-functions-that-calculate-the-nested-TSC-.patch
Patch0180: 0180-KVM-X86-Move-write_l1_tsc_offset-logic-to-common-cod.patch
Patch0181: 0181-KVM-X86-Add-vendor-callbacks-for-writing-the-TSC-mul.patch
Patch0182: 0182-KVM-nVMX-Enable-nested-TSC-scaling.patch
Patch0183: 0183-KVM-selftests-x86-Add-vmx_nested_tsc_scaling_test.patch
Patch0184: 0184-KVM-nVMX-Dynamically-compute-max-VMCS-index-for-vmcs.patch
Patch0185: 0185-Introduce-page-touching-DMA-ops-binding.patch
Patch0186: 0186-nitro_enclaves-Set-Bus-Master-for-the-NE-PCI-device.patch
Patch0187: 0187-nitro_enclaves-Enable-Arm64-support.patch
Patch0188: 0188-nitro_enclaves-Update-documentation-for-Arm64-suppor.patch
Patch0189: 0189-nitro_enclaves-Add-fix-for-the-kernel-doc-report.patch
Patch0190: 0190-nitro_enclaves-Update-copyright-statement-to-include.patch
Patch0191: 0191-nitro_enclaves-Add-fixes-for-checkpatch-match-open-p.patch
Patch0192: 0192-nitro_enclaves-Add-fixes-for-checkpatch-spell-check-.patch
Patch0193: 0193-nitro_enclaves-Add-fixes-for-checkpatch-blank-line-r.patch
Patch0194: 0194-Revert-damon-dbgfs-Support-physical-memory-monitorin.patch
Patch0195: 0195-Revert-mm-damon-Implement-primitives-for-physical-ad.patch
Patch0196: 0196-Revert-mm-damon-vaddr-Separate-commonly-usable-funct.patch
Patch0197: 0197-Revert-damon-dbgfs-Allow-users-to-set-initial-monito.patch
Patch0198: 0198-Revert-mm-damon-schemes-Implement-statistics-feature.patch
Patch0199: 0199-Revert-mm-damon-dbgfs-Support-DAMON-based-Operation-.patch
Patch0200: 0200-Revert-mm-damon-vaddr-Support-DAMON-based-Operation-.patch
Patch0201: 0201-Revert-mm-damon-core-Implement-DAMON-based-Operation.patch
Patch0202: 0202-Revert-mm-damon-core-Account-age-of-target-regions.patch
Patch0203: 0203-Revert-mm-damon-dbgfs-Support-multiple-contexts.patch
Patch0204: 0204-Revert-mm-damon-dbgfs-Export-kdamond-pid-to-the-user.patch
Patch0205: 0205-Revert-mm-damon-dbgfs-Implement-recording-feature.patch
Patch0206: 0206-Revert-mm-damon-Implement-a-debugfs-based-user-space.patch
Patch0207: 0207-Revert-mm-damon-Add-a-tracepoint.patch
Patch0208: 0208-Revert-mm-damon-Implement-primitives-for-the-virtual.patch
Patch0209: 0209-Revert-mm-idle_page_tracking-Make-PG_idle-reusable.patch
Patch0210: 0210-Revert-mm-damon-Adaptively-adjust-regions.patch
Patch0211: 0211-Revert-mm-damon-core-Implement-region-based-sampling.patch
Patch0212: 0212-Revert-mm-Introduce-Data-Access-MONitor-DAMON.patch
Patch0213: 0213-mm-introduce-Data-Access-MONitor-DAMON.patch
Patch0214: 0214-mm-damon-core-implement-region-based-sampling.patch
Patch0215: 0215-mm-damon-adaptively-adjust-regions.patch
Patch0216: 0216-mm-idle_page_tracking-make-PG_idle-reusable.patch
Patch0217: 0217-mm-damon-implement-primitives-for-the-virtual-memory.patch
Patch0218: 0218-mm-damon-add-a-tracepoint.patch
Patch0219: 0219-mm-damon-implement-a-debugfs-based-user-space-interf.patch
Patch0220: 0220-mm-damon-dbgfs-export-kdamond-pid-to-the-user-space.patch
Patch0221: 0221-mm-damon-dbgfs-support-multiple-contexts.patch
Patch0222: 0222-mm-damon-grammar-s-works-work.patch
Patch0223: 0223-include-linux-damon.h-fix-kernel-doc-comments-for-da.patch
Patch0224: 0224-mm-damon-core-print-kdamond-start-log-in-debug-mode-.patch
Patch0225: 0225-mm-damon-remove-unnecessary-do_exit-from-kdamond.patch
Patch0226: 0226-mm-damon-needn-t-hold-kdamond_lock-to-print-pid-of-k.patch
Patch0227: 0227-mm-damon-core-nullify-pointer-ctx-kdamond-with-a-NUL.patch
Patch0228: 0228-mm-damon-core-account-age-of-target-regions.patch
Patch0229: 0229-mm-damon-core-implement-DAMON-based-Operation-Scheme.patch
Patch0230: 0230-mm-damon-vaddr-support-DAMON-based-Operation-Schemes.patch
Patch0231: 0231-mm-damon-dbgfs-support-DAMON-based-Operation-Schemes.patch
Patch0232: 0232-mm-damon-schemes-implement-statistics-feature.patch
Patch0233: 0233-mm-damon-dbgfs-Implement-recording-feature.patch
Patch0234: 0234-damon-dbgfs-Allow-users-to-set-initial-monitoring-ta.patch
Patch0235: 0235-mm-damon-vaddr-Separate-commonly-usable-functions.patch
Patch0236: 0236-mm-damon-Implement-primitives-for-physical-address-s.patch
Patch0237: 0237-damon-dbgfs-Support-physical-memory-monitoring.patch
Patch0238: 0238-mm-damon-paddr-Separate-commonly-usable-functions.patch
Patch0239: 0239-mm-damon-Introduce-arbitrary-target-type.patch
Patch0240: 0240-mm-damon-Implement-primitives-for-page-granularity-i.patch
Patch0241: 0241-mm-damon-paddr-Support-the-pageout-scheme.patch
Patch0242: 0242-mm-damon-damos-Make-schemes-aggressiveness-controlla.patch
Patch0243: 0243-damon-core-schemes-Skip-already-charged-targets-and-.patch
Patch0244: 0244-mm-damon-schemes-Implement-time-quota.patch
Patch0245: 0245-mm-damon-dbgfs-Support-schemes-time-IO-quotas.patch
Patch0246: 0246-mm-damon-schemes-Prioritize-regions-within-the-quota.patch
Patch0247: 0247-mm-damon-vaddr-paddr-Support-pageout-prioritization.patch
Patch0248: 0248-mm-damon-dbgfs-Support-prioritization-weights.patch
Patch0249: 0249-mm-damon-schemes-Activate-schemes-based-on-a-waterma.patch
Patch0250: 0250-mm-damon-dbgfs-Support-watermarks.patch
Patch0251: 0251-mm-damon-Introduce-DAMON-based-reclamation.patch
Patch0252: 0252-arm64-lto-Strengthen-READ_ONCE-to-acquire-when-CONFI.patch
Patch0253: 0253-arm64-vmlinux.lds.S-Drop-redundant-.init.rodata.patch
Patch0254: 0254-arm64-disable-recordmcount-with-DYNAMIC_FTRACE_WITH_.patch
Patch0255: 0255-arm64-rename-S_FRAME_SIZE-to-PT_REGS_SIZE.patch
Patch0256: 0256-arm64-remove-EL0-exception-frame-record.patch
Patch0257: 0257-arm64-stacktrace-Report-when-we-reach-the-end-of-the.patch
Patch0258: 0258-arm64-stacktrace-restore-terminal-records.patch
Patch0259: 0259-arm64-Implement-stack-trace-termination-record.patch
Patch0260: 0260-arm64-Introduce-stack-trace-reliability-checks-in-th.patch
Patch0261: 0261-arm64-Create-a-list-of-SYM_CODE-functions-check-retu.patch
Patch0262: 0262-arm64-Implement-arch_stack_walk_reliable.patch
Patch0263: 0263-rbtree-Add-generic-add-and-find-helpers.patch
Patch0264: 0264-objtool-Fully-validate-the-stack-frame.patch
Patch0265: 0265-objtool-Support-addition-to-set-CFA-base.patch
Patch0266: 0266-objtool-Make-SP-memory-operation-match-PUSH-POP-sema.patch
Patch0267: 0267-objtool-Fix-reloc-generation-on-big-endian-cross-com.patch
Patch0268: 0268-objtool-Fix-x86-orc-generation-on-big-endian-cross-c.patch
Patch0269: 0269-objtool-Rework-header-include-paths.patch
Patch0270: 0270-objtool-Add-asm-version-of-STACK_FRAME_NON_STANDARD.patch
Patch0271: 0271-x86-ftrace-Support-objtool-vmlinux.o-validation-in-f.patch
Patch0272: 0272-x86-acpi-Support-objtool-validation-in-wakeup_64.S.patch
Patch0273: 0273-x86-power-Move-restore_registers-to-top-of-the-file.patch
Patch0274: 0274-x86-power-Support-objtool-validation-in-hibernate_as.patch
Patch0275: 0275-objtool-x86-Additionally-decode-mov-rsp-reg.patch
Patch0276: 0276-objtool-Support-stack-swizzle.patch
Patch0277: 0277-objtool-Fix-stack-swizzle-for-FRAME_POINTER-y.patch
Patch0278: 0278-objtool-Add-a-pass-for-generating-__mcount_loc.patch
Patch0279: 0279-objtool-Don-t-autodetect-vmlinux.o.patch
Patch0280: 0280-objtool-Split-noinstr-validation-from-vmlinux.patch
Patch0281: 0281-objtool-x86-Fix-uaccess-PUSHF-POPF-validation.patch
Patch0282: 0282-arm64-uaccess-move-uao_-alternatives-to-asm-uaccess..patch
Patch0283: 0283-arm64-alternatives-Split-up-alternative.h.patch
Patch0284: 0284-objtool-Allow-UNWIND_HINT-to-suppress-dodgy-stack-mo.patch
Patch0285: 0285-objtool-x86-Renumber-CFI_reg.patch
Patch0286: 0286-objtool-x86-Rewrite-LEA-decode.patch
Patch0287: 0287-objtool-x86-Simplify-register-decode.patch
Patch0288: 0288-objtool-x86-Support-riz-encodings.patch
Patch0289: 0289-objtool-x86-Rewrite-ADD-SUB-AND.patch
Patch0290: 0290-objtool-x86-More-ModRM-sugar.patch
Patch0291: 0291-objtool-Add-backup.patch
Patch0292: 0292-objtool-Collate-parse_options-users.patch
Patch0293: 0293-objtool-Parse-options-from-OBJTOOL_ARGS.patch
Patch0294: 0294-arm64-Move-patching-utilities-out-of-instruction-enc.patch
Patch0295: 0295-arm64-insn-Reduce-header-dependencies-of-instruction.patch
Patch0296: 0296-arm64-Move-instruction-encoder-decoder-under-lib.patch
Patch0297: 0297-arm64-insn-Add-SVE-instruction-class.patch
Patch0298: 0298-arm64-insn-Add-barrier-encodings.patch
Patch0299: 0299-arm64-insn-Add-some-opcodes-to-instruction-decoder.patch
Patch0300: 0300-arm64-insn-Add-load-store-decoding-helpers.patch
Patch0301: 0301-tools-Add-some-generic-functions-and-headers.patch
Patch0302: 0302-tools-arm64-Make-aarch64-instruction-decoder-availab.patch
Patch0303: 0303-tools-bug-Remove-duplicate-definition.patch
Patch0304: 0304-objtool-arm64-Add-base-definition-for-arm64-backend.patch
Patch0305: 0305-objtool-arm64-Decode-add-sub-instructions.patch
Patch0306: 0306-objtool-arm64-Decode-jump-and-call-related-instructi.patch
Patch0307: 0307-objtool-arm64-Decode-other-system-instructions.patch
Patch0308: 0308-objtool-arm64-Decode-load-store-instructions.patch
Patch0309: 0309-objtool-arm64-Decode-LDR-instructions.patch
Patch0310: 0310-objtool-arm64-Accept-padding-in-code-sections.patch
Patch0311: 0311-objtool-arm64-Handle-supported-relocations-in-altern.patch
Patch0312: 0312-objtool-arm64-Ignore-replacement-section-for-alterna.patch
Patch0313: 0313-objtool-arm64-Enable-stack-validation-for-arm64.patch
Patch0314: 0314-arm64-bug-Add-reachable-annotation-to-warning-macros.patch
Patch0315: 0315-arm64-kgdb-Mark-code-following-kgdb-brk-as-reachable.patch
Patch0316: 0316-arm64-Add-intra-function-call-annotations.patch
Patch0317: 0317-arm64-Skip-validation-of-qcom_link_stack_sanitizatio.patch
Patch0318: 0318-arm64-kernel-Add-exception-on-kuser32-to-prevent-sta.patch
Patch0319: 0319-arm64-Mark-sigreturn32.o-as-containing-non-standard-.patch
Patch0320: 0320-arm64-entry-Compile-out-unnecessary-symbols.patch
Patch0321: 0321-arm64-crypto-Remove-unnecessary-stackframe.patch
Patch0322: 0322-arm64-sleep-Properly-set-frame-pointer-before-call.patch
Patch0323: 0323-arm64-Move-constant-to-rodata.patch
Patch0324: 0324-arm64-entry-Mark-tramp_exit-as-local-symbols.patch
Patch0325: 0325-arm64-head.S-rename-el2_setup-init_kernel_el.patch
Patch0326: 0326-arm64-Change-symbol-annotations.patch
Patch0327: 0327-objtool-check-Support-data-in-text-section.patch
Patch0328: 0328-arm64-head-avoid-symbol-names-pointing-into-first-64.patch
Patch0329: 0329-arm64-head-tidy-up-the-Image-header-definition.patch
Patch0330: 0330-arm64-efi-header-Mark-efi-header-as-data.patch
Patch0331: 0331-arm64-head-Mark-constants-as-data.patch
Patch0332: 0332-arm64-proc-Mark-constant-as-data.patch
Patch0333: 0333-arm64-crypto-Mark-data-in-code-sections.patch
Patch0334: 0334-objtool-arm64-Add-unwind_hint-support.patch
Patch0335: 0335-arm64-Annotate-ASM-symbols-with-unknown-stack-state.patch
Patch0336: 0336-arm64-entry-Annotate-valid-stack-in-kernel-entry.patch
Patch0337: 0337-arm64-entry-Add-annotation-when-switching-to-from-th.patch
Patch0338: 0338-arm64-entry-Annotate-code-switching-to-tasks.patch
Patch0339: 0339-arm64-kvm-Annotate-stack-state-for-guest-enter-exit-.patch
Patch0340: 0340-arm64-implement-live-patching.patch
Patch0341: 0341-sched-Simplify-wake_up_-idle.patch
Patch0342: 0342-sched-livepatch-Use-wake_up_if_idle.patch
Patch0343: 0343-ARM64-kvm-vgic-v3-sr-Bug-when-trying-to-read-invalid.patch
Patch0344: 0344-efa-update-to-1.14.1.patch
Patch0345: 0345-linux-kvm.h-Fix-KVM_CAP_PTP_KVM-numbering-to-match-u.patch
Patch0346: 0346-arm64-module-Use-aarch64_insn_write-when-updating-re.patch
Patch0347: 0347-ipc-replace-costly-bailout-check-in-sysvipc_find_ipc.patch
Patch0348: 0348-nvme-add-48-bit-DMA-address-quirk-for-Amazon-NVMe-co.patch
Patch0349: 0349-Revert-PCI-MSI-Enforce-that-MSI-X-table-entry-is-mas.patch
Patch0350: 0350-Revert-mm-damon-Introduce-DAMON-based-reclamation.patch
Patch0351: 0351-Revert-mm-damon-dbgfs-Support-watermarks.patch
Patch0352: 0352-Revert-mm-damon-schemes-Activate-schemes-based-on-a-.patch
Patch0353: 0353-Revert-mm-damon-dbgfs-Support-prioritization-weights.patch
Patch0354: 0354-Revert-mm-damon-vaddr-paddr-Support-pageout-prioriti.patch
Patch0355: 0355-Revert-mm-damon-schemes-Prioritize-regions-within-th.patch
Patch0356: 0356-Revert-mm-damon-dbgfs-Support-schemes-time-IO-quotas.patch
Patch0357: 0357-Revert-mm-damon-schemes-Implement-time-quota.patch
Patch0358: 0358-Revert-damon-core-schemes-Skip-already-charged-targe.patch
Patch0359: 0359-Revert-mm-damon-damos-Make-schemes-aggressiveness-co.patch
Patch0360: 0360-Revert-mm-damon-paddr-Support-the-pageout-scheme.patch
Patch0361: 0361-Revert-mm-damon-Implement-primitives-for-page-granul.patch
Patch0362: 0362-Revert-mm-damon-Introduce-arbitrary-target-type.patch
Patch0363: 0363-Revert-mm-damon-paddr-Separate-commonly-usable-funct.patch
Patch0364: 0364-Revert-damon-dbgfs-Support-physical-memory-monitorin.patch
Patch0365: 0365-Revert-mm-damon-Implement-primitives-for-physical-ad.patch
Patch0366: 0366-Revert-mm-damon-vaddr-Separate-commonly-usable-funct.patch
Patch0367: 0367-Revert-damon-dbgfs-Allow-users-to-set-initial-monito.patch
Patch0368: 0368-Revert-mm-damon-dbgfs-Implement-recording-feature.patch
Patch0369: 0369-Revert-mm-damon-schemes-implement-statistics-feature.patch
Patch0370: 0370-Revert-mm-damon-dbgfs-support-DAMON-based-Operation-.patch
Patch0371: 0371-Revert-mm-damon-vaddr-support-DAMON-based-Operation-.patch
Patch0372: 0372-Revert-mm-damon-core-implement-DAMON-based-Operation.patch
Patch0373: 0373-Revert-mm-damon-core-account-age-of-target-regions.patch
Patch0374: 0374-Revert-mm-damon-core-nullify-pointer-ctx-kdamond-wit.patch
Patch0375: 0375-Revert-mm-damon-needn-t-hold-kdamond_lock-to-print-p.patch
Patch0376: 0376-Revert-mm-damon-remove-unnecessary-do_exit-from-kdam.patch
Patch0377: 0377-Revert-mm-damon-core-print-kdamond-start-log-in-debu.patch
Patch0378: 0378-Revert-include-linux-damon.h-fix-kernel-doc-comments.patch
Patch0379: 0379-Revert-mm-damon-grammar-s-works-work.patch
Patch0380: 0380-Documentation-add-documents-for-DAMON.patch
Patch0381: 0381-mm-damon-add-kunit-tests.patch
Patch0382: 0382-mm-damon-add-user-space-selftests.patch
Patch0383: 0383-MAINTAINERS-update-for-DAMON.patch
Patch0384: 0384-mm-damon-don-t-use-strnlen-with-known-bogus-source-l.patch
Patch0385: 0385-mm-damon-core-test-fix-wrong-expectations-for-damon_.patch
Patch0386: 0386-mm-damon-grammar-s-works-work.patch
Patch0387: 0387-include-linux-damon.h-fix-kernel-doc-comments-for-da.patch
Patch0388: 0388-mm-damon-core-print-kdamond-start-log-in-debug-mode-.patch
Patch0389: 0389-mm-damon-remove-unnecessary-do_exit-from-kdamond.patch
Patch0390: 0390-mm-damon-needn-t-hold-kdamond_lock-to-print-pid-of-k.patch
Patch0391: 0391-mm-damon-core-nullify-pointer-ctx-kdamond-with-a-NUL.patch
Patch0392: 0392-mm-damon-core-account-age-of-target-regions.patch
Patch0393: 0393-mm-damon-core-implement-DAMON-based-Operation-Scheme.patch
Patch0394: 0394-mm-damon-vaddr-support-DAMON-based-Operation-Schemes.patch
Patch0395: 0395-mm-damon-dbgfs-support-DAMON-based-Operation-Schemes.patch
Patch0396: 0396-mm-damon-schemes-implement-statistics-feature.patch
Patch0397: 0397-selftests-damon-add-schemes-debugfs-tests.patch
Patch0398: 0398-Docs-admin-guide-mm-damon-document-DAMON-based-Opera.patch
Patch0399: 0399-mm-damon-dbgfs-allow-users-to-set-initial-monitoring.patch
Patch0400: 0400-mm-damon-dbgfs-test-add-a-unit-test-case-for-init_re.patch
Patch0401: 0401-Docs-admin-guide-mm-damon-document-init_regions-feat.patch
Patch0402: 0402-mm-damon-vaddr-separate-commonly-usable-functions.patch
Patch0403: 0403-mm-damon-implement-primitives-for-physical-address-s.patch
Patch0404: 0404-mm-damon-dbgfs-support-physical-memory-monitoring.patch
Patch0405: 0405-Docs-DAMON-document-physical-memory-monitoring-suppo.patch
Patch0406: 0406-mm-damon-vaddr-constify-static-mm_walk_ops.patch
Patch0407: 0407-mm-damon-dbgfs-remove-unnecessary-variables.patch
Patch0408: 0408-mm-damon-paddr-support-the-pageout-scheme.patch
Patch0409: 0409-mm-damon-schemes-implement-size-quota-for-schemes-ap.patch
Patch0410: 0410-mm-damon-schemes-skip-already-charged-targets-and-re.patch
Patch0411: 0411-mm-damon-schemes-implement-time-quota.patch
Patch0412: 0412-mm-damon-dbgfs-support-quotas-of-schemes.patch
Patch0413: 0413-mm-damon-selftests-support-schemes-quotas.patch
Patch0414: 0414-mm-damon-schemes-prioritize-regions-within-the-quota.patch
Patch0415: 0415-mm-damon-vaddr-paddr-support-pageout-prioritization.patch
Patch0416: 0416-mm-damon-dbgfs-support-prioritization-weights.patch
Patch0417: 0417-tools-selftests-damon-update-for-regions-prioritizat.patch
Patch0418: 0418-mm-damon-schemes-activate-schemes-based-on-a-waterma.patch
Patch0419: 0419-mm-damon-dbgfs-support-watermarks.patch
Patch0420: 0420-selftests-damon-support-watermarks.patch
Patch0421: 0421-mm-damon-introduce-DAMON-based-Reclamation-DAMON_REC.patch
Patch0422: 0422-Documentation-admin-guide-mm-damon-add-a-document-fo.patch
Patch0423: 0423-mm-damon-remove-unnecessary-variable-initialization.patch
Patch0424: 0424-mm-damon-dbgfs-add-adaptive_targets-list-check-befor.patch
Patch0425: 0425-Docs-admin-guide-mm-damon-start-fix-wrong-example-co.patch
Patch0426: 0426-Docs-admin-guide-mm-damon-start-fix-a-wrong-link.patch
Patch0427: 0427-Docs-admin-guide-mm-damon-start-simplify-the-content.patch
Patch0428: 0428-mm-damon-simplify-stop-mechanism.patch
Patch0429: 0429-mm-damon-fix-a-few-spelling-mistakes-in-comments-and.patch
Patch0430: 0430-mm-damon-remove-return-value-from-before_terminate-c.patch
Patch0431: 0431-mm-damon-dbgfs-use-__GFP_NOWARN-for-user-specified-s.patch
Patch0432: 0432-mm-damon-dbgfs-fix-missed-use-of-damon_dbgfs_lock.patch
Patch0433: 0433-ena-Update-to-2.6.0.patch
Patch0434: 0434-lustre-update-to-AmazonFSxLustreClient-v2.10.8-10.patch
Patch0435: 0435-drivers-base-memory-introduce-memory_block_-online-o.patch
Patch0436: 0436-mm-memory_hotplug-relax-fully-spanned-sections-check.patch
Patch0437: 0437-mm-memory_hotplug-factor-out-adjusting-present-pages.patch
Patch0438: 0438-mm-memory_hotplug-allocate-memmap-from-the-added-mem.patch
Patch0439: 0439-acpi-memhotplug-enable-MHP_MEMMAP_ON_MEMORY-when-sup.patch
Patch0440: 0440-mm-memory_hotplug-add-kernel-boot-option-to-enable-m.patch
Patch0441: 0441-x86-Kconfig-introduce-ARCH_MHP_MEMMAP_ON_MEMORY_ENAB.patch
Patch0442: 0442-arm64-Kconfig-introduce-ARCH_MHP_MEMMAP_ON_MEMORY_EN.patch
Patch0443: 0443-drivers-base-memory-fix-trying-offlining-memory-bloc.patch
Patch0444: 0444-drivers-base-memory-use-MHP_MEMMAP_ON_MEMORY-from-th.patch
Patch0445: 0445-mm-add-offline-page-reporting-interface.patch
Patch0446: 0446-virtio-add-hack-to-allow-pre-mapped-scatterlists.patch
Patch0447: 0447-virtio-balloon-optionally-report-offlined-memory-ran.patch
Patch0448: 0448-ENA-Update-to-v2.6.1.patch
Patch0449: 0449-lustre-update-to-AmazonFSxLustreClient-v2.12.8-1.patch
Patch0450: 0450-sched-Improve-wake_up_all_idle_cpus-take-2.patch
Patch0451: 0451-timers-implement-usleep_idle_range.patch
Patch0452: 0452-mm-damon-core-fix-fake-load-reports-due-to-uninterru.patch
Patch0453: 0453-mm-damon-core-use-better-timer-mechanisms-selection-.patch
Patch0454: 0454-mm-damon-dbgfs-remove-an-unnecessary-error-message.patch
Patch0455: 0455-mm-damon-core-remove-unnecessary-error-messages.patch
Patch0456: 0456-mm-damon-vaddr-remove-an-unnecessary-warning-message.patch
Patch0457: 0457-mm-damon-vaddr-test-split-a-test-function-having-102.patch
Patch0458: 0458-mm-damon-vaddr-test-remove-unnecessary-variables.patch
Patch0459: 0459-selftests-damon-skip-test-if-DAMON-is-running.patch
Patch0460: 0460-selftests-damon-test-DAMON-enabling-with-empty-targe.patch
Patch0461: 0461-selftests-damon-test-wrong-DAMOS-condition-ranges-in.patch
Patch0462: 0462-selftests-damon-test-debugfs-file-reads-writes-with-.patch
Patch0463: 0463-selftests-damon-split-test-cases.patch
Patch0464: 0464-mm-damon-dbgfs-protect-targets-destructions-with-kda.patch
Patch0465: 0465-mm-damon-dbgfs-fix-struct-pid-leaks-in-dbgfs_target_.patch
Patch0466: 0466-sched-numa-Rename-nr_running-and-break-out-the-magic.patch
Patch0467: 0467-sched-Avoid-unnecessary-calculation-of-load-imbalanc.patch
Patch0468: 0468-sched-numa-Allow-a-floating-imbalance-between-NUMA-n.patch
Patch0469: 0469-sched-Limit-the-amount-of-NUMA-imbalance-that-can-ex.patch
Patch0470: 0470-Add-out-of-tree-smartpqi-driver-Version-2.1.14-030-a.patch
Patch0471: 0471-bpf-Implement-get_current_task_btf-and-RET_PTR_TO_BT.patch
Patch0472: 0472-bpf-Introduce-composable-reg-ret-and-arg-types.patch
Patch0473: 0473-bpf-Replace-ARG_XXX_OR_NULL-with-ARG_XXX-PTR_MAYBE_N.patch
Patch0474: 0474-bpf-Replace-RET_XXX_OR_NULL-with-RET_XXX-PTR_MAYBE_N.patch
Patch0475: 0475-bpf-Extract-nullable-reg-type-conversion-into-a-help.patch
Patch0476: 0476-bpf-Replace-PTR_TO_XXX_OR_NULL-with-PTR_TO_XXX-PTR_M.patch
Patch0477: 0477-bpf-Introduce-MEM_RDONLY-flag.patch
Patch0478: 0478-bpf-Convert-PTR_TO_MEM_OR_NULL-to-composable-types.patch
Patch0479: 0479-bpf-Make-per_cpu_ptr-return-rdonly-PTR_TO_MEM.patch
Patch0480: 0480-bpf-Add-MEM_RDONLY-for-helper-args-that-are-pointers.patch
Patch0481: 0481-bpf-selftests-Test-PTR_TO_RDONLY_MEM.patch
Patch0482: 0482-sock-remove-one-redundant-SKB_FRAG_PAGE_ORDER-macro.patch
Patch0483: 0483-netfilter-nf_tables-validate-registers-coming-from-u.patch
Patch0484: 0484-Revert-lustre-update-to-AmazonFSxLustreClient-v2.12..patch
Patch0485: 0485-svm-fix-backport-of-KVM-X86-Move-write_l1_tsc_offset.patch
Patch0486: 0486-mm-filemap-c-break-generic_file_buffered_read-up-int.patch
Patch0487: 0487-mm-filemap.c-generic_file_buffered_read-now-uses-fin.patch
Patch0488: 0488-ENA-Update-to-v2.7.1.patch
Patch0489: 0489-lustre-update-to-AmazonFSxLustreClient-v2.10.8-11.patch
Patch0490: 0490-Correct-read-overflow-in-page-touching-DMA-ops-bindi.patch
Patch0491: 0491-iov_iter-track-truncated-size.patch
Patch0492: 0492-bpf-Generalize-check_ctx_reg-for-reuse-with-other-ty.patch
Patch0493: 0493-bpf-Mark-PTR_TO_FUNC-register-initially-with-zero-of.patch
Patch0494: 0494-bpf-Generally-fix-helper-register-offset-check.patch
Patch0495: 0495-bpf-Fix-out-of-bounds-access-for-ringbuf-helpers.patch
Patch0496: 0496-bpf-Fix-ringbuf-memory-type-confusion-when-passing-t.patch
Patch0497: 0497-selftests-bpf-Add-verifier-test-for-PTR_TO_MEM-spill.patch
Patch0498: 0498-bpf-selftests-Add-verifier-test-for-mem_or_null-regi.patch
Patch0499: 0499-bpf-selftests-Add-various-ringbuf-tests-with-invalid.patch
Patch0500: 0500-mm-migrate-Don-t-drop-mapping-lock-in-unmap_and_move.patch
Patch0501: 0501-enable-rfc4106-gcm-aes-for-fips.patch
Patch0502: 0502-sched-fair-Improve-consistency-of-allowed-NUMA-balan.patch
Patch0503: 0503-sched-fair-Adjust-the-allowed-NUMA-imbalance-when-SD.patch
Patch0504: 0504-ENA-Update-to-v2.7.3.patch
Patch0505: 0505-ENA-Update-to-v2.7.4.patch
Patch0506: 0506-ext4-reduce-computation-of-overhead-during-resize.patch
Patch0507: 0507-Mitigate-unbalanced-RETs-on-vmexit-via-serialising-w.patch
Patch0508: 0508-mm-damon-unified-access_check-function-naming-rules.patch
Patch0509: 0509-mm-damon-add-age-of-region-tracepoint-support.patch
Patch0510: 0510-mm-damon-core-use-abs-instead-of-diff_of.patch
Patch0511: 0511-mm-damon-remove-some-unneeded-function-definitions-i.patch
Patch0512: 0512-mm-damon-vaddr-remove-swap_ranges-and-replace-it-wit.patch
Patch0513: 0513-mm-damon-schemes-add-the-validity-judgment-of-thresh.patch
Patch0514: 0514-mm-damon-move-damon_rand-definition-into-damon.h.patch
Patch0515: 0515-mm-damon-modify-damon_rand-macro-to-static-inline-fu.patch
Patch0516: 0516-mm-damon-convert-macro-functions-to-static-inline-fu.patch
Patch0517: 0517-Docs-admin-guide-mm-damon-usage-update-for-scheme-qu.patch
Patch0518: 0518-Docs-admin-guide-mm-damon-usage-remove-redundant-inf.patch
Patch0519: 0519-Docs-admin-guide-mm-damon-usage-mention-tracepoint-a.patch
Patch0520: 0520-Docs-admin-guide-mm-damon-usage-update-for-kdamond_p.patch
Patch0521: 0521-mm-damon-remove-a-mistakenly-added-comment-for-a-fut.patch
Patch0522: 0522-mm-damon-schemes-account-scheme-actions-that-success.patch
Patch0523: 0523-mm-damon-schemes-account-how-many-times-quota-limit-.patch
Patch0524: 0524-mm-damon-reclaim-provide-reclamation-statistics.patch
Patch0525: 0525-Docs-admin-guide-mm-damon-reclaim-document-statistic.patch
Patch0526: 0526-mm-damon-dbgfs-support-all-DAMOS-stats.patch
Patch0527: 0527-Docs-admin-guide-mm-damon-usage-update-for-schemes-s.patch
Patch0528: 0528-mm-damon-add-access-checking-for-hugetlb-pages.patch
Patch0529: 0529-mm-damon-move-the-implementation-of-damon_insert_reg.patch
Patch0530: 0530-mm-damon-dbgfs-remove-an-unnecessary-variable.patch
Patch0531: 0531-mm-damon-vaddr-use-pr_debug-for-damon_va_three_regio.patch
Patch0532: 0532-mm-damon-vaddr-hide-kernel-pointer-from-damon_va_thr.patch
Patch0533: 0533-mm-damon-hide-kernel-pointer-from-tracepoint-event.patch
Patch0534: 0534-mm-damon-minor-cleanup-for-damon_pa_young.patch
Patch0535: 0535-mm-damon-dbgfs-init_regions-use-target-index-instead.patch
Patch0536: 0536-Docs-admin-guide-mm-damon-usage-update-for-changed-i.patch
Patch0537: 0537-mm-damon-core-move-damon_set_targets-into-dbgfs.patch
Patch0538: 0538-mm-damon-remove-the-target-id-concept.patch
Patch0539: 0539-mm-damon-remove-redundant-page-validation.patch
Patch0540: 0540-mm-damon-rename-damon_primitives-to-damon_operations.patch
Patch0541: 0541-mm-damon-let-monitoring-operations-can-be-registered.patch
Patch0542: 0542-mm-damon-paddr-vaddr-register-themselves-to-DAMON-in.patch
Patch0543: 0543-mm-damon-reclaim-use-damon_select_ops-instead-of-dam.patch
Patch0544: 0544-mm-damon-dbgfs-use-damon_select_ops-instead-of-damon.patch
Patch0545: 0545-mm-damon-dbgfs-use-operations-id-for-knowing-if-the-.patch
Patch0546: 0546-mm-damon-dbgfs-test-fix-is_target_id-change.patch
Patch0547: 0547-mm-damon-paddr-vaddr-remove-damon_-p-v-a_-target_val.patch
Patch0548: 0548-mm-damon-remove-unnecessary-CONFIG_DAMON-option.patch
Patch0549: 0549-Docs-damon-update-outdated-term-regions-update-inter.patch
Patch0550: 0550-mm-damon-core-allow-non-exclusive-DAMON-start-stop.patch
Patch0551: 0551-mm-damon-core-add-number-of-each-enum-type-values.patch
Patch0552: 0552-mm-damon-implement-a-minimal-stub-for-sysfs-based-DA.patch
Patch0553: 0553-mm-damon-sysfs-link-DAMON-for-virtual-address-spaces.patch
Patch0554: 0554-mm-damon-sysfs-support-the-physical-address-space-mo.patch
Patch0555: 0555-mm-damon-sysfs-support-DAMON-based-Operation-Schemes.patch
Patch0556: 0556-mm-damon-sysfs-support-DAMOS-quotas.patch
Patch0557: 0557-mm-damon-sysfs-support-schemes-prioritization.patch
Patch0558: 0558-mm-damon-sysfs-support-DAMOS-watermarks.patch
Patch0559: 0559-mm-damon-sysfs-support-DAMOS-stats.patch
Patch0560: 0560-selftests-damon-add-a-test-for-DAMON-sysfs-interface.patch
Patch0561: 0561-Docs-admin-guide-mm-damon-usage-document-DAMON-sysfs.patch
Patch0562: 0562-mm-damon-sysfs-remove-repeat-container_of-in-damon_s.patch
Patch0563: 0563-mm-damon-prevent-activated-scheme-from-sleeping-by-d.patch
Patch0564: 0564-Docs-ABI-testing-add-DAMON-sysfs-interface-ABI-docum.patch
Patch0565: 0565-damon-vaddr-test-tweak-code-to-make-the-logic-cleare.patch
Patch0566: 0566-mm-damon-core-test-add-a-kunit-test-case-for-ops-reg.patch
Patch0567: 0567-mm-damon-remove-unnecessary-type-castings.patch
Patch0568: 0568-mm-damon-reclaim-fix-the-timer-always-stays-active.patch
Patch0569: 0569-mm-damon-core-add-a-function-for-damon_operations-re.patch
Patch0570: 0570-mm-damon-sysfs-add-a-file-for-listing-available-moni.patch
Patch0571: 0571-selftets-damon-sysfs-test-existence-and-permission-o.patch
Patch0572: 0572-Docs-ABI-admin-guide-damon-document-avail_operations.patch
Patch0573: 0573-mm-damon-vaddr-register-a-damon_operations-for-fixed.patch
Patch0574: 0574-mm-damon-sysfs-support-fixed-virtual-address-ranges-.patch
Patch0575: 0575-Docs-ABI-admin-guide-damon-update-for-fixed-virtual-.patch
Patch0576: 0576-mm-damon-core-add-a-new-callback-for-watermarks-chec.patch
Patch0577: 0577-mm-damon-core-finish-kdamond-as-soon-as-any-callback.patch
Patch0578: 0578-mm-damon-vaddr-generalize-damon_va_apply_three_regio.patch
Patch0579: 0579-mm-damon-vaddr-move-damon_set_regions-to-core.patch
Patch0580: 0580-mm-damon-vaddr-remove-damon_va_apply_three_regions.patch
Patch0581: 0581-mm-damon-sysfs-prohibit-multiple-physical-address-sp.patch
Patch0582: 0582-mm-damon-sysfs-move-targets-setup-code-to-a-separate.patch
Patch0583: 0583-mm-damon-sysfs-reuse-damon_set_regions-for-regions-s.patch
Patch0584: 0584-mm-damon-sysfs-use-enum-for-state-input-handling.patch
Patch0585: 0585-mm-damon-sysfs-update-schemes-stat-in-the-kdamond-co.patch
Patch0586: 0586-mm-damon-sysfs-support-online-inputs-update.patch
Patch0587: 0587-Docs-ABI-admin-guide-damon-Update-for-state-sysfs-fi.patch
Patch0588: 0588-mm-damon-reclaim-support-online-inputs-update.patch
Patch0589: 0589-Docs-admin-guide-mm-damon-reclaim-document-commit_in.patch
Patch0590: 0590-mm-damon-reclaim-use-resource_size-function-on-resou.patch
Patch0591: 0591-mm-damon-add-documentation-for-Enum-value.patch
Patch0592: 0592-mm-damon-use-HPAGE_PMD_SIZE.patch
Patch0593: 0593-mm-damon-reclaim-schedule-damon_reclaim_timer-only-a.patch
Patch0594: 0594-mm-damon-use-set_huge_pte_at-to-make-huge-pte-old.patch
Patch0595: 0595-mm-damon-reclaim-fix-potential-memory-leak-in-damon_.patch
Patch0596: 0596-mm-damon-dbgfs-avoid-duplicate-context-directory-cre.patch
Patch0597: 0597-Revert-x86-speculation-Add-RSB-VM-Exit-protections.patch
Patch0598: 0598-DOWNSTREAM-ONLY-Revert-Makefile-link-with-z-noexecst.patch
Patch0599: 0599-ENA-Update-to-v2.8.0.patch
Patch0600: 0600-lustre-update-to-AmazonFSxLustreClient-v2.12.8-fsx4.patch
Patch0601: 0601-scsi-mpi3mr-Add-mpi30-Rev-R-headers-and-Kconfig.patch
Patch0602: 0602-scsi-mpi3mr-Base-driver-code.patch
Patch0603: 0603-scsi-mpi3mr-Create-operational-request-and-reply-que.patch
Patch0604: 0604-scsi-mpi3mr-Add-support-for-queue-command-processing.patch
Patch0605: 0605-scsi-mpi3mr-Add-support-for-internal-watchdog-thread.patch
Patch0606: 0606-scsi-mpi3mr-Add-support-for-device-add-remove-event-.patch
Patch0607: 0607-scsi-mpi3mr-Add-support-for-PCIe-device-event-handli.patch
Patch0608: 0608-scsi-mpi3mr-Additional-event-handling.patch
Patch0609: 0609-scsi-mpi3mr-Add-support-for-recovering-controller.patch
Patch0610: 0610-scsi-mpi3mr-Add-support-for-timestamp-sync-with-firm.patch
Patch0611: 0611-scsi-mpi3mr-Print-IOC-info-for-debugging.patch
Patch0612: 0612-scsi-mpi3mr-Add-bios_param-SCSI-host-template-hook.patch
Patch0613: 0613-scsi-mpi3mr-Implement-SCSI-error-handler-hooks.patch
Patch0614: 0614-scsi-mpi3mr-Add-change-queue-depth-support.patch
Patch0615: 0615-scsi-mpi3mr-Allow-certain-commands-during-pci-remove.patch
Patch0616: 0616-scsi-mpi3mr-Hardware-workaround-for-UNMAP-commands-t.patch
Patch0617: 0617-scsi-mpi3mr-Add-support-for-threaded-ISR.patch
Patch0618: 0618-scsi-mpi3mr-Complete-support-for-soft-reset.patch
Patch0619: 0619-scsi-mpi3mr-Print-pending-host-I-Os-for-debugging.patch
Patch0620: 0620-scsi-mpi3mr-Wait-for-pending-I-O-completions-upon-de.patch
Patch0621: 0621-scsi-mpi3mr-Add-support-for-PM-suspend-and-resume.patch
Patch0622: 0622-scsi-mpi3mr-Add-support-for-DSN-secure-firmware-chec.patch
Patch0623: 0623-scsi-mpi3mr-Add-EEDP-DIF-DIX-support.patch
Patch0624: 0624-scsi-mpi3mr-Add-event-handling-debug-prints.patch
Patch0625: 0625-scsi-mpi3mr-Fix-fall-through-warning-for-Clang.patch
Patch0626: 0626-scsi-mpi3mr-Fix-a-double-free.patch
Patch0627: 0627-scsi-mpi3mr-Delete-unnecessary-NULL-check.patch
Patch0628: 0628-scsi-mpi3mr-Fix-error-handling-in-mpi3mr_setup_isr.patch
Patch0629: 0629-scsi-mpi3mr-Fix-missing-unlock-on-error.patch
Patch0630: 0630-scsi-mpi3mr-Fix-error-return-code-in-mpi3mr_init_ioc.patch
Patch0631: 0631-scsi-mpi3mr-Make-some-symbols-static.patch
Patch0632: 0632-scsi-mpi3mr-Fix-warnings-reported-by-smatch.patch
Patch0633: 0633-scsi-mpi3mr-Fix-W-1-compilation-warnings.patch
Patch0634: 0634-scsi-mpi3mr-Set-up-IRQs-in-resume-path.patch
Patch0635: 0635-scsi-mpi3mr-Fix-duplicate-device-entries-when-scanni.patch
Patch0636: 0636-scsi-mpi3mr-Fixes-around-reply-request-queues.patch
Patch0637: 0637-scsi-mpi3mr-Fix-reporting-of-actual-data-transfer-si.patch
Patch0638: 0638-scsi-mpi3mr-Fix-memory-leaks.patch
Patch0639: 0639-mm-damon-dbgfs-fix-memory-leak-when-using-debugfs_lo.patch
Patch0640: 0640-damon-sysfs-fix-possible-memleak-on-damon_sysfs_add_.patch
Patch0641: 0641-bpf-Allow-LSM-programs-to-use-bpf-spin-locks.patch
Patch0642: 0642-bpf-Implement-task-local-storage.patch
Patch0643: 0643-io_uring-af_unix-defer-registered-files-gc-to-io_uri.patch

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root

%description
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.


%package doc
Summary: Various documentation bits found in the kernel source
Group: Documentation
%description doc
This package contains documentation files from the kernel
source. Various bits of information about the Linux kernel and the
device drivers shipped with it are documented in these files.

You'll want to install this package if you need a reference to the
options that can be passed to Linux kernel modules at load time.


%package headers
Summary: Header files for the Linux kernel for use by glibc
Group: Development/System
Obsoletes: glibc-kernheaders < 3.0-46
Provides: glibc-kernheaders = 3.0-46
%description headers
Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs.  The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package.

%package debuginfo-common-%{_target_cpu}
Summary: Kernel source files used by %{name}-debuginfo packages
Group: Development/Debug
%description debuginfo-common-%{_target_cpu}
This package is required by %{name}-debuginfo subpackages.
It provides the kernel source files common to all builds.

%if %{with_perf}
%package -n perf
Summary: Performance monitoring for the Linux kernel
Group: Development/System
Requires: libzstd
License: GPLv2
%description -n perf
This package contains the perf tool, which enables performance monitoring
of the Linux kernel.

%package -n perf-debuginfo
Summary: Debug information for package perf
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}
AutoReqProv: no
%description -n perf-debuginfo
This package provides debug information for the perf package.

# Note that this pattern only works right to match the .build-id
# symlinks because of the trailing nonmatching alternation and
# the leading .*, because of find-debuginfo.sh's buggy handling
# of matching the pattern against the symlinks file.
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%%{_bindir}/perf(\.debug)?|.*%%{_libexecdir}/perf-core/.*|.*%%{_libdir}/traceevent/plugins/.*|.*%%{_libdir}/libperf-jvmti.so(\.debug)?|XXX' -o perf-debuginfo.list}

%package -n %{py_pkg_prefix}-perf
Summary: Python bindings for apps which will manipulate perf events
Group: Development/Libraries
%description -n %{py_pkg_prefix}-perf
The python-perf package contains a module that permits applications
written in the Python programming language to use the interface
to manipulate perf events.

%package -n %{py_pkg_prefix}-perf-debuginfo
Summary: Debug information for package perf python bindings
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}
AutoReqProv: no
%description -n %{py_pkg_prefix}-perf-debuginfo
This package provides debug information for the perf python bindings.

%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%%{python_sitearch}/perf.*so(\.debug)?|XXX' -o %{py_pkg_prefix}-perf-debuginfo.list}

%endif

%if %{with_tools}
%package tools
Summary: Assortment of tools for the Linux kernel
Group: Development/System
License: GPLv2
Provides:  cpupowerutils = 1:009-0.6.p1
Obsoletes: cpupowerutils < 1:009-0.6.p1
Provides:  cpufreq-utils = 1:009-0.6.p1
Provides:  cpufrequtils = 1:009-0.6.p1
Obsoletes: cpufreq-utils < 1:009-0.6.p1
Obsoletes: cpufrequtils < 1:009-0.6.p1
Obsoletes: cpuspeed < 1:1.5-16

%description tools
This package contains the tools/ directory from the kernel source
and the supporting documentation.

%package tools-devel
Summary: Assortment of tools for the Linux kernel
Group: Development/System
License: GPLv2
Requires: kernel-tools = %{version}-%{release}
%ifarch %{cpupowerarchs}
Provides:  cpupowerutils-devel = 1:009-0.6.p1
Obsoletes: cpupowerutils-devel < 1:009-0.6.p1
%endif

%description tools-devel
This package contains the development files for the tools/ directory from
the kernel source.

%package tools-debuginfo
Summary: Debug information for package kernel-tools
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}
AutoReqProv: no
%description tools-debuginfo
This package provides debug information for package kernel-tools.

# Note that this pattern only works right to match the .build-id
# symlinks because of the trailing nonmatching alternation and
# the leading .*, because of find-debuginfo.sh's buggy handling
# of matching the pattern against the symlinks file.
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%%{_bindir}/centrino-decode(\.debug)?|.*%%{_bindir}/powernow-k8-decode(\.debug)?|.*%%{_bindir}/cpupower(\.debug)?|.*%%{_libdir}/libcpupower.*|XXX' -o kernel-tools-debuginfo.list}
%endif

%if %{with_bpftool}

%package -n bpftool
Summary: Inspection and simple manipulation of eBPF programs and maps
License: GPLv2
%description -n bpftool
This package contains the bpftool, which allows inspection and simple
manipulation of eBPF programs and maps.

%package -n bpftool-debuginfo
Summary: Debug information for package bpftool
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}
AutoReqProv: no
%description -n bpftool-debuginfo
This package provides debug information for the bpftool package.

%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%%{_sbindir}/bpftool(\.debug)?|XXX' -o bpftool-debuginfo.list}

# with_bpftool
%endif

#
# This macro creates a kernel-<subpackage>-debuginfo package.
#	%%kernel_debuginfo_package <subpackage>
#
%define kernel_debuginfo_package() \
%package %{?1:%{1}-}debuginfo\
Summary: Debug information for package %{name}%{?1:-%{1}}\
Group: Development/Debug\
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}\
Provides: %{name}%{?1:-%{1}}-debuginfo-%{_target_cpu} = %{version}-%{release}\
AutoReqProv: no\
%description -n %{name}%{?1:-%{1}}-debuginfo\
This package provides debug information for package %{name}%{?1:-%{1}}.\
This is required to use SystemTap with %{name}%{?1:-%{1}}-%{KVERREL}.\
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '/.*/%%{KVERREL}%{?1:\.%{1}}/.*|/.*%%{KVERREL}%{?1:\.%{1}}(\.debug)?' -o debuginfo%{?1}.list}\
%{nil}

#
# This macro creates a kernel-<subpackage>-devel package.
#	%%kernel_devel_package <subpackage> <pretty-name>
#
%define kernel_devel_package() \
%package %{?1:%{1}-}devel\
Summary: Development package for building kernel modules to match the %{?2:%{2} }kernel\
Group: System Environment/Kernel\
Provides: kernel%{?1:-%{1}}-devel-%{_target_cpu} = %{version}-%{release}\
Provides: kernel-devel-%{_target_cpu} = %{version}-%{release}%{?1:.%{1}}\
Provides: kernel-devel = %{version}-%{release}%{?1:.%{1}}\
Provides: kernel-devel-uname-r = %{KVERREL}%{?1:.%{1}}\
AutoReqProv: no\
%if 0%{?amzn} < 2022\
Requires(pre): %{_bindir}/find\
Requires(post): %{_sbindir}/hardlink\
Requires: gcc10\
%else\
Requires: gcc >= 10\
%endif\
Requires: perl\
Requires: elfutils-libelf-devel\
%if  "%{_gccver}" > "7"\
Provides: buildrequires(gcc) = %{_gccver}\
%endif\
%description -n kernel%{?variant}%{?1:-%{1}}-devel\
This package provides kernel headers and makefiles sufficient to build modules\
against the %{?2:%{2} }kernel package.\
%{nil}
#
# This macro creates a kernel-<subpackage> and its -devel and -debuginfo too.
#	%%define variant_summary The Linux kernel compiled for <configuration>
#	%%kernel_variant_package [-n <pretty-name>] <subpackage>
#
%define kernel_variant_package(n:) \
%package %1\
Summary: %{variant_summary}\
Group: System Environment/Kernel\
%kernel_reqprovconf\
%{expand:%%kernel_devel_package %1 %{!?-n:%1}%{?-n:%{-n*}}}\
%{expand:%%kernel_debuginfo_package %1}\
%{nil}


# First the auxiliary packages of the main kernel package.
%kernel_devel_package
%kernel_debuginfo_package


# Now, each variant package.

%define variant_summary The Linux kernel compiled with extra debugging enabled
%kernel_variant_package debug
%description debug
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

This variant of the kernel has numerous debugging options enabled.
It should only be installed when trying to gather additional information
on kernel bugs, as some of these options impact performance noticably.


%prep
# more sanity checking; do it quietly
if [ "%{patches}" != "%%{patches}" ] ; then
  for patch in %{patches} ; do
    if [ ! -f $patch ] ; then
      echo "ERROR: Patch  ${patch##/*/}  listed in specfile but is missing"
      exit 1
    fi
  done
fi 2>/dev/null

patch_command='patch -p1 -F1 -s'

ApplyNoCheckPatch()
{
  local patch=$1
  shift
  case "$patch" in
    *.bz2) bunzip2 < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
    *.gz) gunzip < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
    *) $patch_command ${1+"$@"} < $patch ;;
  esac
}

ApplyPatch()
{
  local patch=$1
  shift
  if [ ! -f $RPM_SOURCE_DIR/$patch ]; then
    exit 1
  fi
  if ! grep -E "^Patch[0-9]+: $patch\$" %{_specdir}/${RPM_PACKAGE_NAME%%%%%{?variant}}.spec ; then
    if [ "${patch:0:8}" != "patch-3." ] ; then
      echo "ERROR: Patch  $patch  not listed as a source patch in specfile"
      exit 1
    fi
  fi 2>/dev/null
  case "$patch" in
  *.bz2) bunzip2 < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
  *.gz) gunzip < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
  *) $patch_command ${1+"$@"} < "$RPM_SOURCE_DIR/$patch" ;;
  esac
}

# don't apply patch if it's empty
ApplyOptionalPatch()
{
  local patch=$1
  shift
  if [ ! -f $RPM_SOURCE_DIR/$patch ]; then
    exit 1
  fi
  local C=$(wc -l $RPM_SOURCE_DIR/$patch | awk '{print $1}')
  if [ "$C" -gt 9 ]; then
    ApplyPatch $patch ${1+"$@"}
  fi
}

# First we unpack the kernel tarball.
# If this isn't the first make prep, we use links to the existing clean tarball
# which speeds things up quite a bit.

# Update to latest upstream.
%define vanillaversion %{kversion}

# %%{vanillaversion} : the full version name, e.g. 2.6.35-rc6-git3
# %%{kversion}       : the base version, e.g. 2.6.34

# Use kernel-%%{kversion}%%{?dist} as the top-level directory name
# so we can prep different trees within a single git directory.

%setup -q -n kernel-%{kversion}%{?dist} -c
mv linux-%{vanillaversion} vanilla-%{vanillaversion}

%if "%{kversion}" != "%{vanillaversion}"
# Need to apply patches to the base vanilla version.
pushd vanilla-%{vanillaversion} && popd

%endif

# Now build the fedora kernel tree.
if [ -d linux-%{KVERREL} ]; then
  # Just in case we ctrl-c'd a prep already
  rm -rf deleteme.%{_target_cpu}
  # Move away the stale away, and delete in background.
  mv linux-%{KVERREL} deleteme.%{_target_cpu}
  rm -rf deleteme.%{_target_cpu} &
fi

cp -rl vanilla-%{vanillaversion} linux-%{KVERREL}

cd linux-%{KVERREL}
tar xf %{SOURCE1}

# Drop some necessary files from the source dir into the buildroot
cp $RPM_SOURCE_DIR/config-* .
cp %{SOURCE15} .

%ifnarch %nobuildarches
# Dynamically generate kernel .config files from config-* files
make -f %{SOURCE19} VERSION=%{version} config
%endif

# apply the patches we had included in the -patches tarball. We use the
# linux-KVER-patches.list hardcoded apply log filename
patch_list=linux-%{kversion}-patches.list
if [ ! -f ${patch_list} ] ; then
    echo "ERROR: patch file apply log is missing: ${patch_list} not found"
    exit -1
fi
for p in `cat $patch_list` ; do
  ApplyNoCheckPatch ${p}
done

# __APPLYFILE_TEMPLATE__
ApplyPatch 0001-scsi-sd_revalidate_disk-prevent-NULL-ptr-deref.patch
ApplyPatch 0002-not-for-upstream-testmgr-config-changes-to-enable-FI.patch
ApplyPatch 0003-drivers-introduce-AMAZON_DRIVER_UPDATES.patch
ApplyPatch 0004-drivers-amazon-add-network-device-drivers-support.patch
ApplyPatch 0005-drivers-amazon-introduce-AMAZON_ENA_ETHERNET.patch
ApplyPatch 0006-Importing-Amazon-ENA-driver-1.5.0-into-amazon-4.14.y.patch
ApplyPatch 0007-xen-manage-keep-track-of-the-on-going-suspend-mode.patch
ApplyPatch 0008-xen-manage-introduce-helper-function-to-know-the-on-.patch
ApplyPatch 0009-xenbus-add-freeze-thaw-restore-callbacks-support.patch
ApplyPatch 0010-x86-xen-Introduce-new-function-to-map-HYPERVISOR_sha.patch
ApplyPatch 0011-x86-xen-add-system-core-suspend-and-resume-callbacks.patch
ApplyPatch 0012-xen-blkfront-add-callbacks-for-PM-suspend-and-hibern.patch
ApplyPatch 0013-xen-netfront-add-callbacks-for-PM-suspend-and-hibern.patch
ApplyPatch 0014-xen-time-introduce-xen_-save-restore-_steal_clock.patch
ApplyPatch 0015-x86-xen-save-and-restore-steal-clock.patch
ApplyPatch 0016-xen-events-add-xen_shutdown_pirqs-helper-function.patch
ApplyPatch 0017-x86-xen-close-event-channels-for-PIRQs-in-system-cor.patch
ApplyPatch 0018-PM-hibernate-update-the-resume-offset-on-SNAPSHOT_SE.patch
ApplyPatch 0019-Revert-xen-dont-fiddle-with-event-channel-masking-in.patch
ApplyPatch 0020-xen-blkfront-Fixed-blkfront_restore-to-remove-a-call.patch
ApplyPatch 0021-x86-tsc-avoid-system-instability-in-hibernation.patch
ApplyPatch 0022-block-xen-blkfront-consider-new-dom0-features-on-res.patch
ApplyPatch 0023-xen-restore-pirqs-on-resume-from-hibernation.patch
ApplyPatch 0024-xen-Only-restore-the-ACPI-SCI-interrupt-in-xen_resto.patch
ApplyPatch 0025-net-ena-Import-the-ENA-v2-driver-2.0.2g.patch
ApplyPatch 0026-xen-netfront-call-netif_device_attach-on-resume.patch
ApplyPatch 0027-net-ena-replace-dma_zalloc_coherent-with-dma_alloc_c.patch
ApplyPatch 0028-iov_iter-fix-iov_for_each-after-accessor-function-in.patch
ApplyPatch 0029-Import-lustre-client-2.10.5.patch
ApplyPatch 0030-Config-glue-for-lustre-client.patch
ApplyPatch 0031-lustre-change-printf-format-strings-for-64bit-time-i.patch
ApplyPatch 0032-lustre-silence-printk-format-warnings-about-timespec.patch
ApplyPatch 0033-lustre-use-SB_-instead-of-MS_-as-superblock-flags.patch
ApplyPatch 0034-lustre-adapt-to-setup_timer-timer_setup-change.patch
ApplyPatch 0035-lustre-adapt-to-struct-posix_acl-atomic_t-refcount_t.patch
ApplyPatch 0036-lustre-adapt-to-sys_close-ksys_close-change.patch
ApplyPatch 0037-lustre-adapt-to-upstream-struct-address_space-change.patch
ApplyPatch 0038-lustre-adapt-to-upstream-atomic_open-interface-chang.patch
ApplyPatch 0039-lustre-adapt-to-changed-kernel-socket-interfaces.patch
ApplyPatch 0040-lustre-reintroduce-ATTR_ATTR_FLAG.patch
ApplyPatch 0041-lustre-adapt-for-totalram_pages-change.patch
ApplyPatch 0042-lustre-config.h-file-for-Linux-5.0.patch
ApplyPatch 0043-lustre-account-for-the-SO_-TIMEO-SO_-TIME_OLD-rename.patch
ApplyPatch 0044-lustre-adapt-for-fault-page_mkwrite-return-type-chan.patch
ApplyPatch 0045-lustre-add-HAVE_VM_FAULT_T-to-config.h.patch
ApplyPatch 0046-lustre-adapt-to-get_ds-removal.patch
ApplyPatch 0047-lustre-fix-ACL-handling.patch
ApplyPatch 0048-lustre-adapt-to-stacktrace-infrastructure-change.patch
ApplyPatch 0049-lustre-fix-fall-through-warnings.patch
ApplyPatch 0050-lustre-fix-file_lock-usage.patch
ApplyPatch 0051-lustre-fix-lnet-makefile.patch
ApplyPatch 0052-lustre-adapt-to-changed-padata-interfaces.patch
ApplyPatch 0053-iommu-use-config-option-to-specify-if-iommu-mode-sho.patch
ApplyPatch 0054-xen-Restore-xen-pirqs-on-resume-from-hibernation.patch
ApplyPatch 0055-block-xen-blkfront-bump-the-maximum-number-of-indire.patch
ApplyPatch 0056-lustre-hold-lock-while-walking-changelog-dev-list.patch
ApplyPatch 0057-ena-update-to-2.2.3.patch
ApplyPatch 0058-lustre-adapt-to-changed-padata-interfaces-in-5.4-sta.patch
ApplyPatch 0059-lustre-llite-ll_fault-fixes.patch
ApplyPatch 0060-ena-update-to-2.2.6.patch
ApplyPatch 0061-ena-Update-to-2.2.10.patch
ApplyPatch 0062-drivers-amazon-config-don-t-use-help-anymore.patch
ApplyPatch 0063-lustre-restore-mgc-binding-for-sptlrpc.patch
ApplyPatch 0064-Update-lustre-to-tag-v2.10.8-5-in-AmazonFSxLustreCli.patch
ApplyPatch 0065-lustre-remove-CRYPTO_TFM_RES_BAD_KEY_LEN.patch
ApplyPatch 0066-lustre-add-time_t-define.patch
ApplyPatch 0067-lustre-stop-using-struct-timeval.patch
ApplyPatch 0068-lustre-handle-removal-of-NR_UNSTABLE_NFS.patch
ApplyPatch 0069-lustre-Fix-compilation-with-MOFED-5.1.patch
ApplyPatch 0070-lustre-seperate-debugfs-and-procfs-handling.patch
ApplyPatch 0071-lustre-fix-fiemap.h-include.patch
ApplyPatch 0072-lustre-fixup-for-kernel_-get-set-sockopt-removal.patch
ApplyPatch 0073-lustre-mmap_sem-mmap_lock.patch
ApplyPatch 0074-lustre-remove-the-pgprot-argument-to-__vmalloc.patch
ApplyPatch 0075-lustre-use-uaccess_kernel-instead-of-segment_eq.patch
ApplyPatch 0076-Disable-HAVE_LINUX_SELINUX_IS_ENABLED-as-it-s-gone-f.patch
ApplyPatch 0077-lustre-disable-compiling-sec_ctx.c.patch
ApplyPatch 0078-lustre-remove-get-set_fs-from-ptask-code.patch
ApplyPatch 0079-lustre-get-network-interface-configs-directly.patch
ApplyPatch 0080-lustre-lprocfs-work-around-set_fs-removal.patch
ApplyPatch 0081-ena-Update-to-2.4.0.patch
ApplyPatch 0082-lustre-don-t-try-fault-fast-path-if-we-can-t-retry.patch
ApplyPatch 0083-NFS-Ensure-contents-of-struct-nfs_open_dir_context-a.patch
ApplyPatch 0084-NFS-Clean-up-readdir-struct-nfs_cache_array.patch
ApplyPatch 0085-NFS-Clean-up-nfs_readdir_page_filler.patch
ApplyPatch 0086-NFS-Clean-up-directory-array-handling.patch
ApplyPatch 0087-NFS-Don-t-discard-readdir-results.patch
ApplyPatch 0088-NFS-Remove-unnecessary-kmap-in-nfs_readdir_xdr_to_ar.patch
ApplyPatch 0089-NFS-Replace-kmap-with-kmap_atomic-in-nfs_readdir_sea.patch
ApplyPatch 0090-NFS-Simplify-struct-nfs_cache_array_entry.patch
ApplyPatch 0091-NFS-Support-larger-readdir-buffers.patch
ApplyPatch 0092-NFS-More-readdir-cleanups.patch
ApplyPatch 0093-NFS-nfs_do_filldir-does-not-return-a-value.patch
ApplyPatch 0094-NFS-Reduce-readdir-stack-usage.patch
ApplyPatch 0095-NFS-Cleanup-to-remove-nfs_readdir_descriptor_t-typed.patch
ApplyPatch 0096-NFS-Allow-the-NFS-generic-code-to-pass-in-a-verifier.patch
ApplyPatch 0097-NFS-Handle-NFS4ERR_NOT_SAME-and-NFSERR_BADCOOKIE-fro.patch
ApplyPatch 0098-NFS-Improve-handling-of-directory-verifiers.patch
ApplyPatch 0099-NFS-Optimisations-for-monotonically-increasing-readd.patch
ApplyPatch 0100-NFS-Reduce-number-of-RPC-calls-when-doing-uncached-r.patch
ApplyPatch 0101-NFS-Do-uncached-readdir-when-we-re-seeking-a-cookie-.patch
ApplyPatch 0102-ena-update-to-2.4.1.patch
ApplyPatch 0103-Add-Amazon-EFA-driver-version-1.11.1.patch
ApplyPatch 0104-mm-Introduce-Data-Access-MONitor-DAMON.patch
ApplyPatch 0105-mm-damon-core-Implement-region-based-sampling.patch
ApplyPatch 0106-mm-damon-Adaptively-adjust-regions.patch
ApplyPatch 0107-mm-idle_page_tracking-Make-PG_idle-reusable.patch
ApplyPatch 0108-mm-damon-Implement-primitives-for-the-virtual-memory.patch
ApplyPatch 0109-mm-damon-Add-a-tracepoint.patch
ApplyPatch 0110-mm-damon-Implement-a-debugfs-based-user-space-interf.patch
ApplyPatch 0111-mm-damon-dbgfs-Implement-recording-feature.patch
ApplyPatch 0112-mm-damon-dbgfs-Export-kdamond-pid-to-the-user-space.patch
ApplyPatch 0113-mm-damon-dbgfs-Support-multiple-contexts.patch
ApplyPatch 0114-mm-damon-core-Account-age-of-target-regions.patch
ApplyPatch 0115-mm-damon-core-Implement-DAMON-based-Operation-Scheme.patch
ApplyPatch 0116-mm-damon-vaddr-Support-DAMON-based-Operation-Schemes.patch
ApplyPatch 0117-mm-damon-dbgfs-Support-DAMON-based-Operation-Schemes.patch
ApplyPatch 0118-mm-damon-schemes-Implement-statistics-feature.patch
ApplyPatch 0119-damon-dbgfs-Allow-users-to-set-initial-monitoring-ta.patch
ApplyPatch 0120-mm-damon-vaddr-Separate-commonly-usable-functions.patch
ApplyPatch 0121-mm-damon-Implement-primitives-for-physical-address-s.patch
ApplyPatch 0122-damon-dbgfs-Support-physical-memory-monitoring.patch
ApplyPatch 0123-Revert-vmlinux.lds.h-Add-PGO-and-AutoFDO-input-secti.patch
ApplyPatch 0124-arm64-Export-acpi_psci_use_hvc-symbol.patch
ApplyPatch 0125-hwrng-Add-Gravition-RNG-driver.patch
ApplyPatch 0126-lustre-update-to-AmazonFSxLustreClient-v2.10.8-7.patch
ApplyPatch 0127-x86-Disable-KASLR-when-Xen-is-detected.patch
ApplyPatch 0128-ena-Update-to-2.5.0.patch
ApplyPatch 0129-Revert-crypto-jitterentropy-change-back-to-module_in.patch
ApplyPatch 0130-igb_uio-add.patch
ApplyPatch 0131-nfs-Subsequent-READDIR-calls-should-carry-non-zero-c.patch
ApplyPatch 0132-NFS-Fix-handling-of-cookie-verifier-in-uncached_read.patch
ApplyPatch 0133-NFS-Only-change-the-cookie-verifier-if-the-directory.patch
ApplyPatch 0134-Sysfs-memory-probe-interface.patch
ApplyPatch 0135-arm64-mm-Enable-sysfs-based-memory-hot-remove-probe.patch
ApplyPatch 0136-lustre-update-to-AmazonFSxLustreClient-v2.10.8-8.patch
ApplyPatch 0137-efi-libstub-arm64-Warn-when-efi_random_alloc-fails.patch
ApplyPatch 0138-mm-page_alloc-Print-node-fallback-order.patch
ApplyPatch 0139-mm-page_alloc-Use-accumulated-load-when-building-nod.patch
ApplyPatch 0140-arm-arm64-Probe-for-the-presence-of-KVM-hypervisor.patch
ApplyPatch 0141-KVM-arm64-Advertise-KVM-UID-to-guests-via-SMCCC.patch
ApplyPatch 0142-ptp-Reorganize-ptp_kvm.c-to-make-it-arch-independent.patch
ApplyPatch 0143-time-Add-mechanism-to-recognize-clocksource-in-time_.patch
ApplyPatch 0144-clocksource-Add-clocksource-id-for-arm-arch-counter.patch
ApplyPatch 0145-KVM-arm64-Add-support-for-the-KVM-PTP-service.patch
ApplyPatch 0146-ptp-arm-arm64-Enable-ptp_kvm-for-arm-arm64.patch
ApplyPatch 0147-ptp-Don-t-print-an-error-if-ptp_kvm-is-not-supported.patch
ApplyPatch 0148-tools-headers-UAPI-Sync-linux-kvm.h-with-the-kernel-.patch
ApplyPatch 0149-drivers-misc-sysgenid-add-system-generation-id-drive.patch
ApplyPatch 0150-drivers-virt-vmgenid-add-vm-generation-id-driver.patch
ApplyPatch 0151-mm-memcg-throttle-the-memory-reclaim-given-dirty-wri.patch
ApplyPatch 0152-perf-sched-Cast-PTHREAD_STACK_MIN-to-int-as-it-may-t.patch
ApplyPatch 0153-sysctl-add-proc_dou8vec_minmax.patch
ApplyPatch 0154-ipv4-shrink-netns_ipv4-with-sysctl-conversions.patch
ApplyPatch 0155-ipv4-convert-ip_forward_update_priority-sysctl-to-u8.patch
ApplyPatch 0156-inet-convert-tcp_early_demux-and-udp_early_demux-to-.patch
ApplyPatch 0157-tcp-convert-elligible-sysctls-to-u8.patch
ApplyPatch 0158-tcp-fix-tcp_min_tso_segs-sysctl.patch
ApplyPatch 0159-bpf-Expose-bpf_get_socket_cookie-to-tracing-programs.patch
ApplyPatch 0160-bpf-Add-ASSERT_NEQ-ASSERT_FALSE-and-ASSERT_GE-for-se.patch
ApplyPatch 0161-net-Introduce-net.ipv4.tcp_migrate_req.patch
ApplyPatch 0162-tcp-Add-num_closed_socks-to-struct-sock_reuseport.patch
ApplyPatch 0163-tcp-Keep-TCP_CLOSE-sockets-in-the-reuseport-group.patch
ApplyPatch 0164-tcp-Add-reuseport_migrate_sock-to-select-a-new-liste.patch
ApplyPatch 0165-tcp-Migrate-TCP_ESTABLISHED-TCP_SYN_RECV-sockets-in-.patch
ApplyPatch 0166-tcp-Migrate-TCP_NEW_SYN_RECV-requests-at-retransmitt.patch
ApplyPatch 0167-tcp-Migrate-TCP_NEW_SYN_RECV-requests-at-receiving-t.patch
ApplyPatch 0168-bpf-Support-BPF_FUNC_get_socket_cookie-for-BPF_PROG_.patch
ApplyPatch 0169-bpf-Support-socket-migration-by-eBPF.patch
ApplyPatch 0170-libbpf-Set-expected_attach_type-for-BPF_PROG_TYPE_SK.patch
ApplyPatch 0171-bpf-Test-BPF_SK_REUSEPORT_SELECT_OR_MIGRATE.patch
ApplyPatch 0172-tcp-Add-stats-for-socket-migration.patch
ApplyPatch 0173-math64.h-Add-mul_s64_u64_shr.patch
ApplyPatch 0174-KVM-X86-Store-L1-s-TSC-scaling-ratio-in-struct-kvm_v.patch
ApplyPatch 0175-KVM-X86-Rename-kvm_compute_tsc_offset-to-kvm_compute.patch
ApplyPatch 0176-KVM-X86-Add-a-ratio-parameter-to-kvm_scale_tsc.patch
ApplyPatch 0177-KVM-nVMX-Add-a-TSC-multiplier-field-in-VMCS12.patch
ApplyPatch 0178-KVM-X86-Add-functions-for-retrieving-L2-TSC-fields-f.patch
ApplyPatch 0179-KVM-X86-Add-functions-that-calculate-the-nested-TSC-.patch
ApplyPatch 0180-KVM-X86-Move-write_l1_tsc_offset-logic-to-common-cod.patch
ApplyPatch 0181-KVM-X86-Add-vendor-callbacks-for-writing-the-TSC-mul.patch
ApplyPatch 0182-KVM-nVMX-Enable-nested-TSC-scaling.patch
ApplyPatch 0183-KVM-selftests-x86-Add-vmx_nested_tsc_scaling_test.patch
ApplyPatch 0184-KVM-nVMX-Dynamically-compute-max-VMCS-index-for-vmcs.patch
ApplyPatch 0185-Introduce-page-touching-DMA-ops-binding.patch
ApplyPatch 0186-nitro_enclaves-Set-Bus-Master-for-the-NE-PCI-device.patch
ApplyPatch 0187-nitro_enclaves-Enable-Arm64-support.patch
ApplyPatch 0188-nitro_enclaves-Update-documentation-for-Arm64-suppor.patch
ApplyPatch 0189-nitro_enclaves-Add-fix-for-the-kernel-doc-report.patch
ApplyPatch 0190-nitro_enclaves-Update-copyright-statement-to-include.patch
ApplyPatch 0191-nitro_enclaves-Add-fixes-for-checkpatch-match-open-p.patch
ApplyPatch 0192-nitro_enclaves-Add-fixes-for-checkpatch-spell-check-.patch
ApplyPatch 0193-nitro_enclaves-Add-fixes-for-checkpatch-blank-line-r.patch
ApplyPatch 0194-Revert-damon-dbgfs-Support-physical-memory-monitorin.patch
ApplyPatch 0195-Revert-mm-damon-Implement-primitives-for-physical-ad.patch
ApplyPatch 0196-Revert-mm-damon-vaddr-Separate-commonly-usable-funct.patch
ApplyPatch 0197-Revert-damon-dbgfs-Allow-users-to-set-initial-monito.patch
ApplyPatch 0198-Revert-mm-damon-schemes-Implement-statistics-feature.patch
ApplyPatch 0199-Revert-mm-damon-dbgfs-Support-DAMON-based-Operation-.patch
ApplyPatch 0200-Revert-mm-damon-vaddr-Support-DAMON-based-Operation-.patch
ApplyPatch 0201-Revert-mm-damon-core-Implement-DAMON-based-Operation.patch
ApplyPatch 0202-Revert-mm-damon-core-Account-age-of-target-regions.patch
ApplyPatch 0203-Revert-mm-damon-dbgfs-Support-multiple-contexts.patch
ApplyPatch 0204-Revert-mm-damon-dbgfs-Export-kdamond-pid-to-the-user.patch
ApplyPatch 0205-Revert-mm-damon-dbgfs-Implement-recording-feature.patch
ApplyPatch 0206-Revert-mm-damon-Implement-a-debugfs-based-user-space.patch
ApplyPatch 0207-Revert-mm-damon-Add-a-tracepoint.patch
ApplyPatch 0208-Revert-mm-damon-Implement-primitives-for-the-virtual.patch
ApplyPatch 0209-Revert-mm-idle_page_tracking-Make-PG_idle-reusable.patch
ApplyPatch 0210-Revert-mm-damon-Adaptively-adjust-regions.patch
ApplyPatch 0211-Revert-mm-damon-core-Implement-region-based-sampling.patch
ApplyPatch 0212-Revert-mm-Introduce-Data-Access-MONitor-DAMON.patch
ApplyPatch 0213-mm-introduce-Data-Access-MONitor-DAMON.patch
ApplyPatch 0214-mm-damon-core-implement-region-based-sampling.patch
ApplyPatch 0215-mm-damon-adaptively-adjust-regions.patch
ApplyPatch 0216-mm-idle_page_tracking-make-PG_idle-reusable.patch
ApplyPatch 0217-mm-damon-implement-primitives-for-the-virtual-memory.patch
ApplyPatch 0218-mm-damon-add-a-tracepoint.patch
ApplyPatch 0219-mm-damon-implement-a-debugfs-based-user-space-interf.patch
ApplyPatch 0220-mm-damon-dbgfs-export-kdamond-pid-to-the-user-space.patch
ApplyPatch 0221-mm-damon-dbgfs-support-multiple-contexts.patch
ApplyPatch 0222-mm-damon-grammar-s-works-work.patch
ApplyPatch 0223-include-linux-damon.h-fix-kernel-doc-comments-for-da.patch
ApplyPatch 0224-mm-damon-core-print-kdamond-start-log-in-debug-mode-.patch
ApplyPatch 0225-mm-damon-remove-unnecessary-do_exit-from-kdamond.patch
ApplyPatch 0226-mm-damon-needn-t-hold-kdamond_lock-to-print-pid-of-k.patch
ApplyPatch 0227-mm-damon-core-nullify-pointer-ctx-kdamond-with-a-NUL.patch
ApplyPatch 0228-mm-damon-core-account-age-of-target-regions.patch
ApplyPatch 0229-mm-damon-core-implement-DAMON-based-Operation-Scheme.patch
ApplyPatch 0230-mm-damon-vaddr-support-DAMON-based-Operation-Schemes.patch
ApplyPatch 0231-mm-damon-dbgfs-support-DAMON-based-Operation-Schemes.patch
ApplyPatch 0232-mm-damon-schemes-implement-statistics-feature.patch
ApplyPatch 0233-mm-damon-dbgfs-Implement-recording-feature.patch
ApplyPatch 0234-damon-dbgfs-Allow-users-to-set-initial-monitoring-ta.patch
ApplyPatch 0235-mm-damon-vaddr-Separate-commonly-usable-functions.patch
ApplyPatch 0236-mm-damon-Implement-primitives-for-physical-address-s.patch
ApplyPatch 0237-damon-dbgfs-Support-physical-memory-monitoring.patch
ApplyPatch 0238-mm-damon-paddr-Separate-commonly-usable-functions.patch
ApplyPatch 0239-mm-damon-Introduce-arbitrary-target-type.patch
ApplyPatch 0240-mm-damon-Implement-primitives-for-page-granularity-i.patch
ApplyPatch 0241-mm-damon-paddr-Support-the-pageout-scheme.patch
ApplyPatch 0242-mm-damon-damos-Make-schemes-aggressiveness-controlla.patch
ApplyPatch 0243-damon-core-schemes-Skip-already-charged-targets-and-.patch
ApplyPatch 0244-mm-damon-schemes-Implement-time-quota.patch
ApplyPatch 0245-mm-damon-dbgfs-Support-schemes-time-IO-quotas.patch
ApplyPatch 0246-mm-damon-schemes-Prioritize-regions-within-the-quota.patch
ApplyPatch 0247-mm-damon-vaddr-paddr-Support-pageout-prioritization.patch
ApplyPatch 0248-mm-damon-dbgfs-Support-prioritization-weights.patch
ApplyPatch 0249-mm-damon-schemes-Activate-schemes-based-on-a-waterma.patch
ApplyPatch 0250-mm-damon-dbgfs-Support-watermarks.patch
ApplyPatch 0251-mm-damon-Introduce-DAMON-based-reclamation.patch
ApplyPatch 0252-arm64-lto-Strengthen-READ_ONCE-to-acquire-when-CONFI.patch
ApplyPatch 0253-arm64-vmlinux.lds.S-Drop-redundant-.init.rodata.patch
ApplyPatch 0254-arm64-disable-recordmcount-with-DYNAMIC_FTRACE_WITH_.patch
ApplyPatch 0255-arm64-rename-S_FRAME_SIZE-to-PT_REGS_SIZE.patch
ApplyPatch 0256-arm64-remove-EL0-exception-frame-record.patch
ApplyPatch 0257-arm64-stacktrace-Report-when-we-reach-the-end-of-the.patch
ApplyPatch 0258-arm64-stacktrace-restore-terminal-records.patch
ApplyPatch 0259-arm64-Implement-stack-trace-termination-record.patch
ApplyPatch 0260-arm64-Introduce-stack-trace-reliability-checks-in-th.patch
ApplyPatch 0261-arm64-Create-a-list-of-SYM_CODE-functions-check-retu.patch
ApplyPatch 0262-arm64-Implement-arch_stack_walk_reliable.patch
ApplyPatch 0263-rbtree-Add-generic-add-and-find-helpers.patch
ApplyPatch 0264-objtool-Fully-validate-the-stack-frame.patch
ApplyPatch 0265-objtool-Support-addition-to-set-CFA-base.patch
ApplyPatch 0266-objtool-Make-SP-memory-operation-match-PUSH-POP-sema.patch
ApplyPatch 0267-objtool-Fix-reloc-generation-on-big-endian-cross-com.patch
ApplyPatch 0268-objtool-Fix-x86-orc-generation-on-big-endian-cross-c.patch
ApplyPatch 0269-objtool-Rework-header-include-paths.patch
ApplyPatch 0270-objtool-Add-asm-version-of-STACK_FRAME_NON_STANDARD.patch
ApplyPatch 0271-x86-ftrace-Support-objtool-vmlinux.o-validation-in-f.patch
ApplyPatch 0272-x86-acpi-Support-objtool-validation-in-wakeup_64.S.patch
ApplyPatch 0273-x86-power-Move-restore_registers-to-top-of-the-file.patch
ApplyPatch 0274-x86-power-Support-objtool-validation-in-hibernate_as.patch
ApplyPatch 0275-objtool-x86-Additionally-decode-mov-rsp-reg.patch
ApplyPatch 0276-objtool-Support-stack-swizzle.patch
ApplyPatch 0277-objtool-Fix-stack-swizzle-for-FRAME_POINTER-y.patch
ApplyPatch 0278-objtool-Add-a-pass-for-generating-__mcount_loc.patch
ApplyPatch 0279-objtool-Don-t-autodetect-vmlinux.o.patch
ApplyPatch 0280-objtool-Split-noinstr-validation-from-vmlinux.patch
ApplyPatch 0281-objtool-x86-Fix-uaccess-PUSHF-POPF-validation.patch
ApplyPatch 0282-arm64-uaccess-move-uao_-alternatives-to-asm-uaccess..patch
ApplyPatch 0283-arm64-alternatives-Split-up-alternative.h.patch
ApplyPatch 0284-objtool-Allow-UNWIND_HINT-to-suppress-dodgy-stack-mo.patch
ApplyPatch 0285-objtool-x86-Renumber-CFI_reg.patch
ApplyPatch 0286-objtool-x86-Rewrite-LEA-decode.patch
ApplyPatch 0287-objtool-x86-Simplify-register-decode.patch
ApplyPatch 0288-objtool-x86-Support-riz-encodings.patch
ApplyPatch 0289-objtool-x86-Rewrite-ADD-SUB-AND.patch
ApplyPatch 0290-objtool-x86-More-ModRM-sugar.patch
ApplyPatch 0291-objtool-Add-backup.patch
ApplyPatch 0292-objtool-Collate-parse_options-users.patch
ApplyPatch 0293-objtool-Parse-options-from-OBJTOOL_ARGS.patch
ApplyPatch 0294-arm64-Move-patching-utilities-out-of-instruction-enc.patch
ApplyPatch 0295-arm64-insn-Reduce-header-dependencies-of-instruction.patch
ApplyPatch 0296-arm64-Move-instruction-encoder-decoder-under-lib.patch
ApplyPatch 0297-arm64-insn-Add-SVE-instruction-class.patch
ApplyPatch 0298-arm64-insn-Add-barrier-encodings.patch
ApplyPatch 0299-arm64-insn-Add-some-opcodes-to-instruction-decoder.patch
ApplyPatch 0300-arm64-insn-Add-load-store-decoding-helpers.patch
ApplyPatch 0301-tools-Add-some-generic-functions-and-headers.patch
ApplyPatch 0302-tools-arm64-Make-aarch64-instruction-decoder-availab.patch
ApplyPatch 0303-tools-bug-Remove-duplicate-definition.patch
ApplyPatch 0304-objtool-arm64-Add-base-definition-for-arm64-backend.patch
ApplyPatch 0305-objtool-arm64-Decode-add-sub-instructions.patch
ApplyPatch 0306-objtool-arm64-Decode-jump-and-call-related-instructi.patch
ApplyPatch 0307-objtool-arm64-Decode-other-system-instructions.patch
ApplyPatch 0308-objtool-arm64-Decode-load-store-instructions.patch
ApplyPatch 0309-objtool-arm64-Decode-LDR-instructions.patch
ApplyPatch 0310-objtool-arm64-Accept-padding-in-code-sections.patch
ApplyPatch 0311-objtool-arm64-Handle-supported-relocations-in-altern.patch
ApplyPatch 0312-objtool-arm64-Ignore-replacement-section-for-alterna.patch
ApplyPatch 0313-objtool-arm64-Enable-stack-validation-for-arm64.patch
ApplyPatch 0314-arm64-bug-Add-reachable-annotation-to-warning-macros.patch
ApplyPatch 0315-arm64-kgdb-Mark-code-following-kgdb-brk-as-reachable.patch
ApplyPatch 0316-arm64-Add-intra-function-call-annotations.patch
ApplyPatch 0317-arm64-Skip-validation-of-qcom_link_stack_sanitizatio.patch
ApplyPatch 0318-arm64-kernel-Add-exception-on-kuser32-to-prevent-sta.patch
ApplyPatch 0319-arm64-Mark-sigreturn32.o-as-containing-non-standard-.patch
ApplyPatch 0320-arm64-entry-Compile-out-unnecessary-symbols.patch
ApplyPatch 0321-arm64-crypto-Remove-unnecessary-stackframe.patch
ApplyPatch 0322-arm64-sleep-Properly-set-frame-pointer-before-call.patch
ApplyPatch 0323-arm64-Move-constant-to-rodata.patch
ApplyPatch 0324-arm64-entry-Mark-tramp_exit-as-local-symbols.patch
ApplyPatch 0325-arm64-head.S-rename-el2_setup-init_kernel_el.patch
ApplyPatch 0326-arm64-Change-symbol-annotations.patch
ApplyPatch 0327-objtool-check-Support-data-in-text-section.patch
ApplyPatch 0328-arm64-head-avoid-symbol-names-pointing-into-first-64.patch
ApplyPatch 0329-arm64-head-tidy-up-the-Image-header-definition.patch
ApplyPatch 0330-arm64-efi-header-Mark-efi-header-as-data.patch
ApplyPatch 0331-arm64-head-Mark-constants-as-data.patch
ApplyPatch 0332-arm64-proc-Mark-constant-as-data.patch
ApplyPatch 0333-arm64-crypto-Mark-data-in-code-sections.patch
ApplyPatch 0334-objtool-arm64-Add-unwind_hint-support.patch
ApplyPatch 0335-arm64-Annotate-ASM-symbols-with-unknown-stack-state.patch
ApplyPatch 0336-arm64-entry-Annotate-valid-stack-in-kernel-entry.patch
ApplyPatch 0337-arm64-entry-Add-annotation-when-switching-to-from-th.patch
ApplyPatch 0338-arm64-entry-Annotate-code-switching-to-tasks.patch
ApplyPatch 0339-arm64-kvm-Annotate-stack-state-for-guest-enter-exit-.patch
ApplyPatch 0340-arm64-implement-live-patching.patch
ApplyPatch 0341-sched-Simplify-wake_up_-idle.patch
ApplyPatch 0342-sched-livepatch-Use-wake_up_if_idle.patch
ApplyPatch 0343-ARM64-kvm-vgic-v3-sr-Bug-when-trying-to-read-invalid.patch
ApplyPatch 0344-efa-update-to-1.14.1.patch
ApplyPatch 0345-linux-kvm.h-Fix-KVM_CAP_PTP_KVM-numbering-to-match-u.patch
ApplyPatch 0346-arm64-module-Use-aarch64_insn_write-when-updating-re.patch
ApplyPatch 0347-ipc-replace-costly-bailout-check-in-sysvipc_find_ipc.patch
ApplyPatch 0348-nvme-add-48-bit-DMA-address-quirk-for-Amazon-NVMe-co.patch
ApplyPatch 0349-Revert-PCI-MSI-Enforce-that-MSI-X-table-entry-is-mas.patch
ApplyPatch 0350-Revert-mm-damon-Introduce-DAMON-based-reclamation.patch
ApplyPatch 0351-Revert-mm-damon-dbgfs-Support-watermarks.patch
ApplyPatch 0352-Revert-mm-damon-schemes-Activate-schemes-based-on-a-.patch
ApplyPatch 0353-Revert-mm-damon-dbgfs-Support-prioritization-weights.patch
ApplyPatch 0354-Revert-mm-damon-vaddr-paddr-Support-pageout-prioriti.patch
ApplyPatch 0355-Revert-mm-damon-schemes-Prioritize-regions-within-th.patch
ApplyPatch 0356-Revert-mm-damon-dbgfs-Support-schemes-time-IO-quotas.patch
ApplyPatch 0357-Revert-mm-damon-schemes-Implement-time-quota.patch
ApplyPatch 0358-Revert-damon-core-schemes-Skip-already-charged-targe.patch
ApplyPatch 0359-Revert-mm-damon-damos-Make-schemes-aggressiveness-co.patch
ApplyPatch 0360-Revert-mm-damon-paddr-Support-the-pageout-scheme.patch
ApplyPatch 0361-Revert-mm-damon-Implement-primitives-for-page-granul.patch
ApplyPatch 0362-Revert-mm-damon-Introduce-arbitrary-target-type.patch
ApplyPatch 0363-Revert-mm-damon-paddr-Separate-commonly-usable-funct.patch
ApplyPatch 0364-Revert-damon-dbgfs-Support-physical-memory-monitorin.patch
ApplyPatch 0365-Revert-mm-damon-Implement-primitives-for-physical-ad.patch
ApplyPatch 0366-Revert-mm-damon-vaddr-Separate-commonly-usable-funct.patch
ApplyPatch 0367-Revert-damon-dbgfs-Allow-users-to-set-initial-monito.patch
ApplyPatch 0368-Revert-mm-damon-dbgfs-Implement-recording-feature.patch
ApplyPatch 0369-Revert-mm-damon-schemes-implement-statistics-feature.patch
ApplyPatch 0370-Revert-mm-damon-dbgfs-support-DAMON-based-Operation-.patch
ApplyPatch 0371-Revert-mm-damon-vaddr-support-DAMON-based-Operation-.patch
ApplyPatch 0372-Revert-mm-damon-core-implement-DAMON-based-Operation.patch
ApplyPatch 0373-Revert-mm-damon-core-account-age-of-target-regions.patch
ApplyPatch 0374-Revert-mm-damon-core-nullify-pointer-ctx-kdamond-wit.patch
ApplyPatch 0375-Revert-mm-damon-needn-t-hold-kdamond_lock-to-print-p.patch
ApplyPatch 0376-Revert-mm-damon-remove-unnecessary-do_exit-from-kdam.patch
ApplyPatch 0377-Revert-mm-damon-core-print-kdamond-start-log-in-debu.patch
ApplyPatch 0378-Revert-include-linux-damon.h-fix-kernel-doc-comments.patch
ApplyPatch 0379-Revert-mm-damon-grammar-s-works-work.patch
ApplyPatch 0380-Documentation-add-documents-for-DAMON.patch
ApplyPatch 0381-mm-damon-add-kunit-tests.patch
ApplyPatch 0382-mm-damon-add-user-space-selftests.patch
ApplyPatch 0383-MAINTAINERS-update-for-DAMON.patch
ApplyPatch 0384-mm-damon-don-t-use-strnlen-with-known-bogus-source-l.patch
ApplyPatch 0385-mm-damon-core-test-fix-wrong-expectations-for-damon_.patch
ApplyPatch 0386-mm-damon-grammar-s-works-work.patch
ApplyPatch 0387-include-linux-damon.h-fix-kernel-doc-comments-for-da.patch
ApplyPatch 0388-mm-damon-core-print-kdamond-start-log-in-debug-mode-.patch
ApplyPatch 0389-mm-damon-remove-unnecessary-do_exit-from-kdamond.patch
ApplyPatch 0390-mm-damon-needn-t-hold-kdamond_lock-to-print-pid-of-k.patch
ApplyPatch 0391-mm-damon-core-nullify-pointer-ctx-kdamond-with-a-NUL.patch
ApplyPatch 0392-mm-damon-core-account-age-of-target-regions.patch
ApplyPatch 0393-mm-damon-core-implement-DAMON-based-Operation-Scheme.patch
ApplyPatch 0394-mm-damon-vaddr-support-DAMON-based-Operation-Schemes.patch
ApplyPatch 0395-mm-damon-dbgfs-support-DAMON-based-Operation-Schemes.patch
ApplyPatch 0396-mm-damon-schemes-implement-statistics-feature.patch
ApplyPatch 0397-selftests-damon-add-schemes-debugfs-tests.patch
ApplyPatch 0398-Docs-admin-guide-mm-damon-document-DAMON-based-Opera.patch
ApplyPatch 0399-mm-damon-dbgfs-allow-users-to-set-initial-monitoring.patch
ApplyPatch 0400-mm-damon-dbgfs-test-add-a-unit-test-case-for-init_re.patch
ApplyPatch 0401-Docs-admin-guide-mm-damon-document-init_regions-feat.patch
ApplyPatch 0402-mm-damon-vaddr-separate-commonly-usable-functions.patch
ApplyPatch 0403-mm-damon-implement-primitives-for-physical-address-s.patch
ApplyPatch 0404-mm-damon-dbgfs-support-physical-memory-monitoring.patch
ApplyPatch 0405-Docs-DAMON-document-physical-memory-monitoring-suppo.patch
ApplyPatch 0406-mm-damon-vaddr-constify-static-mm_walk_ops.patch
ApplyPatch 0407-mm-damon-dbgfs-remove-unnecessary-variables.patch
ApplyPatch 0408-mm-damon-paddr-support-the-pageout-scheme.patch
ApplyPatch 0409-mm-damon-schemes-implement-size-quota-for-schemes-ap.patch
ApplyPatch 0410-mm-damon-schemes-skip-already-charged-targets-and-re.patch
ApplyPatch 0411-mm-damon-schemes-implement-time-quota.patch
ApplyPatch 0412-mm-damon-dbgfs-support-quotas-of-schemes.patch
ApplyPatch 0413-mm-damon-selftests-support-schemes-quotas.patch
ApplyPatch 0414-mm-damon-schemes-prioritize-regions-within-the-quota.patch
ApplyPatch 0415-mm-damon-vaddr-paddr-support-pageout-prioritization.patch
ApplyPatch 0416-mm-damon-dbgfs-support-prioritization-weights.patch
ApplyPatch 0417-tools-selftests-damon-update-for-regions-prioritizat.patch
ApplyPatch 0418-mm-damon-schemes-activate-schemes-based-on-a-waterma.patch
ApplyPatch 0419-mm-damon-dbgfs-support-watermarks.patch
ApplyPatch 0420-selftests-damon-support-watermarks.patch
ApplyPatch 0421-mm-damon-introduce-DAMON-based-Reclamation-DAMON_REC.patch
ApplyPatch 0422-Documentation-admin-guide-mm-damon-add-a-document-fo.patch
ApplyPatch 0423-mm-damon-remove-unnecessary-variable-initialization.patch
ApplyPatch 0424-mm-damon-dbgfs-add-adaptive_targets-list-check-befor.patch
ApplyPatch 0425-Docs-admin-guide-mm-damon-start-fix-wrong-example-co.patch
ApplyPatch 0426-Docs-admin-guide-mm-damon-start-fix-a-wrong-link.patch
ApplyPatch 0427-Docs-admin-guide-mm-damon-start-simplify-the-content.patch
ApplyPatch 0428-mm-damon-simplify-stop-mechanism.patch
ApplyPatch 0429-mm-damon-fix-a-few-spelling-mistakes-in-comments-and.patch
ApplyPatch 0430-mm-damon-remove-return-value-from-before_terminate-c.patch
ApplyPatch 0431-mm-damon-dbgfs-use-__GFP_NOWARN-for-user-specified-s.patch
ApplyPatch 0432-mm-damon-dbgfs-fix-missed-use-of-damon_dbgfs_lock.patch
ApplyPatch 0433-ena-Update-to-2.6.0.patch
ApplyPatch 0434-lustre-update-to-AmazonFSxLustreClient-v2.10.8-10.patch
ApplyPatch 0435-drivers-base-memory-introduce-memory_block_-online-o.patch
ApplyPatch 0436-mm-memory_hotplug-relax-fully-spanned-sections-check.patch
ApplyPatch 0437-mm-memory_hotplug-factor-out-adjusting-present-pages.patch
ApplyPatch 0438-mm-memory_hotplug-allocate-memmap-from-the-added-mem.patch
ApplyPatch 0439-acpi-memhotplug-enable-MHP_MEMMAP_ON_MEMORY-when-sup.patch
ApplyPatch 0440-mm-memory_hotplug-add-kernel-boot-option-to-enable-m.patch
ApplyPatch 0441-x86-Kconfig-introduce-ARCH_MHP_MEMMAP_ON_MEMORY_ENAB.patch
ApplyPatch 0442-arm64-Kconfig-introduce-ARCH_MHP_MEMMAP_ON_MEMORY_EN.patch
ApplyPatch 0443-drivers-base-memory-fix-trying-offlining-memory-bloc.patch
ApplyPatch 0444-drivers-base-memory-use-MHP_MEMMAP_ON_MEMORY-from-th.patch
ApplyPatch 0445-mm-add-offline-page-reporting-interface.patch
ApplyPatch 0446-virtio-add-hack-to-allow-pre-mapped-scatterlists.patch
ApplyPatch 0447-virtio-balloon-optionally-report-offlined-memory-ran.patch
ApplyPatch 0448-ENA-Update-to-v2.6.1.patch
ApplyPatch 0449-lustre-update-to-AmazonFSxLustreClient-v2.12.8-1.patch
ApplyPatch 0450-sched-Improve-wake_up_all_idle_cpus-take-2.patch
ApplyPatch 0451-timers-implement-usleep_idle_range.patch
ApplyPatch 0452-mm-damon-core-fix-fake-load-reports-due-to-uninterru.patch
ApplyPatch 0453-mm-damon-core-use-better-timer-mechanisms-selection-.patch
ApplyPatch 0454-mm-damon-dbgfs-remove-an-unnecessary-error-message.patch
ApplyPatch 0455-mm-damon-core-remove-unnecessary-error-messages.patch
ApplyPatch 0456-mm-damon-vaddr-remove-an-unnecessary-warning-message.patch
ApplyPatch 0457-mm-damon-vaddr-test-split-a-test-function-having-102.patch
ApplyPatch 0458-mm-damon-vaddr-test-remove-unnecessary-variables.patch
ApplyPatch 0459-selftests-damon-skip-test-if-DAMON-is-running.patch
ApplyPatch 0460-selftests-damon-test-DAMON-enabling-with-empty-targe.patch
ApplyPatch 0461-selftests-damon-test-wrong-DAMOS-condition-ranges-in.patch
ApplyPatch 0462-selftests-damon-test-debugfs-file-reads-writes-with-.patch
ApplyPatch 0463-selftests-damon-split-test-cases.patch
ApplyPatch 0464-mm-damon-dbgfs-protect-targets-destructions-with-kda.patch
ApplyPatch 0465-mm-damon-dbgfs-fix-struct-pid-leaks-in-dbgfs_target_.patch
ApplyPatch 0466-sched-numa-Rename-nr_running-and-break-out-the-magic.patch
ApplyPatch 0467-sched-Avoid-unnecessary-calculation-of-load-imbalanc.patch
ApplyPatch 0468-sched-numa-Allow-a-floating-imbalance-between-NUMA-n.patch
ApplyPatch 0469-sched-Limit-the-amount-of-NUMA-imbalance-that-can-ex.patch
ApplyPatch 0470-Add-out-of-tree-smartpqi-driver-Version-2.1.14-030-a.patch
ApplyPatch 0471-bpf-Implement-get_current_task_btf-and-RET_PTR_TO_BT.patch
ApplyPatch 0472-bpf-Introduce-composable-reg-ret-and-arg-types.patch
ApplyPatch 0473-bpf-Replace-ARG_XXX_OR_NULL-with-ARG_XXX-PTR_MAYBE_N.patch
ApplyPatch 0474-bpf-Replace-RET_XXX_OR_NULL-with-RET_XXX-PTR_MAYBE_N.patch
ApplyPatch 0475-bpf-Extract-nullable-reg-type-conversion-into-a-help.patch
ApplyPatch 0476-bpf-Replace-PTR_TO_XXX_OR_NULL-with-PTR_TO_XXX-PTR_M.patch
ApplyPatch 0477-bpf-Introduce-MEM_RDONLY-flag.patch
ApplyPatch 0478-bpf-Convert-PTR_TO_MEM_OR_NULL-to-composable-types.patch
ApplyPatch 0479-bpf-Make-per_cpu_ptr-return-rdonly-PTR_TO_MEM.patch
ApplyPatch 0480-bpf-Add-MEM_RDONLY-for-helper-args-that-are-pointers.patch
ApplyPatch 0481-bpf-selftests-Test-PTR_TO_RDONLY_MEM.patch
ApplyPatch 0482-sock-remove-one-redundant-SKB_FRAG_PAGE_ORDER-macro.patch
ApplyPatch 0483-netfilter-nf_tables-validate-registers-coming-from-u.patch
ApplyPatch 0484-Revert-lustre-update-to-AmazonFSxLustreClient-v2.12..patch
ApplyPatch 0485-svm-fix-backport-of-KVM-X86-Move-write_l1_tsc_offset.patch
ApplyPatch 0486-mm-filemap-c-break-generic_file_buffered_read-up-int.patch
ApplyPatch 0487-mm-filemap.c-generic_file_buffered_read-now-uses-fin.patch
ApplyPatch 0488-ENA-Update-to-v2.7.1.patch
ApplyPatch 0489-lustre-update-to-AmazonFSxLustreClient-v2.10.8-11.patch
ApplyPatch 0490-Correct-read-overflow-in-page-touching-DMA-ops-bindi.patch
ApplyPatch 0491-iov_iter-track-truncated-size.patch
ApplyPatch 0492-bpf-Generalize-check_ctx_reg-for-reuse-with-other-ty.patch
ApplyPatch 0493-bpf-Mark-PTR_TO_FUNC-register-initially-with-zero-of.patch
ApplyPatch 0494-bpf-Generally-fix-helper-register-offset-check.patch
ApplyPatch 0495-bpf-Fix-out-of-bounds-access-for-ringbuf-helpers.patch
ApplyPatch 0496-bpf-Fix-ringbuf-memory-type-confusion-when-passing-t.patch
ApplyPatch 0497-selftests-bpf-Add-verifier-test-for-PTR_TO_MEM-spill.patch
ApplyPatch 0498-bpf-selftests-Add-verifier-test-for-mem_or_null-regi.patch
ApplyPatch 0499-bpf-selftests-Add-various-ringbuf-tests-with-invalid.patch
ApplyPatch 0500-mm-migrate-Don-t-drop-mapping-lock-in-unmap_and_move.patch
ApplyPatch 0501-enable-rfc4106-gcm-aes-for-fips.patch
ApplyPatch 0502-sched-fair-Improve-consistency-of-allowed-NUMA-balan.patch
ApplyPatch 0503-sched-fair-Adjust-the-allowed-NUMA-imbalance-when-SD.patch
ApplyPatch 0504-ENA-Update-to-v2.7.3.patch
ApplyPatch 0505-ENA-Update-to-v2.7.4.patch
ApplyPatch 0506-ext4-reduce-computation-of-overhead-during-resize.patch
ApplyPatch 0507-Mitigate-unbalanced-RETs-on-vmexit-via-serialising-w.patch
ApplyPatch 0508-mm-damon-unified-access_check-function-naming-rules.patch
ApplyPatch 0509-mm-damon-add-age-of-region-tracepoint-support.patch
ApplyPatch 0510-mm-damon-core-use-abs-instead-of-diff_of.patch
ApplyPatch 0511-mm-damon-remove-some-unneeded-function-definitions-i.patch
ApplyPatch 0512-mm-damon-vaddr-remove-swap_ranges-and-replace-it-wit.patch
ApplyPatch 0513-mm-damon-schemes-add-the-validity-judgment-of-thresh.patch
ApplyPatch 0514-mm-damon-move-damon_rand-definition-into-damon.h.patch
ApplyPatch 0515-mm-damon-modify-damon_rand-macro-to-static-inline-fu.patch
ApplyPatch 0516-mm-damon-convert-macro-functions-to-static-inline-fu.patch
ApplyPatch 0517-Docs-admin-guide-mm-damon-usage-update-for-scheme-qu.patch
ApplyPatch 0518-Docs-admin-guide-mm-damon-usage-remove-redundant-inf.patch
ApplyPatch 0519-Docs-admin-guide-mm-damon-usage-mention-tracepoint-a.patch
ApplyPatch 0520-Docs-admin-guide-mm-damon-usage-update-for-kdamond_p.patch
ApplyPatch 0521-mm-damon-remove-a-mistakenly-added-comment-for-a-fut.patch
ApplyPatch 0522-mm-damon-schemes-account-scheme-actions-that-success.patch
ApplyPatch 0523-mm-damon-schemes-account-how-many-times-quota-limit-.patch
ApplyPatch 0524-mm-damon-reclaim-provide-reclamation-statistics.patch
ApplyPatch 0525-Docs-admin-guide-mm-damon-reclaim-document-statistic.patch
ApplyPatch 0526-mm-damon-dbgfs-support-all-DAMOS-stats.patch
ApplyPatch 0527-Docs-admin-guide-mm-damon-usage-update-for-schemes-s.patch
ApplyPatch 0528-mm-damon-add-access-checking-for-hugetlb-pages.patch
ApplyPatch 0529-mm-damon-move-the-implementation-of-damon_insert_reg.patch
ApplyPatch 0530-mm-damon-dbgfs-remove-an-unnecessary-variable.patch
ApplyPatch 0531-mm-damon-vaddr-use-pr_debug-for-damon_va_three_regio.patch
ApplyPatch 0532-mm-damon-vaddr-hide-kernel-pointer-from-damon_va_thr.patch
ApplyPatch 0533-mm-damon-hide-kernel-pointer-from-tracepoint-event.patch
ApplyPatch 0534-mm-damon-minor-cleanup-for-damon_pa_young.patch
ApplyPatch 0535-mm-damon-dbgfs-init_regions-use-target-index-instead.patch
ApplyPatch 0536-Docs-admin-guide-mm-damon-usage-update-for-changed-i.patch
ApplyPatch 0537-mm-damon-core-move-damon_set_targets-into-dbgfs.patch
ApplyPatch 0538-mm-damon-remove-the-target-id-concept.patch
ApplyPatch 0539-mm-damon-remove-redundant-page-validation.patch
ApplyPatch 0540-mm-damon-rename-damon_primitives-to-damon_operations.patch
ApplyPatch 0541-mm-damon-let-monitoring-operations-can-be-registered.patch
ApplyPatch 0542-mm-damon-paddr-vaddr-register-themselves-to-DAMON-in.patch
ApplyPatch 0543-mm-damon-reclaim-use-damon_select_ops-instead-of-dam.patch
ApplyPatch 0544-mm-damon-dbgfs-use-damon_select_ops-instead-of-damon.patch
ApplyPatch 0545-mm-damon-dbgfs-use-operations-id-for-knowing-if-the-.patch
ApplyPatch 0546-mm-damon-dbgfs-test-fix-is_target_id-change.patch
ApplyPatch 0547-mm-damon-paddr-vaddr-remove-damon_-p-v-a_-target_val.patch
ApplyPatch 0548-mm-damon-remove-unnecessary-CONFIG_DAMON-option.patch
ApplyPatch 0549-Docs-damon-update-outdated-term-regions-update-inter.patch
ApplyPatch 0550-mm-damon-core-allow-non-exclusive-DAMON-start-stop.patch
ApplyPatch 0551-mm-damon-core-add-number-of-each-enum-type-values.patch
ApplyPatch 0552-mm-damon-implement-a-minimal-stub-for-sysfs-based-DA.patch
ApplyPatch 0553-mm-damon-sysfs-link-DAMON-for-virtual-address-spaces.patch
ApplyPatch 0554-mm-damon-sysfs-support-the-physical-address-space-mo.patch
ApplyPatch 0555-mm-damon-sysfs-support-DAMON-based-Operation-Schemes.patch
ApplyPatch 0556-mm-damon-sysfs-support-DAMOS-quotas.patch
ApplyPatch 0557-mm-damon-sysfs-support-schemes-prioritization.patch
ApplyPatch 0558-mm-damon-sysfs-support-DAMOS-watermarks.patch
ApplyPatch 0559-mm-damon-sysfs-support-DAMOS-stats.patch
ApplyPatch 0560-selftests-damon-add-a-test-for-DAMON-sysfs-interface.patch
ApplyPatch 0561-Docs-admin-guide-mm-damon-usage-document-DAMON-sysfs.patch
ApplyPatch 0562-mm-damon-sysfs-remove-repeat-container_of-in-damon_s.patch
ApplyPatch 0563-mm-damon-prevent-activated-scheme-from-sleeping-by-d.patch
ApplyPatch 0564-Docs-ABI-testing-add-DAMON-sysfs-interface-ABI-docum.patch
ApplyPatch 0565-damon-vaddr-test-tweak-code-to-make-the-logic-cleare.patch
ApplyPatch 0566-mm-damon-core-test-add-a-kunit-test-case-for-ops-reg.patch
ApplyPatch 0567-mm-damon-remove-unnecessary-type-castings.patch
ApplyPatch 0568-mm-damon-reclaim-fix-the-timer-always-stays-active.patch
ApplyPatch 0569-mm-damon-core-add-a-function-for-damon_operations-re.patch
ApplyPatch 0570-mm-damon-sysfs-add-a-file-for-listing-available-moni.patch
ApplyPatch 0571-selftets-damon-sysfs-test-existence-and-permission-o.patch
ApplyPatch 0572-Docs-ABI-admin-guide-damon-document-avail_operations.patch
ApplyPatch 0573-mm-damon-vaddr-register-a-damon_operations-for-fixed.patch
ApplyPatch 0574-mm-damon-sysfs-support-fixed-virtual-address-ranges-.patch
ApplyPatch 0575-Docs-ABI-admin-guide-damon-update-for-fixed-virtual-.patch
ApplyPatch 0576-mm-damon-core-add-a-new-callback-for-watermarks-chec.patch
ApplyPatch 0577-mm-damon-core-finish-kdamond-as-soon-as-any-callback.patch
ApplyPatch 0578-mm-damon-vaddr-generalize-damon_va_apply_three_regio.patch
ApplyPatch 0579-mm-damon-vaddr-move-damon_set_regions-to-core.patch
ApplyPatch 0580-mm-damon-vaddr-remove-damon_va_apply_three_regions.patch
ApplyPatch 0581-mm-damon-sysfs-prohibit-multiple-physical-address-sp.patch
ApplyPatch 0582-mm-damon-sysfs-move-targets-setup-code-to-a-separate.patch
ApplyPatch 0583-mm-damon-sysfs-reuse-damon_set_regions-for-regions-s.patch
ApplyPatch 0584-mm-damon-sysfs-use-enum-for-state-input-handling.patch
ApplyPatch 0585-mm-damon-sysfs-update-schemes-stat-in-the-kdamond-co.patch
ApplyPatch 0586-mm-damon-sysfs-support-online-inputs-update.patch
ApplyPatch 0587-Docs-ABI-admin-guide-damon-Update-for-state-sysfs-fi.patch
ApplyPatch 0588-mm-damon-reclaim-support-online-inputs-update.patch
ApplyPatch 0589-Docs-admin-guide-mm-damon-reclaim-document-commit_in.patch
ApplyPatch 0590-mm-damon-reclaim-use-resource_size-function-on-resou.patch
ApplyPatch 0591-mm-damon-add-documentation-for-Enum-value.patch
ApplyPatch 0592-mm-damon-use-HPAGE_PMD_SIZE.patch
ApplyPatch 0593-mm-damon-reclaim-schedule-damon_reclaim_timer-only-a.patch
ApplyPatch 0594-mm-damon-use-set_huge_pte_at-to-make-huge-pte-old.patch
ApplyPatch 0595-mm-damon-reclaim-fix-potential-memory-leak-in-damon_.patch
ApplyPatch 0596-mm-damon-dbgfs-avoid-duplicate-context-directory-cre.patch
ApplyPatch 0597-Revert-x86-speculation-Add-RSB-VM-Exit-protections.patch
ApplyPatch 0598-DOWNSTREAM-ONLY-Revert-Makefile-link-with-z-noexecst.patch
ApplyPatch 0599-ENA-Update-to-v2.8.0.patch
ApplyPatch 0600-lustre-update-to-AmazonFSxLustreClient-v2.12.8-fsx4.patch
ApplyPatch 0601-scsi-mpi3mr-Add-mpi30-Rev-R-headers-and-Kconfig.patch
ApplyPatch 0602-scsi-mpi3mr-Base-driver-code.patch
ApplyPatch 0603-scsi-mpi3mr-Create-operational-request-and-reply-que.patch
ApplyPatch 0604-scsi-mpi3mr-Add-support-for-queue-command-processing.patch
ApplyPatch 0605-scsi-mpi3mr-Add-support-for-internal-watchdog-thread.patch
ApplyPatch 0606-scsi-mpi3mr-Add-support-for-device-add-remove-event-.patch
ApplyPatch 0607-scsi-mpi3mr-Add-support-for-PCIe-device-event-handli.patch
ApplyPatch 0608-scsi-mpi3mr-Additional-event-handling.patch
ApplyPatch 0609-scsi-mpi3mr-Add-support-for-recovering-controller.patch
ApplyPatch 0610-scsi-mpi3mr-Add-support-for-timestamp-sync-with-firm.patch
ApplyPatch 0611-scsi-mpi3mr-Print-IOC-info-for-debugging.patch
ApplyPatch 0612-scsi-mpi3mr-Add-bios_param-SCSI-host-template-hook.patch
ApplyPatch 0613-scsi-mpi3mr-Implement-SCSI-error-handler-hooks.patch
ApplyPatch 0614-scsi-mpi3mr-Add-change-queue-depth-support.patch
ApplyPatch 0615-scsi-mpi3mr-Allow-certain-commands-during-pci-remove.patch
ApplyPatch 0616-scsi-mpi3mr-Hardware-workaround-for-UNMAP-commands-t.patch
ApplyPatch 0617-scsi-mpi3mr-Add-support-for-threaded-ISR.patch
ApplyPatch 0618-scsi-mpi3mr-Complete-support-for-soft-reset.patch
ApplyPatch 0619-scsi-mpi3mr-Print-pending-host-I-Os-for-debugging.patch
ApplyPatch 0620-scsi-mpi3mr-Wait-for-pending-I-O-completions-upon-de.patch
ApplyPatch 0621-scsi-mpi3mr-Add-support-for-PM-suspend-and-resume.patch
ApplyPatch 0622-scsi-mpi3mr-Add-support-for-DSN-secure-firmware-chec.patch
ApplyPatch 0623-scsi-mpi3mr-Add-EEDP-DIF-DIX-support.patch
ApplyPatch 0624-scsi-mpi3mr-Add-event-handling-debug-prints.patch
ApplyPatch 0625-scsi-mpi3mr-Fix-fall-through-warning-for-Clang.patch
ApplyPatch 0626-scsi-mpi3mr-Fix-a-double-free.patch
ApplyPatch 0627-scsi-mpi3mr-Delete-unnecessary-NULL-check.patch
ApplyPatch 0628-scsi-mpi3mr-Fix-error-handling-in-mpi3mr_setup_isr.patch
ApplyPatch 0629-scsi-mpi3mr-Fix-missing-unlock-on-error.patch
ApplyPatch 0630-scsi-mpi3mr-Fix-error-return-code-in-mpi3mr_init_ioc.patch
ApplyPatch 0631-scsi-mpi3mr-Make-some-symbols-static.patch
ApplyPatch 0632-scsi-mpi3mr-Fix-warnings-reported-by-smatch.patch
ApplyPatch 0633-scsi-mpi3mr-Fix-W-1-compilation-warnings.patch
ApplyPatch 0634-scsi-mpi3mr-Set-up-IRQs-in-resume-path.patch
ApplyPatch 0635-scsi-mpi3mr-Fix-duplicate-device-entries-when-scanni.patch
ApplyPatch 0636-scsi-mpi3mr-Fixes-around-reply-request-queues.patch
ApplyPatch 0637-scsi-mpi3mr-Fix-reporting-of-actual-data-transfer-si.patch
ApplyPatch 0638-scsi-mpi3mr-Fix-memory-leaks.patch
ApplyPatch 0639-mm-damon-dbgfs-fix-memory-leak-when-using-debugfs_lo.patch
ApplyPatch 0640-damon-sysfs-fix-possible-memleak-on-damon_sysfs_add_.patch
ApplyPatch 0641-bpf-Allow-LSM-programs-to-use-bpf-spin-locks.patch
ApplyPatch 0642-bpf-Implement-task-local-storage.patch
ApplyPatch 0643-io_uring-af_unix-defer-registered-files-gc-to-io_uri.patch

# Any further pre-build tree manipulations happen here.

chmod +x scripts/checkpatch.pl

touch .scmversion

%if 0%{?amzn} >= 2022
# Mangle /usr/bin/python shebangs to /usr/bin/python3
# Mangle all Python shebangs to be Python 3 explicitly
# -p preserves timestamps
# -n prevents creating ~backup files
# -i specifies the interpreter for the shebang
# This fixes errors such as
# *** ERROR: ambiguous python shebang in /usr/bin/kvm_stat: #!/usr/bin/python. Change it to python3 (or python2) explicitly.
# We patch all sources below for which we got a report/error.
pathfix.py -i "%{__python3} %{py3_shbang_opts}" -p -n \
      tools/kvm/kvm_stat/kvm_stat \
      scripts/show_delta \
      scripts/diffconfig \
      scripts/bloat-o-meter \
      scripts/jobserver-exec \
      scripts/tracing/draw_functrace.py \
      scripts/spdxcheck.py \
      tools \
      Documentation \
      scripts/clang-tools
%endif

# only deal with configs if we are going to build for the arch
%ifnarch %nobuildarches

mkdir configs

# Remove configs not for the buildarch
for cfg in kernel-%{version}-*.config; do
  if [ `echo %{all_arch_configs} | grep -c $cfg` -eq 0 ]; then
    rm -f $cfg
  fi
done

%if !%{debugbuildsenabled}
rm -f kernel-%{version}-*debug.config
%endif

%if 0%{?amzn} >= 2022
%global make_defines CC=gcc HOSTCC=gcc HOSTCXX=g++
%else
%global make_defines CROSS_COMPILE=%{GCC_VER} CC=%{GCC_VER}gcc HOSTCC=%{GCC_VER}gcc HOSTCXX=%{GCC_VER}g++ LD=%{GCC_VER}ld.bfd
%endif

# now run oldconfig over all the config files
for i in *.config
do
  mv $i .config
  Arch=`head -1 .config | cut -b 3-`
%if %{with_oldconfig}
  make ARCH=$Arch %{oldconfig_target} %{?make_defines}
%endif
  echo "# $Arch" > configs/$i
  cat .config >> configs/$i
done
# end of kernel config
%endif

# get rid of unwanted files resulting from patch fuzz
find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null

cd ..

###
### build
###
%build

%if %{with_sparse}
%define sparse_mflags	C=1
%endif

cp_vmlinux()
{
  eu-strip --remove-comment -o "$2" "$1"
}

export CC=%{?_gcc}%{?!_gcc:gcc}
export HOSTCC=%{?_gcc}%{?!_gcc:gcc}
export HOSTCXX=%{?_gxx}%{?!_gxx:g++}

export KBUILD_BUILD_HOST=$(hostname --short)

BuildKernel() {
    MakeTarget=$1
    KernelImage=$2
    Flavour=$3
    Flav=${Flavour:+.${Flavour}}
    InstallName=${4:-vmlinuz}

    # Pick the right config file for the kernel we're building
    Config=kernel-%{version}-%{_target_cpu}${Flavour:+-${Flavour}}.config
    DevelDir=/usr/src/kernels/%{KVERREL}${Flav}

    # When the bootable image is just the ELF kernel, strip it.
    # We already copy the unstripped file into the debuginfo package.
    if [ "$KernelImage" = vmlinux ]; then
      CopyKernel=cp_vmlinux
    else
      CopyKernel=cp
    fi

    KernelVer=%{version}-%{release}.%{_target_cpu}${Flav}
    echo BUILDING A KERNEL FOR ${Flavour} %{_target_cpu}...

    # make sure EXTRAVERSION says what we want it to say
    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}.%{_target_cpu}${Flav}/" Makefile

    # and now to start the build process

    make -s mrproper %{?make_defines} 
    cp configs/$Config .config

%if %{signmodules}
    cp %{SOURCE11} .
%endif

    Arch=`head -1 .config | cut -b 3-`
    echo USING ARCH=$Arch

    make -s ARCH=$Arch %{oldconfig_target} %{?make_defines} > /dev/null

     # This ensures build-ids are unique to allow parallel debuginfo
     perl -p -i -e "s/^CONFIG_BUILD_SALT.*/CONFIG_BUILD_SALT=\"%{KVERREL}\"/" .config

    make -s ARCH=$Arch V=1 %{?_smp_mflags} $MakeTarget %{?sparse_mflags} %{?make_defines}
    make -s ARCH=$Arch V=1 %{?_smp_mflags} modules %{?sparse_mflags} %{?make_defines} || exit 1

    # Start installing the results
%if %{with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/boot
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/%{image_install_path}
%endif
    mkdir -p $RPM_BUILD_ROOT/%{image_install_path}
    install -m 644 .config $RPM_BUILD_ROOT/boot/config-$KernelVer
    install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-$KernelVer

%if 0%{?amzn} >= 2022
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer
    install -m 644 .config $RPM_BUILD_ROOT/lib/modules/$KernelVer/config
    install -m 644 System.map $RPM_BUILD_ROOT/lib/modules/$KernelVer/System.map
%endif

    # We estimate the size of the initramfs because rpm needs to take this size
    # into consideration when performing disk space calculations. (See bz #530778)
    dd if=/dev/zero of=$RPM_BUILD_ROOT/boot/initramfs-$KernelVer.img bs=1M count=20

    if [ -f arch/$Arch/boot/zImage.stub ]; then
      cp arch/$Arch/boot/zImage.stub $RPM_BUILD_ROOT/%{image_install_path}/zImage.stub-$KernelVer || :
%if 0%{?amzn} >= 2022
    cp arch/$Arch/boot/zImage.stub $RPM_BUILD_ROOT/lib/modules/$KernelVer/zImage.stub-$KernelVer || :
%endif
    fi
    %if %{signmodules}
        %if %{usingefi}
        # Sign the image if we're using EFI
        %pesign -s -i $KernelImage -o vmlinuz.signed
        if [ ! -s vmlinuz.signed ]; then
            echo "pesigning failed"
            exit 1
        fi
        mv vmlinuz.signed $KernelImage
        %endif
    %endif
    $CopyKernel $KernelImage \
    		$RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer
    chmod 755 $RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer
%if 0%{?amzn} >= 2022
    cp $RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer $RPM_BUILD_ROOT/lib/modules/$KernelVer/$InstallName
%endif

%if %{with_fips}
    #hmac sign the kernel for FIPS
    echo "Creating hmac file: $RPM_BUILD_ROOT/%{image_install_path}/.vmlinuz-$KernelVer.hmac"
    ls -l $RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer
    sha512hmac $RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer | sed -e "s,$RPM_BUILD_ROOT,," >  $RPM_BUILD_ROOT/%{image_install_path}/.vmlinuz-$KernelVer.hmac
%if 0%{?amzn} >= 2022
    cp $RPM_BUILD_ROOT/%{image_install_path}/.vmlinuz-$KernelVer.hmac $RPM_BUILD_ROOT/lib/modules/$KernelVer/.vmlinuz.hmac
%endif
%endif

    # Override $(mod-fw) because we don't want it to install any firmware
    # we'll get it from the linux-firmware package and we don't want conflicts
    make -s ARCH=$Arch INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=$KernelVer mod-fw= %{?make_defines}

%ifarch %{vdso_arches}
    make -s ARCH=$Arch INSTALL_MOD_PATH=$RPM_BUILD_ROOT vdso_install KERNELRELEASE=$KernelVer %{?make_defines}
%endif

    # And save the headers/makefiles etc for building modules against
    #
    # This all looks scary, but the end result is supposed to be:
    # * all arch relevant include/ files
    # * all Makefile/Kconfig files
    # * all script/ files

    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/source
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    (cd $RPM_BUILD_ROOT/lib/modules/$KernelVer ; ln -s build source)
    # dirs for additional modules per module-init-tools, kbuild/modules.txt
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/extra
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/updates
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/weak-updates
    # first copy everything
    cp --parents `find  -type f -name "Makefile*" -o -name "Kconfig*"` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    cp Module.symvers $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    gzip -c9 Module.symvers >  $RPM_BUILD_ROOT/boot/symvers-$KernelVer.gz
%if 0%{?amzn} >= 2022
    cp $RPM_BUILD_ROOT/boot/symvers-$KernelVer.gz $RPM_BUILD_ROOT/lib/modules/$KernelVer/symvers.gz
%endif
    cp System.map $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    if [ -s Module.markers ]; then
      cp Module.markers $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    fi
    # then drop all but the needed Makefiles/Kconfig files
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Documentation
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cp .config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    if [ -f tools/objtool/objtool ]; then
      cp -a tools/objtool/objtool $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/tools/objtool/ || :
    fi
    cp -a scripts $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    if [ -d arch/$Arch/scripts ]; then
      cp -a arch/$Arch/scripts $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch} || :
    fi
    if [ -f arch/$Arch/*lds ]; then
      cp -a arch/$Arch/*lds $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch}/ || :
    fi
    if [ -f arch/%{asmarch}/kernel/module.lds ]; then
      cp -a --parents arch/%{asmarch}/kernel/module.lds $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    fi
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts/*.o
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts/*/*.o
    if [ -d arch/%{asmarch}/include ]; then
      cp -a --parents arch/%{asmarch}/include $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    fi
    cp -a include $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
%if 0%{?amzn} < 2022
    #Use a wrapper Makefile so modules compile with gcc10
    mv $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile.kernel
    cp $RPM_SOURCE_DIR/Makefile.module $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile
%endif


    # newer kernels relocate these from under include/linux to
    # include/generated.... Maintain compatibility with old(er) code looking
    # for former files in the formerly valid location
    pushd  $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux
    test -s utsrelease.h        || ln -sf ../generated/utsrelease.h .
    test -s autoconf.h          || ln -sf ../generated/autoconf.h .
    test -s version.h           || ln -sf ../generated/uapi/linux/version.h .
    popd
    # Make sure the Makefile and version.h have a matching timestamp so that
    # external modules can be built
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/version.h
%if 0%{?amzn} < 2022
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile.kernel
%endif
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/.config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/autoconf.h
    
    # Copy .config to include/config/auto.conf so "make prepare" is unnecessary.
    cp -a $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/.config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/config/auto.conf

%if %{with_debuginfo}
    eu-readelf -n vmlinux | grep "Build ID" | awk '{print $NF}' > vmlinux.id
    cp vmlinux.id $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/vmlinux.id
    #
    # save the vmlinux file for kernel debugging into the kernel-debuginfo rpm
    #
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/$KernelVer
    cp vmlinux $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/$KernelVer
%endif

    find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f >modnames

    # mark modules executable so that strip-to-file can strip them
    xargs --no-run-if-empty chmod u+x < modnames

    # Generate a list of modules for block and networking.

    grep -F /drivers/ modnames | xargs --no-run-if-empty %{GCC_VER}nm -upA |
    sed -n 's,^.*/\([^/]*\.ko\):  *U \(.*\)$,\1 \2,p' > drivers.undef

    collect_modules_list()
    {
      sed -r -n -e "s/^([^ ]+) \\.?($2)\$/\\1/p" drivers.undef |
      LC_ALL=C sort -u > $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.$1
    }

    collect_modules_list networking \
                        'register_netdev|ieee80211_register_hw|usbnet_probe|phy_driver_register|rt(l_|2x00)(pci|usb)_probe|register_netdevice'
    collect_modules_list block \
                        'ata_scsi_ioctl|scsi_add_host|scsi_add_host_with_dma|blk_init_queue|register_mtd_blktrans|scsi_esp_register|scsi_register_device_handler|blk_queue_physical_block_size'
    collect_modules_list drm \
                        'drm_open|drm_init'
    collect_modules_list modesetting \
                        'drm_crtc_init'

    # detect missing or incorrect license tags
    rm -f modinfo
    while read i
    do
      echo -n "${i#$RPM_BUILD_ROOT/lib/modules/$KernelVer/} " >> modinfo
      %{_sbindir}/modinfo -l $i >> modinfo
    done < modnames

    grep -E -v \
    	  'GPL( v2)?$|Dual BSD/GPL$|Dual MPL/GPL$|GPL and additional rights$' \
	  modinfo && exit 1

    rm -f modinfo modnames

    # Call the modules-extra script to move things around
    %{SOURCE17} $RPM_BUILD_ROOT/lib/modules/$KernelVer %{SOURCE16}

%if %{signmodules}
    # Save off the modules.order file.  We'll use it in the
    # __debug_install_post macro below to sign the right things
    # Also save the signing keys so we actually sign the modules with the
    # right key.
    cp -v modules.order modules.order.sign${Flavour:+.${Flavour}}
    cp certs/signing_key.pem signing_key.pem.sign${Flavour:+.${Flavour}}
    cp certs/signing_key.x509 signing_key.x509.sign${Flavour:+.${Flavour}}
%endif

    # remove files that will be auto generated by depmod at rpm -i time
    for i in alias alias.bin builtin.bin ccwmap dep dep.bin ieee1394map inputmap isapnpmap ofmap pcimap seriomap symbols symbols.bin usbmap devname softdep
    do
      rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.$i
    done

    # Move the devel headers out of the root file system
    mkdir -p $RPM_BUILD_ROOT/usr/src/kernels
    mv $RPM_BUILD_ROOT/lib/modules/$KernelVer/build $RPM_BUILD_ROOT/$DevelDir
    ln -sf $DevelDir $RPM_BUILD_ROOT/lib/modules/$KernelVer/build

    # prune junk from kernel-devel
    find $RPM_BUILD_ROOT/usr/src/kernels -name ".*.cmd" -exec rm -f {} \;
}

###
# DO it...
###

# prepare directories
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/boot
mkdir -p $RPM_BUILD_ROOT%{_libexecdir}

cd linux-%{KVERREL}

%if %{with_debug}
BuildKernel %make_target %kernel_image debug
%endif

%if %{with_up}
BuildKernel %make_target %kernel_image
%endif

# perf
%global perf_make \
  make %{?_smp_mflags} -C tools/perf -s V=1 EXTRA_CFLAGS="-Wno-error=array-bounds -Wno-error=format-overflow" HAVE_CPLUS_DEMANGLE=1 NO_LIBUNWIND=1 NO_GTK2=1 NO_LIBNUMA=1 NO_STRLCPY=1 prefix=%{_prefix} lib=%{_lib} PYTHON=%{__python} VF=1 %{?make_defines}
%if %{with_perf}
%{perf_make} all
%{perf_make} man || %{doc_build_fail}
%endif

%if %{with_tools}
%ifarch %{cpupowerarchs}
# cpupower
# make sure version-gen.sh is executable.
chmod +x tools/power/cpupower/utils/version-gen.sh
make %{?_smp_mflags} -C tools/power/cpupower CPUFREQ_BENCH=false %{?make_defines}
%ifarch %{ix86}
    pushd tools/power/cpupower/debug/i386
    make %{?_smp_mflags} centrino-decode powernow-k8-decode
    popd
%endif
%ifarch x86_64
    pushd tools/power/cpupower/debug/x86_64
    make %{?_smp_mflags} centrino-decode powernow-k8-decode
    popd
%endif
%ifarch %{ix86} x86_64
   pushd tools/power/x86/x86_energy_perf_policy/
   make %{?make_defines}
   popd
   pushd tools/power/x86/turbostat
   make %{?make_defines}
   popd
%endif
%endif
%endif

%global bpftool_make \
  %{__make} EXTRA_CFLAGS="${RPM_OPT_FLAGS}" EXTRA_LDFLAGS="%{__global_ldflags}" DESTDIR=$RPM_BUILD_ROOT V=1 %{?make_defines}
%if %{with_bpftool}
pushd tools/bpf/bpftool
%{bpftool_make}
popd
%endif

%if %{with_doc}
#
# Make the HTML documents.
# Newer kernel versions use ReST markups for documentation which
# needs to be built using Sphinx. Sphinx toolchain is fragile and any
# upgrade to its toolchain or dependent python package can cause
# documentation build to fail. To avoid this problem, documentation
# build uses one particular version of Sphinx. To build document,
# we create a virtual environment and install the required version
# of Sphinx inside it.
# Refer to $SRC/Documentation/sphinx/requirements.txt for more
# information related to package and version dependency.
#
virtualenv doc_build_env
source ./doc_build_env/bin/activate
pip install -r Documentation/sphinx/requirements.txt
make htmldocs || %{doc_build_fail}
deactivate
rm -rf doc_build_env

# Build man pages for the kernel API (section 9)
scripts/kernel-doc -man $(find . -name '*.[ch]') | %{split_man_cmd} Documentation/output/man
pushd Documentation/output/man
gzip *.9
popd

# sometimes non-world-readable files sneak into the kernel source tree
chmod -R a=rX Documentation
find Documentation -type d | xargs chmod u+w

# switch absolute symlinks to relative ones
find . -lname "$(pwd)*" -exec sh -c 'ln -snvf $(%{__%{py_pkg_prefix}} -c "from os.path import *; print relpath(\"$(readlink {})\",dirname(\"{}\"))") {}' \;
%endif

# In the modsign case, we do 3 things.  1) We check the "flavour" and hard
# code the value in the following invocations.  This is somewhat sub-optimal
# but we're doing this inside of an RPM macro and it isn't as easy as it
# could be because of that.  2) We restore the .tmp_versions/ directory from
# the one we saved off in BuildKernel above.  This is to make sure we're
# signing the modules we actually built/installed in that flavour.  3) We
# grab the arch and invoke mod-sign.sh command to actually sign the modules.
#
# We have to do all of those things _after_ find-debuginfo runs, otherwise
# that will strip the signature off of the modules.
%define __modsign_install_post \
  if [ "%{signmodules}" == "1" ]; then \
    if [ "%{with_debug}" -ne "0" ]; \
    then \
      mv modules.order.sign.debug modules.order \
      Arch=`head -1 configs/kernel-%{rpmversion}-%{_target_cpu}-debug.config | cut -b 3-` \
      mv signing_key.pem.sign.debug signing_key.pem \
      mv signing_key.x509.sign.debug signing_key.x509 \
      make -s ARCH=$Arch V=1 INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_sign KERNELRELEASE=%{KVERREL}.debug %{?make_defines} \
      %{modsign_cmd} $RPM_BUILD_ROOT/lib/modules/%{KVERREL}.debug/extra/ \
    fi \
    if [ "%{with_up}" -ne "0" ]; \
    then \
      Arch=`head -1 configs/kernel-%{rpmversion}-%{_target_cpu}.config | cut -b 3-` \
      mv signing_key.pem.sign signing_key.pem \
      mv signing_key.x509.sign signing_key.x509 \
      %{modsign_cmd} $RPM_BUILD_ROOT/lib/modules/%{KVERREL}/ \
      %{modsign_cmd} $RPM_BUILD_ROOT/lib/modules/%{KVERREL}/extra/ \
    fi \
  fi \
%{nil}

###
### Special hacks for debuginfo subpackages.
###

# This macro is used by %%install, so we must redefine it before that.
%define debug_package %{nil}

%if %{with_debuginfo}

%ifnarch noarch
%global __debug_package 1
%files -f debugfiles.list debuginfo-common-%{_target_cpu}
%defattr(-,root,root)
%endif

%endif

#
# Disgusting hack alert! We need to ensure we sign modules *after* all
# invocations of strip occur, which is in __debug_install_post if
# find-debuginfo.sh runs, and __os_install_post if not.
%define __spec_install_post \
  %{?__debug_package:%{__debug_install_post}}\
  %{__arch_install_post}\
  %{__os_install_post}\
  %{__modsign_install_post}

###
### install
###

%install

cd linux-%{KVERREL}

%if %{with_doc}
docdir=$RPM_BUILD_ROOT%{_datadir}/doc/kernel-doc-%{rpmversion}
man9dir=$RPM_BUILD_ROOT%{_datadir}/man/man9

# copy the source over
mkdir -p $docdir
tar -f - --exclude=man --exclude='.*' -c Documentation | tar xf - -C $docdir

# Install man pages for the kernel API.
mkdir -p $man9dir
pushd Documentation/output/man
find -type f -name '*.9.gz' -print0 |
xargs -0 --no-run-if-empty %{__install} -m 444 -t $man9dir $m
popd
ls $man9dir | grep -q '' || > $man9dir/BROKEN
%endif

# We have to do the headers install before the tools install because the
# kernel headers_install will remove any header files in /usr/include that
# it doesn't install itself.

%if %{with_headers}
# Install kernel headers
make -s ARCH=%{hdrarch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr headers_install %{?make_defines}

# Do headers_check but don't die if it fails.
make -s ARCH=%{hdrarch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr headers_check \
     > hdrwarnings.txt || :
if grep -q exist hdrwarnings.txt; then
   sed s:^$RPM_BUILD_ROOT/usr/include/:: hdrwarnings.txt
   # Temporarily cause a build failure if header inconsistencies.
   # exit 1
fi

find $RPM_BUILD_ROOT/usr/include \
     \( -name .install -o -name .check -o \
     	-name ..install.cmd -o -name ..check.cmd \) | xargs rm -f

# glibc provides scsi headers for itself, for now
rm -rf $RPM_BUILD_ROOT/usr/include/scsi
rm -f $RPM_BUILD_ROOT/usr/include/asm*/atomic.h
rm -f $RPM_BUILD_ROOT/usr/include/asm*/io.h
rm -f $RPM_BUILD_ROOT/usr/include/asm*/irq.h
%endif

%if %{with_perf}
# perf tool binary and supporting scripts/binaries
%{perf_make} DESTDIR=$RPM_BUILD_ROOT install
# python-perf extension
%{perf_make} DESTDIR=$RPM_BUILD_ROOT install-python_ext
# perf man pages (note: implicit rpm magic compresses them later)
%{perf_make} DESTDIR=$RPM_BUILD_ROOT install-man || %{doc_build_fail}
# clean up files we don't use
rm -f $RPM_BUILD_ROOT/etc/bash_completion.d/perf
%endif

%if %{with_tools}
%ifarch %{cpupowerarchs}
make -C tools/power/cpupower DESTDIR=$RPM_BUILD_ROOT libdir=%{_libdir} mandir=%{_mandir} CPUFREQ_BENCH=false install
rm -f %{buildroot}%{_libdir}/*.{a,la}
%find_lang cpupower
mv cpupower.lang ../
%ifarch %{ix86}
    pushd tools/power/cpupower/debug/i386
    install -m755 centrino-decode %{buildroot}%{_bindir}/centrino-decode
    install -m755 powernow-k8-decode %{buildroot}%{_bindir}/powernow-k8-decode
    popd
%endif
%ifarch x86_64
    pushd tools/power/cpupower/debug/x86_64
    install -m755 centrino-decode %{buildroot}%{_bindir}/centrino-decode
    install -m755 powernow-k8-decode %{buildroot}%{_bindir}/powernow-k8-decode
    popd
%endif
%ifarch %{ix86} x86_64
   mkdir -p %{buildroot}%{_mandir}/man8
   pushd tools/power/x86/x86_energy_perf_policy
   make DESTDIR=%{buildroot} install
   popd
   pushd tools/power/x86/turbostat
   make DESTDIR=%{buildroot} install
   popd
%endif
chmod 0755 %{buildroot}%{_libdir}/libcpupower.so*
mkdir -p %{buildroot}%{_initddir} %{buildroot}%{_sysconfdir}/sysconfig
#install -m644 %{SOURCE2000} %{buildroot}%{_initddir}/cpupower
install -m644 %{SOURCE2001} %{buildroot}%{_sysconfdir}/sysconfig/cpupower
%endif
# just in case so the files list won't croak
touch ../cpupower.lang
%endif

%if %{with_bpftool}
pushd tools/bpf/bpftool
%{bpftool_make} prefix=%{_prefix} bash_compdir=%{_sysconfdir}/bash_completion.d/ mandir=%{_mandir} install doc-install
popd
%if 0%{?amzn} >= 2022
# man-pages packages this (rhbz #1686954, #1918707)
rm %{buildroot}%{_mandir}/man7/bpf-helpers.7
%endif
%endif

###
### clean
###

%clean
rm -rf $RPM_BUILD_ROOT

###
### scripts
###

%if %{with_tools}
%post tools
%{_sbindir}/ldconfig

%postun tools
%{_sbindir}/ldconfig
%endif

#
# This macro defines a %%post script for a kernel*-devel package.
#	%%kernel_devel_post [<subpackage>]
#
# Note we don't run hardlink if ostree is in use, as ostree is
# a far more sophisticated hardlink implementation.
# https://github.com/projectatomic/rpm-ostree/commit/58a79056a889be8814aa51f507b2c7a4dccee526
#
%define kernel_devel_post() \
%{expand:%%post %{?1:%{1}-}devel}\
if [ -f /etc/sysconfig/kernel ]\
then\
    . /etc/sysconfig/kernel || exit $?\
fi\
if [ "$HARDLINK" != "no" -a -x %{_sbindir}/hardlink -a ! -e /run/ostree-booted ]\
then\
    (cd /usr/src/kernels/%{KVERREL}%{?1:.%{1}} &&\
     %{_bindir}/find . -type f | while read f; do\
       %{_sbindir}/hardlink -c /usr/src/kernels/*.%{dist}.*/$f $f\
     done)\
fi\
%{nil}

# This macro defines a %%posttrans script for a kernel package.
#	%%kernel_variant_posttrans [<subpackage>]
# More text can follow to go at the end of this variant's %%post.
#
%if 0%{?amzn} >= 2022

%define kernel_variant_posttrans() \
%{expand:%%posttrans %{?1}}\
if [ -x %{_sbindir}/weak-modules ]\
then\
    %{_sbindir}/weak-modules --add-kernel %{KVERREL}%{?1:+%{1}} || exit $?\
fi\
/bin/kernel-install add %{KVERREL}%{?1:+%{1}} /lib/modules/%{KVERREL}%{?1:+%{1}}/vmlinuz || exit $?\
%{nil}

%else

%define kernel_variant_posttrans() \
%{expand:%%posttrans %{?1}}\
%{expand:\
%{_sbindir}/new-kernel-pkg --package kernel%{?1:-%{1}} --mkinitrd --make-default --dracut --depmod --install %{KVERREL}%{?1:.%{1}} || exit $?\
}\
%{_sbindir}/new-kernel-pkg --package kernel%{?1:-%{1}} --rpmposttrans %{KVERREL}%{?1:.%{1}} || exit $?\
%{nil}

%endif

#
# This macro defines a %%post script for a kernel package and its devel package.
#	%%kernel_variant_post [-v <subpackage>] [-r <replace>]
# More text can follow to go at the end of this variant's %%post.
#
%define kernel_variant_post(v:r:) \
%{expand:%%kernel_devel_post %{?-v*}}\
%{expand:%%kernel_variant_posttrans %{?-v*}}\
%{expand:%%post %{?-v*}}\
%{-r:\
if [ `uname -i` == "x86_64" -o `uname -i` == "i386" ] &&\
   [ -f /etc/sysconfig/kernel ]; then\
  %{_bindir}/sed -r -i -e 's/^DEFAULTKERNEL=%{-r*}$/DEFAULTKERNEL=kernel%{?-v:-%{-v*}}/' /etc/sysconfig/kernel || exit $?\
fi}\
/sbin/depmod -a %{KVERREL}%{?1:+%{1}}\
%{nil}

#
# This macro defines a %%preun script for a kernel package.
#	%%kernel_variant_preun <subpackage>
#
%if 0%{?amzn} >= 2022

%define kernel_variant_preun() \
%{expand:%%preun %{?1}}\
/bin/kernel-install remove %{KVERREL}%{?1:+%{1}} /lib/modules/%{KVERREL}%{?1:+%{1}}/vmlinuz || exit $?\
if [ -x %{_sbindir}/weak-modules ]\
then\
    %{_sbindir}/weak-modules --remove-kernel %{KVERREL}%{?1:+%{1}} || exit $?\
fi\
%{nil}

%else

%define kernel_variant_preun() \
%{expand:%%preun %{?1}}\
%{_sbindir}/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}%{?1:.%{1}} || exit $?\
%{nil}

%endif

%kernel_variant_preun
%kernel_variant_post

%kernel_variant_preun debug
%kernel_variant_post -v debug

if [ -x %{_sbindir}/ldconfig ]
then
    %{_sbindir}/ldconfig -X || exit $?
fi

###
### file lists
###

%if %{with_headers}
%files headers
%defattr(-,root,root)
/usr/include/*
%endif

# only some architecture builds need kernel-doc
%if %{with_doc}
%files doc
%defattr(-,root,root)
%{_datadir}/doc/kernel-doc-%{rpmversion}/Documentation/*
%dir %{_datadir}/doc/kernel-doc-%{rpmversion}/Documentation
%dir %{_datadir}/doc/kernel-doc-%{rpmversion}
%{_datadir}/man/man9/*
%endif

%if %{with_perf}
%files -n perf
%defattr(-,root,root)
%{_bindir}/perf
%{_libdir}/libperf-jvmti.so
%{_bindir}/trace
%dir %{_libexecdir}/perf-core
%{_libexecdir}/perf-core/*
%{_datadir}/perf-core/*
%{_datadir}/doc/perf*/*
%dir %{_libdir}/traceevent/plugins
%{_libdir}/traceevent/plugins/*
%{_mandir}/man[1-8]/perf*
%{_prefix}/lib/perf/examples/*
%{_prefix}/lib/perf/include/*
%doc linux-%{KVERREL}/tools/perf/Documentation/examples.txt

%files -n %{py_pkg_prefix}-perf
%defattr(-,root,root)
%{python_sitearch}/*

%if %{with_debuginfo}
%files -f perf-debuginfo.list -n perf-debuginfo
%defattr(-,root,root)

%files -f %{py_pkg_prefix}-perf-debuginfo.list -n %{py_pkg_prefix}-perf-debuginfo
%defattr(-,root,root)
%endif
%endif

%if %{with_tools}
%files tools -f cpupower.lang
%defattr(-,root,root)
%{_mandir}/man[1-8]/cpupower*
%{_bindir}/cpupower
%{_datadir}/bash-completion/completions/cpupower
%ifarch %{ix86} x86_64
%{_bindir}/centrino-decode
%{_bindir}/powernow-k8-decode
%{_bindir}/x86_energy_perf_policy
%{_mandir}/man8/x86_energy_perf_policy*
%{_bindir}/turbostat
%{_mandir}/man8/turbostat*
%endif
%{_libdir}/libcpupower.so.0
%{_libdir}/libcpupower.so.0.0.1
%config(noreplace) %{_sysconfdir}/sysconfig/cpupower

%if %{with_debuginfo}
%files tools-debuginfo -f kernel-tools-debuginfo.list
%defattr(-,root,root)
%endif

%ifarch %{cpupowerarchs}
%files tools-devel
%{_libdir}/libcpupower.so
%{_includedir}/cpufreq.h
%endif
# with_tools
%endif

%if %{with_bpftool}
%files -n bpftool
%{_sbindir}/bpftool
%{_sysconfdir}/bash_completion.d/bpftool
%if 0%{?amzn} < 2022
%{_mandir}/man7/bpf-helpers.7.gz
%endif
%{_mandir}/man8/bpftool-cgroup.8.gz
%{_mandir}/man8/bpftool-gen.8.gz
%{_mandir}/man8/bpftool-iter.8.gz
%{_mandir}/man8/bpftool-link.8.gz
%{_mandir}/man8/bpftool-map.8.gz
%{_mandir}/man8/bpftool-prog.8.gz
%{_mandir}/man8/bpftool-perf.8.gz
%{_mandir}/man8/bpftool.8.gz
%{_mandir}/man8/bpftool-net.8.gz
%{_mandir}/man8/bpftool-feature.8.gz
%{_mandir}/man8/bpftool-btf.8.gz
%{_mandir}/man8/bpftool-struct_ops.8.gz

%if %{with_debuginfo}
%files -f bpftool-debuginfo.list -n bpftool-debuginfo
%defattr(-,root,root)
%endif
%endif

# This is %%{image_install_path} on an arch where that includes ELF files,
# or empty otherwise.
%define elf_image_install_path %{?kernel_image_elf:%{image_install_path}}

#
# This macro defines the %%files sections for a kernel package
# and its devel and debuginfo packages.
#	%%kernel_variant_files [-k vmlinux] <condition> <subpackage>
#
%define kernel_variant_files(k:) \
%if %{1}\
%{expand:%%files %{?2}}\
%defattr(-,root,root)\
%if 0%{?amzn} >= 2022\
/lib/modules/%{KVERREL}%{?2:+%{2}}/%{?-k:%{-k*}}%{!?-k:vmlinuz}\
%ghost /%{image_install_path}/%{?-k:%{-k*}}%{!?-k:vmlinuz}-%{KVERREL}%{?2:.%{2}}\
%attr(600,root,root) /lib/modules/%{KVERREL}%{?2:+%{2}}/System.map\
%ghost /boot/System.map-%{KVERREL}%{?2:.%{2}}\
%if %{with_fips} \
/lib/modules/%{KVERREL}%{?2:+%{2}}/.vmlinuz.hmac \
%ghost /%{image_install_path}/.vmlinuz-%{KVERREL}%{?2:.%{2}}.hmac \
%endif \
/lib/modules/%{KVERREL}%{?3:+%{3}}/symvers.gz\
/lib/modules/%{KVERREL}%{?2:+%{2}}/config\
%ghost /boot/symvers-%{KVERREL}%{?2:.%{2}}.gz\
%ghost /boot/config-%{KVERREL}%{?2:.%{2}}\
%else\
/%{image_install_path}/%{?-k:%{-k*}}%{!?-k:vmlinuz}-%{KVERREL}%{?2:.%{2}}\
%attr(600,root,root) /boot/System.map-%{KVERREL}%{?2:.%{2}}\
%if %{with_fips} \
/%{image_install_path}/.vmlinuz-%{KVERREL}%{?2:.%{2}}.hmac \
%endif\
/boot/symvers-%{KVERREL}%{?2:.%{2}}.gz\
/boot/config-%{KVERREL}%{?2:.%{2}}\
%endif\
%dir /lib/modules/%{KVERREL}%{?2:.%{2}}\
/lib/modules/%{KVERREL}%{?2:.%{2}}/kernel\
/lib/modules/%{KVERREL}%{?2:.%{2}}/build\
/lib/modules/%{KVERREL}%{?2:.%{2}}/source\
/lib/modules/%{KVERREL}%{?2:.%{2}}/extra\
/lib/modules/%{KVERREL}%{?2:.%{2}}/updates\
/lib/modules/%{KVERREL}%{?2:.%{2}}/weak-updates\
%ifarch %{vdso_arches}\
/lib/modules/%{KVERREL}%{?2:.%{2}}/vdso\
%endif\
/lib/modules/%{KVERREL}%{?2:.%{2}}/modules.*\
%ghost /boot/initramfs-%{KVERREL}%{?2:.%{2}}.img\
%{expand:%%files %{?2:%{2}-}devel}\
%defattr(-,root,root)\
%verify(not mtime) /usr/src/kernels/%{KVERREL}%{?2:.%{2}}\
%dir /usr/src/kernels\
%if %{with_debuginfo}\
%ifnarch noarch\
%{expand:%%files -f debuginfo%{?2}.list %{?2:%{2}-}debuginfo}\
%defattr(-,root,root)\
%endif\
%endif\
%endif\
%{nil}

%kernel_variant_files %{with_up}
%kernel_variant_files %{with_debug} debug

#
# Finally kernel-livepatch as it has it's own version/release
# NOTE: Don't move this anywhere else, otherwise it'll need
# it's own Name: and that affects all the packages that
# follow. Aslo having a Version, Release affects other subpackages
# so safely tuck this to the end.
# Other Caveats: This spec file uses a special hack for __spec_install_post
# Hence, all operations in __spec_install_post should not refer to
# either %%{version} or %%{release}
#
%ifarch x86_64 aarch64
%package -n kernel-livepatch-%{rpmversion}-%{buildid}
Summary: Livepatches for the Linux Kernel
Version: 1.0
Release: 0%{?dist}
Requires: kpatch
BuildRequires: systemd

%{?systemd_requires}

%description -n kernel-livepatch-%{rpmversion}-%{buildid}
This package contains the live patch modules for bug fixes
against the version of the kernel. This package contains
version 0 (no real livepatches) and helps subscribe to
the kernel livepatch updates for the kernel.

%files -n kernel-livepatch-%{rpmversion}-%{buildid}
%defattr(-,root,root)
%{nil}
%endif

%changelog
* Tue Oct 18 2022 Builder <builder@amazon.com>
- builder/437558e2cf805761ea221472a3cb1ac1b48e3a80 last changes:
  + [437558e] [2022-10-18] Rebase to v5.10.149 (linuxci@linux-corp-jenkins-kernel-62002.pdx2.corp.amazon.com)

- linux/6571d2c0a1b1ca73ef3db4dd29376dd2b0bbea35 last changes:
  + [6571d2c0a1b1] [2022-10-03] io_uring/af_unix: defer registered files gc to io_uring release (asml.silence@gmail.com)
  + [7b1c64698307] [2020-11-06] bpf: Implement task local storage (kpsingh@google.com)
  + [2a64c04b56a5] [2020-11-06] bpf: Allow LSM programs to use bpf spin locks (kpsingh@google.com)
  + [3d3101fb9ad3] [2022-09-26] damon/sysfs: fix possible memleak on damon_sysfs_add_target (ppbuk5246@gmail.com)
  + [c586acc1be4b] [2022-09-02] mm/damon/dbgfs: fix memory leak when using debugfs_lookup() (gregkh@linuxfoundation.org)
  + [5c0ecbdc5e1b] [2022-02-10] scsi: mpi3mr: Fix memory leaks (sreekanth.reddy@broadcom.com)
  + [40312ea4cf42] [2022-02-10] scsi: mpi3mr: Fix reporting of actual data transfer size (sreekanth.reddy@broadcom.com)
  + [1172b4221f40] [2021-12-20] scsi: mpi3mr: Fixes around reply request queues (sreekanth.reddy@broadcom.com)
  + [3c5f8835159a] [2021-10-14] scsi: mpi3mr: Fix duplicate device entries when scanning through sysfs (sreekanth.reddy@broadcom.com)
  + [fc479ae2d7b8] [2021-08-18] scsi: mpi3mr: Set up IRQs in resume path (kashyap.desai@broadcom.com)
  + [ca43d607d865] [2021-07-07] scsi: mpi3mr: Fix W=1 compilation warnings (sreekanth.reddy@broadcom.com)
  + [cd4c67ad2c62] [2021-06-29] scsi: mpi3mr: Fix warnings reported by smatch (sreekanth.reddy@broadcom.com)
  + [17aed3ff3a48] [2021-06-04] scsi: mpi3mr: Make some symbols static (yangyingliang@huawei.com)
  + [74ee88cd91c2] [2021-06-03] scsi: mpi3mr: Fix error return code in mpi3mr_init_ioc() (yangyingliang@huawei.com)
  + [ee8572a8f60f] [2021-06-03] scsi: mpi3mr: Fix missing unlock on error (yangyingliang@huawei.com)
  + [27290f398b5d] [2021-06-09] scsi: mpi3mr: Fix error handling in mpi3mr_setup_isr() (dan.carpenter@oracle.com)
  + [dfffd812205c] [2021-06-09] scsi: mpi3mr: Delete unnecessary NULL check (dan.carpenter@oracle.com)
  + [2e5fd1a9e79b] [2021-06-08] scsi: mpi3mr: Fix a double free (thenzl@redhat.com)
  + [e2f90b480164] [2021-06-03] scsi: mpi3mr: Fix fall-through warning for Clang (gustavoars@kernel.org)
  + [ae5b07efa185] [2021-05-20] scsi: mpi3mr: Add event handling debug prints (kashyap.desai@broadcom.com)
  + [bea7c89318dd] [2021-05-20] scsi: mpi3mr: Add EEDP DIF DIX support (kashyap.desai@broadcom.com)
  + [639119426d02] [2021-05-20] scsi: mpi3mr: Add support for DSN secure firmware check (kashyap.desai@broadcom.com)
  + [cfff22d0ce9d] [2021-05-20] scsi: mpi3mr: Add support for PM suspend and resume (kashyap.desai@broadcom.com)
  + [a5ede485ae75] [2021-05-20] scsi: mpi3mr: Wait for pending I/O completions upon detection of VD I/O timeout (kashyap.desai@broadcom.com)
  + [da418a284537] [2021-05-20] scsi: mpi3mr: Print pending host I/Os for debugging (kashyap.desai@broadcom.com)
  + [8f86114d3e84] [2021-05-20] scsi: mpi3mr: Complete support for soft reset (kashyap.desai@broadcom.com)
  + [5fde3d6acabb] [2021-05-20] scsi: mpi3mr: Add support for threaded ISR (kashyap.desai@broadcom.com)
  + [6e883862dd53] [2021-05-20] scsi: mpi3mr: Hardware workaround for UNMAP commands to NVMe drives (kashyap.desai@broadcom.com)
  + [c1eedf9bbabf] [2021-05-20] scsi: mpi3mr: Allow certain commands during pci-remove hook (kashyap.desai@broadcom.com)
  + [a4643ed0fae0] [2021-05-20] scsi: mpi3mr: Add change queue depth support (kashyap.desai@broadcom.com)
  + [8d713459eca7] [2021-05-20] scsi: mpi3mr: Implement SCSI error handler hooks (kashyap.desai@broadcom.com)
  + [844d6cd856fd] [2021-05-20] scsi: mpi3mr: Add bios_param SCSI host template hook (kashyap.desai@broadcom.com)
  + [026d19053d5f] [2021-05-20] scsi: mpi3mr: Print IOC info for debugging (kashyap.desai@broadcom.com)
  + [3e6f049ad413] [2021-05-20] scsi: mpi3mr: Add support for timestamp sync with firmware (kashyap.desai@broadcom.com)
  + [6fe7498242e9] [2021-05-20] scsi: mpi3mr: Add support for recovering controller (kashyap.desai@broadcom.com)
  + [1a24ad365fe6] [2021-05-20] scsi: mpi3mr: Additional event handling (kashyap.desai@broadcom.com)
  + [6d95560e1b47] [2021-05-20] scsi: mpi3mr: Add support for PCIe device event handling (kashyap.desai@broadcom.com)
  + [341547195735] [2021-05-20] scsi: mpi3mr: Add support for device add/remove event handling (kashyap.desai@broadcom.com)
  + [5f7938b74305] [2021-05-20] scsi: mpi3mr: Add support for internal watchdog thread (kashyap.desai@broadcom.com)
  + [c630f8856829] [2021-05-20] scsi: mpi3mr: Add support for queue command processing (kashyap.desai@broadcom.com)
  + [9d69c47e8dd5] [2021-05-20] scsi: mpi3mr: Create operational request and reply queue pair (kashyap.desai@broadcom.com)
  + [5a8b03cc56a4] [2021-05-20] scsi: mpi3mr: Base driver code (kashyap.desai@broadcom.com)
  + [d40baba3765a] [2021-05-20] scsi: mpi3mr: Add mpi30 Rev-R headers and Kconfig (kashyap.desai@broadcom.com)
  + [6ea37d2c7fb4] [2022-09-13] lustre: update to AmazonFSxLustreClient v2.12.8-fsx4 (shaoyi@amazon.com)
  + [f51c443bdd4e] [2022-09-13] ENA: Update to v2.8.0 (surajjs@amazon.com)
  + [bc90a869bd1a] [2022-09-13] DOWNSTREAM ONLY: Revert "Makefile: link with -z noexecstack --no-warn-rwx-segments" (surajjs@amazon.com)
  + [d7054d36a6c0] [2022-08-30] Revert "x86/speculation: Add RSB VM Exit protections" (surajjs@amazon.com)
  + [b0c28468c21b] [2022-08-21] mm/damon/dbgfs: avoid duplicate context directory creation (badari.pulavarty@intel.com)
  + [7db3364398a9] [2022-07-14] mm/damon/reclaim: fix potential memory leak in damon_reclaim_init() (niejianglei2021@163.com)
  + [e5566125fe26] [2022-06-20] mm/damon: use set_huge_pte_at() to make huge pte old (baolin.wang@linux.alibaba.com)
  + [215811e0c14a] [2022-06-04] mm/damon/reclaim: schedule 'damon_reclaim_timer' only after 'system_wq' is initialized (sj@kernel.org)
  + [472588998750] [2022-05-17] mm: damon: use HPAGE_PMD_SIZE (wangkefeng.wang@huawei.com)
  + [51e542233327] [2022-05-13] mm/damon: add documentation for Enum value (gautammenghani201@gmail.com)
  + [295b15fb4b41] [2022-05-12] mm/damon/reclaim: use resource_size function on resource object (jiapeng.chong@linux.alibaba.com)
  + [f2ef65e7d928] [2022-05-09] Docs/admin-guide/mm/damon/reclaim: document 'commit_inputs' parameter (sj@kernel.org)
  + [585443642597] [2022-05-09] mm/damon/reclaim: support online inputs update (sj@kernel.org)
  + [4b98fa719d87] [2022-05-09] Docs/{ABI,admin-guide}/damon: Update for 'state' sysfs file input keyword, 'commit' (sj@kernel.org)
  + [cfc1c2186335] [2022-05-09] mm/damon/sysfs: support online inputs update (sj@kernel.org)
  + [bf8352adb587] [2022-05-09] mm/damon/sysfs: update schemes stat in the kdamond context (sj@kernel.org)
  + [bb94ddc40f9d] [2022-05-09] mm/damon/sysfs: use enum for 'state' input handling (sj@kernel.org)
  + [ad1ff1137c9c] [2022-05-09] mm/damon/sysfs: reuse damon_set_regions() for regions setting (sj@kernel.org)
  + [3dc2b406fd24] [2022-05-09] mm/damon/sysfs: move targets setup code to a separated function (sj@kernel.org)
  + [3e875737ed1b] [2022-05-09] mm/damon/sysfs: prohibit multiple physical address space monitoring targets (sj@kernel.org)
  + [ec345017d102] [2022-05-09] mm/damon/vaddr: remove damon_va_apply_three_regions() (sj@kernel.org)
  + [484f4cdd74cc] [2022-05-09] mm/damon/vaddr: move 'damon_set_regions()' to core (sj@kernel.org)
  + [5ad10e2597e9] [2022-05-09] mm/damon/vaddr: generalize damon_va_apply_three_regions() (sj@kernel.org)
  + [1fdaf98a3f37] [2022-05-09] mm/damon/core: finish kdamond as soon as any callback returns an error (sj@kernel.org)
  + [7e81688fb618] [2022-05-09] mm/damon/core: add a new callback for watermarks checks (sj@kernel.org)
  + [d74b409420f9] [2022-05-09] Docs/{ABI,admin-guide}/damon: update for fixed virtual address ranges monitoring (sj@kernel.org)
  + [d31af7683cf9] [2022-05-09] mm/damon/sysfs: support fixed virtual address ranges monitoring (sj@kernel.org)
  + [127ab70a5f9e] [2022-05-09] mm/damon/vaddr: register a damon_operations for fixed virtual address ranges monitoring (sj@kernel.org)
  + [24a550a52d1c] [2022-05-09] Docs/{ABI,admin-guide}/damon: document 'avail_operations' sysfs file (sj@kernel.org)
  + [5f9f7c8454b7] [2022-05-09] selftets/damon/sysfs: test existence and permission of avail_operations (sj@kernel.org)
  + [2bf65a2f2d2f] [2022-05-09] mm/damon/sysfs: add a file for listing available monitoring ops (sj@kernel.org)
  + [c1a831a3063e] [2022-05-09] mm/damon/core: add a function for damon_operations registration checks (sj@kernel.org)
  + [0c3f2fe1a192] [2022-04-29] mm/damon/reclaim: fix the timer always stays active (tuhailong@gmail.com)
  + [454217edf015] [2022-04-29] mm/damon: remove unnecessary type castings (yuzhe@nfschina.com)
  + [68dbe96af1bd] [2022-04-29] mm/damon/core-test: add a kunit test case for ops registration (sj@kernel.org)
  + [71a3a4a668ab] [2022-04-29] damon: vaddr-test: tweak code to make the logic clearer (xiam0nd.tong@gmail.com)
  + [40f86c1bc8d9] [2022-03-22] Docs/ABI/testing: add DAMON sysfs interface ABI document (sj@kernel.org)
  + [9972dd4b50b5] [2022-04-01] mm/damon: prevent activated scheme from sleeping by deactivated schemes (tome01@ajou.ac.kr)
  + [b1f0c3039d9a] [2022-03-22] mm/damon/sysfs: remove repeat container_of() in damon_sysfs_kdamond_release() (xhao@linux.alibaba.com)
  + [6d2326745c8c] [2022-03-22] Docs/admin-guide/mm/damon/usage: document DAMON sysfs interface (sj@kernel.org)
  + [cba0a0582950] [2022-03-22] selftests/damon: add a test for DAMON sysfs interface (sj@kernel.org)
  + [079def93a66e] [2022-03-22] mm/damon/sysfs: support DAMOS stats (sj@kernel.org)
  + [26121f536db4] [2022-03-22] mm/damon/sysfs: support DAMOS watermarks (sj@kernel.org)
  + [74086930a9e4] [2022-03-22] mm/damon/sysfs: support schemes prioritization (sj@kernel.org)
  + [8403cfe57ec1] [2022-03-22] mm/damon/sysfs: support DAMOS quotas (sj@kernel.org)
  + [331dbea57785] [2022-03-22] mm/damon/sysfs: support DAMON-based Operation Schemes (sj@kernel.org)
  + [a0733734be2e] [2022-03-22] mm/damon/sysfs: support the physical address space monitoring (sj@kernel.org)
  + [60f5de04f58f] [2022-03-22] mm/damon/sysfs: link DAMON for virtual address spaces monitoring (sj@kernel.org)
  + [64a971a82e95] [2022-03-22] mm/damon: implement a minimal stub for sysfs-based DAMON interface (sj@kernel.org)
  + [aee716657b37] [2022-03-22] mm/damon/core: add number of each enum type values (sj@kernel.org)
  + [6adebb94662c] [2022-03-22] mm/damon/core: allow non-exclusive DAMON start/stop (sj@kernel.org)
  + [9ec00891935a] [2022-03-22] Docs/damon: update outdated term 'regions update interval' (sj@kernel.org)
  + [1f370371164b] [2022-03-22] mm/damon: remove unnecessary CONFIG_DAMON option (tangmeng@uniontech.com)
  + [483f19ff0b35] [2022-03-22] mm/damon/paddr,vaddr: remove damon_{p,v}a_{target_valid,set_operations}() (sj@kernel.org)
  + [bcb5993a6ac8] [2022-03-22] mm/damon/dbgfs-test: fix is_target_id() change (sj@kernel.org)
  + [4465c95d259e] [2022-03-22] mm/damon/dbgfs: use operations id for knowing if the target has pid (sj@kernel.org)
  + [539324602395] [2022-03-22] mm/damon/dbgfs: use damon_select_ops() instead of damon_{v,p}a_set_operations() (sj@kernel.org)
  + [645fb3e2ec6f] [2022-03-22] mm/damon/reclaim: use damon_select_ops() instead of damon_{v,p}a_set_operations() (sj@kernel.org)
  + [1a01eefe4919] [2022-03-22] mm/damon/paddr,vaddr: register themselves to DAMON in subsys_initcall (sj@kernel.org)
  + [df4fa4e51854] [2022-03-22] mm/damon: let monitoring operations can be registered and selected (sj@kernel.org)
  + [d96aefee3531] [2022-03-22] mm/damon: rename damon_primitives to damon_operations (sj@kernel.org)
  + [f46398b98438] [2022-03-22] mm/damon: remove redundant page validation (baolin.wang@linux.alibaba.com)
  + [3977702dc2d4] [2022-03-22] mm/damon: remove the target id concept (sj@kernel.org)
  + [854387c9174a] [2022-03-22] mm/damon/core: move damon_set_targets() into dbgfs (sj@kernel.org)
  + [46e86313dcd8] [2022-03-22] Docs/admin-guide/mm/damon/usage: update for changed initail_regions file input (sj@kernel.org)
  + [10ead3eb2cd8] [2022-03-22] mm/damon/dbgfs/init_regions: use target index instead of target id (sj@kernel.org)
  + [6cd8621e50b8] [2022-03-16] mm/damon: minor cleanup for damon_pa_young (linmiaohe@huawei.com)
  + [e94710d4a755] [2022-01-14] mm/damon: hide kernel pointer from tracepoint event (sj@kernel.org)
  + [f67c2b87a04e] [2022-01-14] mm/damon/vaddr: hide kernel pointer from damon_va_three_regions() failure log (sj@kernel.org)
  + [0878d8fb04ba] [2022-01-14] mm/damon/vaddr: use pr_debug() for damon_va_three_regions() failure logging (sj@kernel.org)
  + [696b9108e028] [2022-01-14] mm/damon/dbgfs: remove an unnecessary variable (sj@kernel.org)
  + [1e11ed4202d5] [2022-01-14] mm/damon: move the implementation of damon_insert_region to damon.h (guoqing.jiang@linux.dev)
  + [30cea43a5a31] [2022-01-14] mm/damon: add access checking for hugetlb pages (baolin.wang@linux.alibaba.com)
  + [d99b0fce6dd7] [2022-01-14] Docs/admin-guide/mm/damon/usage: update for schemes statistics (sj@kernel.org)
  + [7689d7f734f8] [2022-01-14] mm/damon/dbgfs: support all DAMOS stats (sj@kernel.org)
  + [c76506d00155] [2022-01-14] Docs/admin-guide/mm/damon/reclaim: document statistics parameters (sj@kernel.org)
  + [64c503912c3c] [2022-01-14] mm/damon/reclaim: provide reclamation statistics (sj@kernel.org)
  + [eb2736720b3a] [2022-01-14] mm/damon/schemes: account how many times quota limit has exceeded (sj@kernel.org)
  + [39c74efbf9bf] [2022-01-14] mm/damon/schemes: account scheme actions that successfully applied (sj@kernel.org)
  + [50f9cb313353] [2022-01-14] mm/damon: remove a mistakenly added comment for a future feature (sj@kernel.org)
  + [35c50786cfb5] [2022-01-14] Docs/admin-guide/mm/damon/usage: update for kdamond_pid and (mk|rm)_contexts (sj@kernel.org)
  + [d5648b1206b3] [2022-01-14] Docs/admin-guide/mm/damon/usage: mention tracepoint at the beginning (sj@kernel.org)
  + [7306568f5f88] [2022-01-14] Docs/admin-guide/mm/damon/usage: remove redundant information (sj@kernel.org)
  + [2e9d9ccd8002] [2022-01-14] Docs/admin-guide/mm/damon/usage: update for scheme quotas and watermarks (sj@kernel.org)
  + [501788cc051b] [2022-01-14] mm/damon: convert macro functions to static inline functions (sj@kernel.org)
  + [caa956263e5e] [2022-01-14] mm/damon: modify damon_rand() macro to static inline function (xhao@linux.alibaba.com)
  + [c2b6e96cef34] [2022-01-14] mm/damon: move damon_rand() definition into damon.h (xhao@linux.alibaba.com)
  + [ee57d392787e] [2022-01-14] mm/damon/schemes: add the validity judgment of thresholds (xhao@linux.alibaba.com)
  + [501d5f4f853c] [2022-01-14] mm/damon/vaddr: remove swap_ranges() and replace it with swap() (hanyihao@vivo.com)
  + [839ce0babb3e] [2022-01-14] mm/damon: remove some unneeded function definitions in damon.h (xhao@linux.alibaba.com)
  + [05a2a9b89c16] [2022-01-14] mm/damon/core: use abs() instead of diff_of() (xhao@linux.alibaba.com)
  + [17eddd494fa9] [2022-01-14] mm/damon: add 'age' of region tracepoint support (xhao@linux.alibaba.com)
  + [546079dbc6f3] [2022-01-14] mm/damon: unified access_check function naming rules (xhao@linux.alibaba.com)
  + [f1a6ce510f26] [2022-08-05] Mitigate unbalanced RETs on vmexit via serialising wrmsr (surajjs@amazon.com)
  + [7d755ba96645] [2022-06-15] ext4: reduce computation of overhead during resize (okiselev@amazon.com)
  + [ad3ab04d99c1] [2022-08-02] ENA: Update to v2.7.4 (shaoyi@amazon.com)
  + [526aad1a2f3c] [2022-06-27] ENA: Update to v2.7.3 (surajjs@amazon.com)
  + [8c73bf4c3cf7] [2022-02-08] sched/fair: Adjust the allowed NUMA imbalance when SD_NUMA spans multiple LLCs (mgorman@techsingularity.net)
  + [f1d8482c3c22] [2022-02-08] sched/fair: Improve consistency of allowed NUMA balance calculations (mgorman@techsingularity.net)
  + [0135ba341b2c] [2022-06-03] enable rfc4106(gcm(aes)) for fips (hailmo@amazon.com)
  + [a4bff0d0aa84] [2022-05-25] mm/migrate: Don't drop mapping lock in unmap_and_move_huge_page() (surajjs@amazon.com)
  + [eca302c2797c] [2022-01-10] bpf, selftests: Add various ringbuf tests with invalid offset (daniel@iogearbox.net)
  + [a3b203a1b04b] [2022-01-05] bpf, selftests: Add verifier test for mem_or_null register with offset. (daniel@iogearbox.net)
  + [ac7c12c133ec] [2021-01-13] selftests/bpf: Add verifier test for PTR_TO_MEM spill (gilad.reti@gmail.com)
  + [3e380f7719e3] [2022-01-13] bpf: Fix ringbuf memory type confusion when passing to helpers (daniel@iogearbox.net)
  + [eda502eac8b1] [2022-01-11] bpf: Fix out of bounds access for ringbuf helpers (daniel@iogearbox.net)
  + [8c60edc9b3a8] [2022-01-10] bpf: Generally fix helper register offset check (daniel@iogearbox.net)
  + [57f499638cd2] [2022-01-14] bpf: Mark PTR_TO_FUNC register initially with zero offset (daniel@iogearbox.net)
  + [2d9c67f6abf2] [2022-01-10] bpf: Generalize check_ctx_reg for reuse with other types (daniel@iogearbox.net)
  + [a8c365dea022] [2021-08-23] iov_iter: track truncated size (asml.silence@gmail.com)
  + [71e140c51ca8] [2022-05-25] Correct read overflow in page touching DMA ops binding (tbarri@amazon.com)
  + [3450f94d2b16] [2022-05-20] lustre: update to AmazonFSxLustreClient v2.10.8-11 (shaoyi@amazon.com)
  + [9d3a22daf250] [2022-04-28] ENA: Update to v2.7.1 (surajjs@amazon.com)
  + [a9aff0c659f9] [2020-12-14] mm/filemap.c: generic_file_buffered_read() now uses find_get_pages_contig (kent.overstreet@gmail.com)
  + [e51c8b577d93] [2020-12-14] mm/filemap/c: break generic_file_buffered_read up into multiple functions (kent.overstreet@gmail.com)
  + [283a6c4a1a5d] [2022-04-18] svm: fix backport of "KVM: X86: Move write_l1_tsc_offset() logic to common code and rename it" (fllinden@amazon.com)
  + [87f11b3f5cb0] [2022-03-23] Revert "lustre: update to AmazonFSxLustreClient v2.12.8-1" (shaoyi@amazon.com)
  + [a2bfedcf6ea9] [2022-03-17] netfilter: nf_tables: validate registers coming from userspace. (pablo@netfilter.org)
  + [f298ae5fd9d1] [2021-08-26] sock: remove one redundant SKB_FRAG_PAGE_ORDER macro (linyunsheng@huawei.com)
  + [98dede546d28] [2021-12-16] bpf/selftests: Test PTR_TO_RDONLY_MEM (haoluo@google.com)
  + [7277fcd3a744] [2021-12-16] bpf: Add MEM_RDONLY for helper args that are pointers to rdonly mem. (haoluo@google.com)
  + [afb34b6defc5] [2021-12-16] bpf: Make per_cpu_ptr return rdonly PTR_TO_MEM. (haoluo@google.com)
  + [295b2323d579] [2021-12-16] bpf: Convert PTR_TO_MEM_OR_NULL to composable types. (haoluo@google.com)
  + [1e4308a64ada] [2021-12-16] bpf: Introduce MEM_RDONLY flag (haoluo@google.com)
  + [34e5da6774a6] [2021-12-16] bpf: Replace PTR_TO_XXX_OR_NULL with PTR_TO_XXX | PTR_MAYBE_NULL (haoluo@google.com)
  + [f24f7cb5a811] [2021-02-13] bpf: Extract nullable reg type conversion into a helper function (me@ubique.spb.ru)
  + [9776d1147933] [2021-12-16] bpf: Replace RET_XXX_OR_NULL with RET_XXX | PTR_MAYBE_NULL (haoluo@google.com)
  + [0cc346889931] [2021-12-16] bpf: Replace ARG_XXX_OR_NULL with ARG_XXX | PTR_MAYBE_NULL (haoluo@google.com)
  + [bded589ace75] [2021-12-16] bpf: Introduce composable reg, ret and arg types. (haoluo@google.com)
  + [5ac1f8ab7de4] [2020-11-06] bpf: Implement get_current_task_btf and RET_PTR_TO_BTF_ID (kpsingh@google.com)
  + [93e50ecc2621] [2022-02-05] Add out-of-tree smartpqi driver Version 2.1.14-030 as external module under drivers/amazon (shaoyi@amazon.com)
  + [1e7c6c0ba656] [2020-11-20] sched: Limit the amount of NUMA imbalance that can exist at fork time (mgorman@techsingularity.net)
  + [c21600cb7c7a] [2020-11-20] sched/numa: Allow a floating imbalance between NUMA nodes (mgorman@techsingularity.net)
  + [8147f70f71ba] [2020-11-20] sched: Avoid unnecessary calculation of load imbalance at clone time (mgorman@techsingularity.net)
  + [52397b538c78] [2020-11-20] sched/numa: Rename nr_running and break out the magic number (mgorman@techsingularity.net)
  + [0650824fcc99] [2021-12-30] mm/damon/dbgfs: fix 'struct pid' leaks in 'dbgfs_target_ids_write()' (sj@kernel.org)
  + [7121de14c6cb] [2021-12-24] mm/damon/dbgfs: protect targets destructions with kdamond_lock (sj@kernel.org)
  + [dce429b6186e] [2021-12-10] selftests/damon: split test cases (sj@kernel.org)
  + [438d5a42837b] [2021-12-10] selftests/damon: test debugfs file reads/writes with huge count (sj@kernel.org)
  + [27266deae452] [2021-12-10] selftests/damon: test wrong DAMOS condition ranges input (sj@kernel.org)
  + [a977cbcb9fd8] [2021-12-10] selftests/damon: test DAMON enabling with empty target_ids case (sj@kernel.org)
  + [f85554dc9d6a] [2021-12-10] selftests/damon: skip test if DAMON is running (sj@kernel.org)
  + [c0c884bde1ff] [2021-12-10] mm/damon/vaddr-test: remove unnecessary variables (sj@kernel.org)
  + [319150814378] [2021-12-10] mm/damon/vaddr-test: split a test function having >1024 bytes frame size (sj@kernel.org)
  + [6711a41ad879] [2021-12-10] mm/damon/vaddr: remove an unnecessary warning message (sj@kernel.org)
  + [cb30ead837cf] [2021-12-10] mm/damon/core: remove unnecessary error messages (sj@kernel.org)
  + [12236dfc2857] [2021-12-10] mm/damon/dbgfs: remove an unnecessary error message (sj@kernel.org)
  + [a6cb269357c3] [2021-12-10] mm/damon/core: use better timer mechanisms selection threshold (sj@kernel.org)
  + [7e79abceb8f2] [2021-12-10] mm/damon/core: fix fake load reports due to uninterruptible sleeps (sj@kernel.org)
  + [40a3569ec71b] [2021-12-10] timers: implement usleep_idle_range() (sj@kernel.org)
  + [d6775bbc1efd] [2021-10-18] sched: Improve wake_up_all_idle_cpus() take #2 (peterz@infradead.org)
  + [803ae7adc3cc] [2022-03-01] lustre: update to AmazonFSxLustreClient v2.12.8-1 (shaoyi@amazon.com)
  + [4aa0a25afc8b] [2022-02-02] ENA: Update to v2.6.1 (surajjs@amazon.com)
  + [2d296f75ab1a] [2021-12-10] virtio-balloon: optionally report offlined memory ranges (fllinden@amazon.com)
  + [c237ead6a175] [2022-01-06] virtio: add hack to allow pre-mapped scatterlists (fllinden@amazon.com)
  + [bce9e1f0fcac] [2022-01-06] mm: add offline page reporting interface (fllinden@amazon.com)
  + [ca7a4020c1a1] [2021-12-09] drivers/base/memory: use MHP_MEMMAP_ON_MEMORY from the probe interface (fllinden@amazon.com)
  + [3e176f94084b] [2021-06-04] drivers/base/memory: fix trying offlining memory blocks with memory holes on aarch64 (david@redhat.com)
  + [13e4846b8861] [2021-05-04] arm64/Kconfig: introduce ARCH_MHP_MEMMAP_ON_MEMORY_ENABLE (osalvador@suse.de)
  + [45de4d05795a] [2021-05-04] x86/Kconfig: introduce ARCH_MHP_MEMMAP_ON_MEMORY_ENABLE (osalvador@suse.de)
  + [5771207fdca6] [2021-05-04] mm,memory_hotplug: add kernel boot option to enable memmap_on_memory (osalvador@suse.de)
  + [9477d67acd99] [2021-05-04] acpi,memhotplug: enable MHP_MEMMAP_ON_MEMORY when supported (osalvador@suse.de)
  + [3a118b8614b6] [2021-05-04] mm,memory_hotplug: allocate memmap from the added memory range (osalvador@suse.de)
  + [ea42586a032a] [2021-05-04] mm,memory_hotplug: factor out adjusting present pages into adjust_present_page_count() (david@redhat.com)
  + [eba7082d08d5] [2021-05-04] mm,memory_hotplug: relax fully spanned sections check (osalvador@suse.de)
  + [82658afdb5bd] [2021-05-04] drivers/base/memory: introduce memory_block_{online,offline} (osalvador@suse.de)
  + [974f2c15d1e0] [2022-01-11] lustre: update to AmazonFSxLustreClient v2.10.8-10 (shaoyi@amazon.com)
  + [b0cf3f63a0b7] [2021-12-07] ena: Update to 2.6.0 (yishache@amazon.com)
  + [05e26125442d] [2021-11-18] mm/damon/dbgfs: fix missed use of damon_dbgfs_lock (sj@kernel.org)
  + [3b9f681cf78e] [2021-11-18] mm/damon/dbgfs: use '__GFP_NOWARN' for user-specified size buffer allocation (sj@kernel.org)
  + [6de6a5a61e70] [2021-11-05] mm/damon: remove return value from before_terminate callback (changbin.du@gmail.com)
  + [c2bf4c250d25] [2021-11-05] mm/damon: fix a few spelling mistakes in comments and a pr_debug message (colin.i.king@googlemail.com)
  + [c9b2c338846f] [2021-11-05] mm/damon: simplify stop mechanism (changbin.du@gmail.com)
  + [74b63f7608c1] [2021-11-05] Docs/admin-guide/mm/damon/start: simplify the content (sj@kernel.org)
  + [fd4ef56bbe88] [2021-11-05] Docs/admin-guide/mm/damon/start: fix a wrong link (sj@kernel.org)
  + [f9e459e46a13] [2021-11-05] Docs/admin-guide/mm/damon/start: fix wrong example commands (sj@kernel.org)
  + [c9c3640d9e49] [2021-11-05] mm/damon/dbgfs: add adaptive_targets list check before enable monitor_on (xhao@linux.alibaba.com)
  + [45308b167bc0] [2021-11-05] mm/damon: remove unnecessary variable initialization (xhao@linux.alibaba.com)
  + [7211817627fc] [2021-11-05] Documentation/admin-guide/mm/damon: add a document for DAMON_RECLAIM (sj@kernel.org)
  + [c00ce8c71b1b] [2021-11-05] mm/damon: introduce DAMON-based Reclamation (DAMON_RECLAIM) (sj@kernel.org)
  + [67526bc41ec5] [2021-11-05] selftests/damon: support watermarks (sj@kernel.org)
  + [c777c8ee62fa] [2021-11-05] mm/damon/dbgfs: support watermarks (sj@kernel.org)
  + [82f42670bffa] [2021-11-05] mm/damon/schemes: activate schemes based on a watermarks mechanism (sj@kernel.org)
  + [560bc61a1270] [2021-11-05] tools/selftests/damon: update for regions prioritization of schemes (sj@kernel.org)
  + [62acec41bfa1] [2021-11-05] mm/damon/dbgfs: support prioritization weights (sj@kernel.org)
  + [95a0911611d9] [2021-11-05] mm/damon/vaddr,paddr: support pageout prioritization (sj@kernel.org)
  + [607280bb035b] [2021-11-05] mm/damon/schemes: prioritize regions within the quotas (sj@kernel.org)
  + [8a3fb291509d] [2021-11-05] mm/damon/selftests: support schemes quotas (sj@kernel.org)
  + [3076b2c629cb] [2021-11-05] mm/damon/dbgfs: support quotas of schemes (sj@kernel.org)
  + [876b41387355] [2021-11-05] mm/damon/schemes: implement time quota (sj@kernel.org)
  + [40750dd0ec9d] [2021-11-05] mm/damon/schemes: skip already charged targets and regions (sj@kernel.org)
  + [42c1c4a72f9a] [2021-11-05] mm/damon/schemes: implement size quota for schemes application speed control (sj@kernel.org)
  + [7ecbcf683257] [2021-11-05] mm/damon/paddr: support the pageout scheme (sj@kernel.org)
  + [92c58c979482] [2021-11-05] mm/damon/dbgfs: remove unnecessary variables (rongwei.wang@linux.alibaba.com)
  + [617f0314445d] [2021-11-05] mm/damon/vaddr: constify static mm_walk_ops (rikard.falkeborn@gmail.com)
  + [00baa996cc9f] [2021-11-05] Docs/DAMON: document physical memory monitoring support (sj@kernel.org)
  + [58f94087eac0] [2021-11-05] mm/damon/dbgfs: support physical memory monitoring (sj@kernel.org)
  + [a22aedea6b8a] [2021-11-05] mm/damon: implement primitives for physical address space monitoring (sj@kernel.org)
  + [f3fa23251441] [2021-11-05] mm/damon/vaddr: separate commonly usable functions (sj@kernel.org)
  + [d1ee24980496] [2021-11-05] Docs/admin-guide/mm/damon: document 'init_regions' feature (sj@kernel.org)
  + [77af9732d676] [2021-11-05] mm/damon/dbgfs-test: add a unit test case for 'init_regions' (sj@kernel.org)
  + [ecdf3ff37632] [2021-11-05] mm/damon/dbgfs: allow users to set initial monitoring target regions (sj@kernel.org)
  + [3037d79ee1a9] [2021-11-05] Docs/admin-guide/mm/damon: document DAMON-based Operation Schemes (sj@kernel.org)
  + [559b2805c5c9] [2021-11-05] selftests/damon: add 'schemes' debugfs tests (sj@kernel.org)
  + [296ff9f9cb3f] [2021-11-05] mm/damon/schemes: implement statistics feature (sj@kernel.org)
  + [b0ee5d05ed64] [2021-11-05] mm/damon/dbgfs: support DAMON-based Operation Schemes (sj@kernel.org)
  + [5b6be5ded0cd] [2021-11-05] mm/damon/vaddr: support DAMON-based Operation Schemes (sj@kernel.org)
  + [0727fc617f73] [2021-11-05] mm/damon/core: implement DAMON-based Operation Schemes (DAMOS) (sj@kernel.org)
  + [620be841c192] [2021-11-05] mm/damon/core: account age of target regions (sj@kernel.org)
  + [43957d859ba2] [2021-11-05] mm/damon/core: nullify pointer ctx->kdamond with a NULL (colin.king@canonical.com)
  + [a3ecbadabf09] [2021-11-05] mm/damon: needn't hold kdamond_lock to print pid of kdamond (changbin.du@gmail.com)
  + [f2313acf88cc] [2021-11-05] mm/damon: remove unnecessary do_exit() from kdamond (changbin.du@gmail.com)
  + [947094bd8d27] [2021-11-05] mm/damon/core: print kdamond start log in debug mode only (sj@kernel.org)
  + [b6138f91d845] [2021-11-05] include/linux/damon.h: fix kernel-doc comments for 'damon_callback' (sjpark@amazon.de)
  + [7a90d446e4c1] [2021-11-05] mm/damon: grammar s/works/work/ (geert@linux-m68k.org)
  + [f09ce4acf303] [2021-10-28] mm/damon/core-test: fix wrong expectations for 'damon_split_regions_of()' (sj@kernel.org)
  + [09b184478b00] [2021-09-24] mm/damon: don't use strnlen() with known-bogus source length (kilobyte@angband.pl)
  + [4ae165224198] [2021-09-07] MAINTAINERS: update for DAMON (sjpark@amazon.de)
  + [624e3cc73e6d] [2021-09-07] mm/damon: add user space selftests (sjpark@amazon.de)
  + [4ff61f348d98] [2021-09-07] mm/damon: add kunit tests (sjpark@amazon.de)
  + [a8298eb6e1f9] [2021-09-07] Documentation: add documents for DAMON (sjpark@amazon.de)
  + [ebb7d80aa310] [2021-11-23] Revert "mm/damon: grammar s/works/work/" (sjpark@amazon.de)
  + [5a35fbf69bc8] [2021-11-23] Revert "include/linux/damon.h: fix kernel-doc comments for 'damon_callback'" (sjpark@amazon.de)
  + [87d0ca916796] [2021-11-23] Revert "mm/damon/core: print kdamond start log in debug mode only" (sjpark@amazon.de)
  + [07138f96141e] [2021-11-23] Revert "mm/damon: remove unnecessary do_exit() from kdamond" (sjpark@amazon.de)
  + [52437ea3f86e] [2021-11-23] Revert "mm/damon: needn't hold kdamond_lock to print pid of kdamond" (sjpark@amazon.de)
  + [261a7c118488] [2021-11-23] Revert "mm/damon/core: nullify pointer ctx->kdamond with a NULL" (sjpark@amazon.de)
  + [ee366f26f305] [2021-11-23] Revert "mm/damon/core: account age of target regions" (sjpark@amazon.de)
  + [95a8be55e0bc] [2021-11-23] Revert "mm/damon/core: implement DAMON-based Operation Schemes (DAMOS)" (sjpark@amazon.de)
  + [e8d06cd052c2] [2021-11-23] Revert "mm/damon/vaddr: support DAMON-based Operation Schemes" (sjpark@amazon.de)
  + [8a7a0e8c69d7] [2021-11-23] Revert "mm/damon/dbgfs: support DAMON-based Operation Schemes" (sjpark@amazon.de)
  + [c27dfaa0beec] [2021-11-23] Revert "mm/damon/schemes: implement statistics feature" (sjpark@amazon.de)
  + [9841abb5eac8] [2021-11-23] Revert "mm/damon/dbgfs: Implement recording feature" (sjpark@amazon.de)
  + [80fa4a9ba4e4] [2021-11-23] Revert "damon/dbgfs: Allow users to set initial monitoring target regions" (sjpark@amazon.de)
  + [22bc4fa7a5b6] [2021-11-23] Revert "mm/damon/vaddr: Separate commonly usable functions" (sjpark@amazon.de)
  + [76e82e458f8b] [2021-11-23] Revert "mm/damon: Implement primitives for physical address space monitoring" (sjpark@amazon.de)
  + [e4edae77b2d3] [2021-11-23] Revert "damon/dbgfs: Support physical memory monitoring" (sjpark@amazon.de)
  + [f35ffb50702b] [2021-11-23] Revert "mm/damon/paddr: Separate commonly usable functions" (sjpark@amazon.de)
  + [ae25a3f3ac94] [2021-11-23] Revert "mm/damon: Introduce arbitrary target type" (sjpark@amazon.de)
  + [b464a3b781f6] [2021-11-23] Revert "mm/damon: Implement primitives for page granularity idleness monitoring" (sjpark@amazon.de)
  + [9322672d9818] [2021-11-23] Revert "mm/damon/paddr: Support the pageout scheme" (sjpark@amazon.de)
  + [50d65b86f6ea] [2021-11-23] Revert "mm/damon/damos: Make schemes aggressiveness controllable" (sjpark@amazon.de)
  + [0d4679c3056a] [2021-11-23] Revert "damon/core/schemes: Skip already charged targets and regions" (sjpark@amazon.de)
  + [cafb75d69f73] [2021-11-23] Revert "mm/damon/schemes: Implement time quota" (sjpark@amazon.de)
  + [5b2a08c6bc37] [2021-11-23] Revert "mm/damon/dbgfs: Support schemes' time/IO quotas" (sjpark@amazon.de)
  + [2a0c8f3d2f27] [2021-11-23] Revert "mm/damon/schemes: Prioritize regions within the quotas" (sjpark@amazon.de)
  + [cf5a398df90d] [2021-11-23] Revert "mm/damon/vaddr,paddr: Support pageout prioritization" (sjpark@amazon.de)
  + [024e33964a14] [2021-11-23] Revert "mm/damon/dbgfs: Support prioritization weights" (sjpark@amazon.de)
  + [a8a695586f5b] [2021-11-23] Revert "mm/damon/schemes: Activate schemes based on a watermarks mechanism" (sjpark@amazon.de)
  + [ce40c4502513] [2021-11-23] Revert "mm/damon/dbgfs: Support watermarks" (sjpark@amazon.de)
  + [595c662af096] [2021-11-23] Revert "mm/damon: Introduce DAMON-based reclamation" (sjpark@amazon.de)
  + [bbe11de074d3] [2021-12-23] Revert "PCI/MSI: Enforce that MSI-X table entry is masked for update" (fllinden@amazon.com)
  + [75674836b071] [2021-02-10] nvme: add 48-bit DMA address quirk for Amazon NVMe controllers (sironi@amazon.de)
  + [da9787394d97] [2021-09-07] ipc: replace costly bailout check in sysvipc_find_ipc() (aquini@redhat.com)
  + [d23a305f130b] [2021-11-02] arm64: module: Use aarch64_insn_write when updating relocations later on (surajjs@amazon.com)
  + [33dba71d154a] [2021-11-01] linux/kvm.h: Fix KVM_CAP_PTP_KVM numbering to match upstream (surajjs@amazon.com)
  + [023cc2536718] [2021-10-26] efa: update to 1.14.1 (yishache@amazon.com)
  + [b759ed766dae] [2021-10-15] ARM64: kvm: vgic-v3-sr: Bug when trying to read invalid APRs (surajjs@amazon.com)
  + [a4fbf9a0b462] [2021-09-29] sched,livepatch: Use wake_up_if_idle() (peterz@infradead.org)
  + [8df13e85012b] [2021-09-29] sched: Simplify wake_up_*idle*() (peterz@infradead.org)
  + [e33f43c1f1c4] [2021-05-03] arm64: implement live patching (surajjs@amazon.com)
  + [e6f3bb382fbc] [2021-01-20] arm64: kvm: Annotate stack state for guest enter/exit code (jthierry@redhat.com)
  + [a268f17f81bc] [2021-01-20] arm64: entry: Annotate code switching to tasks (jthierry@redhat.com)
  + [0088711a4493] [2021-01-20] arm64: entry: Add annotation when switching to/from the irq stack (jthierry@redhat.com)
  + [7a2be0dcb4e2] [2021-01-20] arm64: entry: Annotate valid stack in kernel entry (jthierry@redhat.com)
  + [45c30f98d029] [2021-01-20] arm64: Annotate ASM symbols with unknown stack state (jthierry@redhat.com)
  + [df5ba7cf4312] [2020-04-03] objtool: arm64: Add unwind_hint support (jthierry@redhat.com)
  + [d89ab996f64e] [2020-09-17] arm64: crypto: Mark data in code sections (jthierry@redhat.com)
  + [064093f85371] [2020-03-29] arm64: proc: Mark constant as data (jthierry@redhat.com)
  + [a74beb913849] [2020-03-29] arm64: head: Mark constants as data (jthierry@redhat.com)
  + [53029a38cb81] [2020-03-29] arm64: efi-header: Mark efi header as data (jthierry@redhat.com)
  + [541af4232b7f] [2020-11-17] arm64: head: tidy up the Image header definition (ardb@kernel.org)
  + [3b6bb9232867] [2020-11-17] arm64/head: avoid symbol names pointing into first 64 KB of kernel image (ardb@kernel.org)
  + [8c5b836e722f] [2020-08-31] objtool: check: Support data in text section (jthierry@redhat.com)
  + [d63987df743e] [2020-03-29] arm64: Change symbol annotations (jthierry@redhat.com)
  + [d90efac39315] [2020-11-13] arm64: head.S: rename el2_setup -> init_kernel_el (mark.rutland@arm.com)
  + [05c103ea84c0] [2020-04-03] arm64: entry: Mark tramp_exit as local symbols (jthierry@redhat.com)
  + [232c2c66ea5e] [2019-12-02] arm64: Move constant to rodata (jthierry@redhat.com)
  + [19aee7534b69] [2020-08-31] arm64: sleep: Properly set frame pointer before call (jthierry@redhat.com)
  + [b78ee17feaa3] [2020-09-17] arm64: crypto: Remove unnecessary stackframe (jthierry@redhat.com)
  + [ff49f76e7041] [2020-03-27] arm64: entry: Compile out unnecessary symbols (jthierry@redhat.com)
  + [e39712bbf374] [2019-12-02] arm64: Mark sigreturn32.o as containing non standard code (jthierry@redhat.com)
  + [efbb60da8811] [2019-08-16] arm64: kernel: Add exception on kuser32 to prevent stack analysis (raphael.gault@arm.com)
  + [c168514b6f9a] [2021-01-15] arm64: Skip validation of qcom_link_stack_sanitization (jthierry@redhat.com)
  + [41fe7348cf79] [2020-09-07] arm64: Add intra-function call annotations (jthierry@redhat.com)
  + [07af806f9cd0] [2020-03-31] arm64: kgdb: Mark code following kgdb brk as reachable (jthierry@redhat.com)
  + [c5611d1c3e07] [2020-03-18] arm64: bug: Add reachable annotation to warning macros (jthierry@redhat.com)
  + [969a63ddc357] [2019-08-16] objtool: arm64: Enable stack validation for arm64 (raphael.gault@arm.com)
  + [aa82ba284ff9] [2020-08-28] objtool: arm64: Ignore replacement section for alternative callback (jthierry@redhat.com)
  + [d8b9e08f30bd] [2020-03-31] objtool: arm64: Handle supported relocations in alternatives (jthierry@redhat.com)
  + [a7fd722d5118] [2021-01-19] objtool: arm64: Accept padding in code sections (jthierry@redhat.com)
  + [8f2b954d20d2] [2021-01-19] objtool: arm64: Decode LDR instructions (jthierry@redhat.com)
  + [5e63c3004135] [2020-09-09] objtool: arm64: Decode load/store instructions (jthierry@redhat.com)
  + [2c410dbeb221] [2020-09-09] objtool: arm64: Decode other system instructions (jthierry@redhat.com)
  + [984b36473e22] [2020-09-09] objtool: arm64: Decode jump and call related instructions (jthierry@redhat.com)
  + [27958183d359] [2020-09-09] objtool: arm64: Decode add/sub instructions (jthierry@redhat.com)
  + [61b45610ccb7] [2020-09-09] objtool: arm64: Add base definition for arm64 backend (jthierry@redhat.com)
  + [50f85b6a28b0] [2020-09-14] tools: bug: Remove duplicate definition (jthierry@redhat.com)
  + [eca44b6b6b42] [2020-02-15] tools: arm64: Make aarch64 instruction decoder available to tools (jthierry@redhat.com)
  + [5c56486c17a6] [2020-02-15] tools: Add some generic functions and headers (jthierry@redhat.com)
  + [d08bc49673c8] [2020-02-14] arm64: insn: Add load/store decoding helpers (jthierry@redhat.com)
  + [e3c66effb7c9] [2020-02-14] arm64: insn: Add some opcodes to instruction decoder (jthierry@redhat.com)
  + [c0497f50d710] [2020-02-19] arm64: insn: Add barrier encodings (jthierry@redhat.com)
  + [ed21558c82b6] [2021-02-10] arm64: insn: Add SVE instruction class (jthierry@redhat.com)
  + [00e5b704bf0f] [2021-02-10] arm64: Move instruction encoder/decoder under lib/ (jthierry@redhat.com)
  + [38f649e0f061] [2021-02-10] arm64: insn: Reduce header dependencies of instruction decoder (jthierry@redhat.com)
  + [03b5ec866ffa] [2021-02-10] arm64: Move patching utilities out of instruction encoding/decoding (jthierry@redhat.com)
  + [dbf7472688ae] [2021-02-26] objtool: Parse options from OBJTOOL_ARGS (peterz@infradead.org)
  + [6e7f49297a5f] [2021-02-26] objtool: Collate parse_options() users (peterz@infradead.org)
  + [f94540261811] [2021-02-26] objtool: Add --backup (peterz@infradead.org)
  + [3a9fadcdc3eb] [2021-02-12] objtool,x86: More ModRM sugar (peterz@infradead.org)
  + [58afb7871853] [2021-02-10] objtool,x86: Rewrite ADD/SUB/AND (peterz@infradead.org)
  + [3a3320f7d9fd] [2021-02-10] objtool,x86: Support %riz encodings (peterz@infradead.org)
  + [ab7aec1460a1] [2021-02-09] objtool,x86: Simplify register decode (peterz@infradead.org)
  + [d6a55fdf9bcd] [2021-02-09] objtool,x86: Rewrite LEA decode (peterz@infradead.org)
  + [536823d0d988] [2021-02-09] objtool,x86: Renumber CFI_reg (peterz@infradead.org)
  + [6e03437f9658] [2021-02-11] objtool: Allow UNWIND_HINT to suppress dodgy stack modifications (peterz@infradead.org)
  + [7e9462b30a50] [2020-06-30] arm64: alternatives: Split up alternative.h (will@kernel.org)
  + [874d942b8f5e] [2020-10-26] arm64: uaccess: move uao_* alternatives to asm-uaccess.h (mark.rutland@arm.com)
  + [98c0f2890906] [2021-03-08] objtool,x86: Fix uaccess PUSHF/POPF validation (peterz@infradead.org)
  + [9961fedbe29b] [2020-09-30] objtool: Split noinstr validation from --vmlinux (samitolvanen@google.com)
  + [9ec29a69878f] [2020-07-17] objtool: Don't autodetect vmlinux.o (samitolvanen@google.com)
  + [522f11a569ea] [2020-08-06] objtool: Add a pass for generating __mcount_loc (peterz@infradead.org)
  + [ce919b26f392] [2021-02-18] objtool: Fix stack-swizzle for FRAME_POINTER=y (peterz@infradead.org)
  + [0565d6c4a729] [2021-02-03] objtool: Support stack-swizzle (peterz@infradead.org)
  + [dcbd0d6358aa] [2021-02-03] objtool,x86: Additionally decode: mov %rsp, (%reg) (peterz@infradead.org)
  + [fc178b1dd687] [2021-01-21] x86/power: Support objtool validation in hibernate_asm_64.S (jpoimboe@redhat.com)
  + [31ecc98c1947] [2021-01-21] x86/power: Move restore_registers() to top of the file (jpoimboe@redhat.com)
  + [83ee2f2c5770] [2021-01-21] x86/acpi: Support objtool validation in wakeup_64.S (jpoimboe@redhat.com)
  + [b13a2250bf82] [2021-01-21] x86/ftrace: Support objtool vmlinux.o validation in ftrace_64.S (jpoimboe@redhat.com)
  + [0f81610ab426] [2021-01-21] objtool: Add asm version of STACK_FRAME_NON_STANDARD (jpoimboe@redhat.com)
  + [f17851190235] [2020-11-13] objtool: Rework header include paths (gor@linux.ibm.com)
  + [10fe1ce3e21a] [2020-11-13] objtool: Fix x86 orc generation on big endian cross-compiles (gor@linux.ibm.com)
  + [f1606d7882e5] [2020-11-13] objtool: Fix reloc generation on big endian cross-compiles (schwidefsky@de.ibm.com)
  + [10a63b9c8069] [2020-10-14] objtool: Make SP memory operation match PUSH/POP semantics (jthierry@redhat.com)
  + [efe0152e797e] [2020-10-14] objtool: Support addition to set CFA base (jthierry@redhat.com)
  + [5e3d68c4613e] [2020-10-14] objtool: Fully validate the stack frame (jthierry@redhat.com)
  + [154a1c86cdd3] [2020-04-29] rbtree: Add generic add and find helpers (peterz@infradead.org)
  + [9641d032c936] [2021-03-15] arm64: Implement arch_stack_walk_reliable() (madvenka@linux.microsoft.com)
  + [6cf3eaf47346] [2021-05-26] arm64: Create a list of SYM_CODE functions, check return PC against list (madvenka@linux.microsoft.com)
  + [af8adc5dbc6c] [2021-05-26] arm64: Introduce stack trace reliability checks in the unwinder (madvenka@linux.microsoft.com)
  + [097e5f23a8a6] [2021-05-10] arm64: Implement stack trace termination record (madvenka@linux.microsoft.com)
  + [793ce5e3d479] [2021-04-29] arm64: stacktrace: restore terminal records (mark.rutland@arm.com)
  + [997f9c54c7cb] [2021-02-24] arm64: stacktrace: Report when we reach the end of the stack (broonie@kernel.org)
  + [0633a006ea08] [2021-01-13] arm64: remove EL0 exception frame record (mark.rutland@arm.com)
  + [eab88b8225a4] [2021-01-12] arm64: rename S_FRAME_SIZE to PT_REGS_SIZE (Jianlin.Lv@arm.com)
  + [790111c276c0] [2020-12-11] arm64: disable recordmcount with DYNAMIC_FTRACE_WITH_REGS (samitolvanen@google.com)
  + [14d43740b6db] [2020-11-19] arm64: vmlinux.lds.S: Drop redundant *.init.rodata.* (tangyouling@loongson.cn)
  + [23b897c1d372] [2020-06-30] arm64: lto: Strengthen READ_ONCE() to acquire when CONFIG_LTO=y (will@kernel.org)
  + [4da76d4f1769] [2021-05-25] mm/damon: Introduce DAMON-based reclamation (sj@kernel.org)
  + [2c83a75d6a37] [2021-07-12] mm/damon/dbgfs: Support watermarks (sj@kernel.org)
  + [c4b41ed095b8] [2021-07-12] mm/damon/schemes: Activate schemes based on a watermarks mechanism (sj@kernel.org)
  + [8055fedaea18] [2021-07-12] mm/damon/dbgfs: Support prioritization weights (sj@kernel.org)
  + [1fbaf3612b0d] [2021-06-25] mm/damon/vaddr,paddr: Support pageout prioritization (sj@kernel.org)
  + [5a2674c995cc] [2021-07-12] mm/damon/schemes: Prioritize regions within the quotas (sj@kernel.org)
  + [95e8ff514e0f] [2021-05-26] mm/damon/dbgfs: Support schemes' time/IO quotas (sj@kernel.org)
  + [0f8f7a391c3a] [2021-07-12] mm/damon/schemes: Implement time quota (sj@kernel.org)
  + [badaf84b0bf4] [2021-07-12] damon/core/schemes: Skip already charged targets and regions (sj@kernel.org)
  + [48f1bef411f3] [2021-05-06] mm/damon/damos: Make schemes aggressiveness controllable (sj@kernel.org)
  + [feeedbf8c094] [2021-09-09] mm/damon/paddr: Support the pageout scheme (sj@kernel.org)
  + [372438a829ea] [2021-03-30] mm/damon: Implement primitives for page granularity idleness monitoring (sj@kernel.org)
  + [1c85282558b7] [2021-02-02] mm/damon: Introduce arbitrary target type (sj@kernel.org)
  + [50d2d7fa43b8] [2021-09-09] mm/damon/paddr: Separate commonly usable functions (sj@kernel.org)
  + [b918c8cd6779] [2020-07-21] damon/dbgfs: Support physical memory monitoring (sj@kernel.org)
  + [c52bb3c099ac] [2020-12-10] mm/damon: Implement primitives for physical address space monitoring (sj@kernel.org)
  + [2b13d073766b] [2021-10-08] mm/damon/vaddr: Separate commonly usable functions (sjpark@amazon.de)
  + [e4bbc615a908] [2020-07-21] damon/dbgfs: Allow users to set initial monitoring target regions (sj@kernel.org)
  + [65fcf9006e27] [2021-10-01] mm/damon/dbgfs: Implement recording feature (sj@kernel.org)
  + [f01d7178dbf9] [2021-10-05] mm/damon/schemes: implement statistics feature (sj@kernel.org)
  + [da00daf843dd] [2021-10-05] mm/damon/dbgfs: support DAMON-based Operation Schemes (sj@kernel.org)
  + [bad00d3bcf1d] [2021-10-05] mm/damon/vaddr: support DAMON-based Operation Schemes (sj@kernel.org)
  + [8019ae86bdde] [2021-10-05] mm/damon/core: implement DAMON-based Operation Schemes (DAMOS) (sj@kernel.org)
  + [3d7f0f6abc76] [2021-10-05] mm/damon/core: account age of target regions (sj@kernel.org)
  + [09fe62c7a3b3] [2021-10-05] mm/damon/core: nullify pointer ctx->kdamond with a NULL (colin.king@canonical.com)
  + [beb80e196b1a] [2021-10-05] mm/damon: needn't hold kdamond_lock to print pid of kdamond (changbin.du@gmail.com)
  + [83a7a7273112] [2021-10-05] mm/damon: remove unnecessary do_exit() from kdamond (changbin.du@gmail.com)
  + [fb42b1ab843c] [2021-10-05] mm/damon/core: print kdamond start log in debug mode only (sj@kernel.org)
  + [15b21b83b127] [2021-10-05] include/linux/damon.h: fix kernel-doc comments for 'damon_callback' (sjpark@amazon.de)
  + [ef9c059451aa] [2021-10-05] mm/damon: grammar s/works/work/ (geert@linux-m68k.org)
  + [1a69ec2cdf51] [2021-09-07] mm/damon/dbgfs: support multiple contexts (sjpark@amazon.de)
  + [3dfdf7bcdc49] [2021-09-07] mm/damon/dbgfs: export kdamond pid to the user space (sjpark@amazon.de)
  + [f755f08f59a3] [2021-09-07] mm/damon: implement a debugfs-based user space interface (sjpark@amazon.de)
  + [8c54e25d939a] [2021-09-07] mm/damon: add a tracepoint (sjpark@amazon.de)
  + [81ba9884bcf9] [2021-09-07] mm/damon: implement primitives for the virtual memory address spaces (sjpark@amazon.de)
  + [e0e5ac36230d] [2021-09-07] mm/idle_page_tracking: make PG_idle reusable (sjpark@amazon.de)
  + [2eb98e05f1fc] [2021-09-07] mm/damon: adaptively adjust regions (sjpark@amazon.de)
  + [516bfec3fe01] [2021-09-07] mm/damon/core: implement region-based sampling (sjpark@amazon.de)
  + [cd46ede185e6] [2021-09-07] mm: introduce Data Access MONitor (DAMON) (sjpark@amazon.de)
  + [d076c7dad52a] [2021-10-11] Revert "mm: Introduce Data Access MONitor (DAMON)" (anchalag@amazon.com)
  + [4479cf81f5e7] [2021-10-11] Revert "mm/damon/core: Implement region-based sampling" (anchalag@amazon.com)
  + [fe07fed19409] [2021-10-11] Revert "mm/damon: Adaptively adjust regions" (anchalag@amazon.com)
  + [6d5fb76b33e4] [2021-10-11] Revert "mm/idle_page_tracking: Make PG_idle reusable" (anchalag@amazon.com)
  + [1be1928ab6ee] [2021-10-11] Revert "mm/damon: Implement primitives for the virtual memory address spaces" (anchalag@amazon.com)
  + [0e56ad5e5f13] [2021-10-11] Revert "mm/damon: Add a tracepoint" (anchalag@amazon.com)
  + [bf1e166b8a21] [2021-10-11] Revert "mm/damon: Implement a debugfs-based user space interface" (anchalag@amazon.com)
  + [ab2b02caf2dd] [2021-10-11] Revert "mm/damon/dbgfs: Implement recording feature" (anchalag@amazon.com)
  + [ddd0b75022f3] [2021-10-11] Revert "mm/damon/dbgfs: Export kdamond pid to the user space" (anchalag@amazon.com)
  + [684dd1a0da75] [2021-10-11] Revert "mm/damon/dbgfs: Support multiple contexts" (anchalag@amazon.com)
  + [81d79de9102d] [2021-10-11] Revert "mm/damon/core: Account age of target regions" (anchalag@amazon.com)
  + [059701e40506] [2021-10-11] Revert "mm/damon/core: Implement DAMON-based Operation Schemes (DAMOS)" (anchalag@amazon.com)
  + [c6f5d7b60d81] [2021-10-11] Revert "mm/damon/vaddr: Support DAMON-based Operation Schemes" (anchalag@amazon.com)
  + [a94db552b9f3] [2021-10-11] Revert "mm/damon/dbgfs: Support DAMON-based Operation Schemes" (anchalag@amazon.com)
  + [2b53c25ec85c] [2021-10-11] Revert "mm/damon/schemes: Implement statistics feature" (anchalag@amazon.com)
  + [36d659936b81] [2021-10-11] Revert "damon/dbgfs: Allow users to set initial monitoring target regions" (anchalag@amazon.com)
  + [66b0aa8de36b] [2021-10-11] Revert "mm/damon/vaddr: Separate commonly usable functions" (anchalag@amazon.com)
  + [61c2e31375fb] [2021-10-11] Revert "mm/damon: Implement primitives for physical address space monitoring" (anchalag@amazon.com)
  + [d13ebf63376d] [2021-10-11] Revert "damon/dbgfs: Support physical memory monitoring" (anchalag@amazon.com)
  + [526189c69b7b] [2021-08-27] nitro_enclaves: Add fixes for checkpatch blank line reports (andraprs@amazon.com)
  + [ea965f9ff721] [2021-08-27] nitro_enclaves: Add fixes for checkpatch spell check reports (andraprs@amazon.com)
  + [8eae1835739c] [2021-08-27] nitro_enclaves: Add fixes for checkpatch match open parenthesis reports (andraprs@amazon.com)
  + [aa47b3f7a0d8] [2021-08-27] nitro_enclaves: Update copyright statement to include 2021 (andraprs@amazon.com)
  + [4da9d7af9b38] [2021-08-27] nitro_enclaves: Add fix for the kernel-doc report (andraprs@amazon.com)
  + [dbdc51d8046d] [2021-08-27] nitro_enclaves: Update documentation for Arm64 support (andraprs@amazon.com)
  + [dde637ddd72e] [2021-08-27] nitro_enclaves: Enable Arm64 support (andraprs@amazon.com)
  + [5196f321a044] [2021-06-21] nitro_enclaves: Set Bus Master for the NE PCI device (longpeng2@huawei.com)
  + [474df74dce88] [2021-09-17] Introduce page touching DMA ops binding (jgowans@amazon.com)
  + [78de4518a49f] [2021-06-18] KVM: nVMX: Dynamically compute max VMCS index for vmcs12 (seanjc@google.com)
  + [7928bc4fd608] [2021-05-26] KVM: selftests: x86: Add vmx_nested_tsc_scaling_test (ilstam@amazon.com)
  + [a5040f3cf10f] [2021-05-26] KVM: nVMX: Enable nested TSC scaling (ilstam@amazon.com)
  + [3ba2c8fbcb51] [2021-06-07] KVM: X86: Add vendor callbacks for writing the TSC multiplier (ilstam@amazon.com)
  + [546371be161d] [2021-05-26] KVM: X86: Move write_l1_tsc_offset() logic to common code and rename it (ilstam@amazon.com)
  + [c48987171274] [2021-05-26] KVM: X86: Add functions that calculate the nested TSC fields (ilstam@amazon.com)
  + [689b7fae8186] [2021-05-26] KVM: X86: Add functions for retrieving L2 TSC fields from common code (ilstam@amazon.com)
  + [8622a9806176] [2021-05-26] KVM: nVMX: Add a TSC multiplier field in VMCS12 (ilstam@amazon.com)
  + [9a96cba1eef3] [2021-05-26] KVM: X86: Add a ratio parameter to kvm_scale_tsc() (ilstam@amazon.com)
  + [33a04f7556f3] [2021-05-26] KVM: X86: Rename kvm_compute_tsc_offset() to kvm_compute_l1_tsc_offset() (ilstam@amazon.com)
  + [46c72f3aa20e] [2021-05-26] KVM: X86: Store L1's TSC scaling ratio in 'struct kvm_vcpu_arch' (ilstam@amazon.com)
  + [d4acda8a74ef] [2021-05-26] math64.h: Add mul_s64_u64_shr() (ilstam@amazon.com)
  + [62b198cd5931] [2021-06-23] tcp: Add stats for socket migration. (kuniyu@amazon.co.jp)
  + [b85afae679e0] [2021-06-12] bpf: Test BPF_SK_REUSEPORT_SELECT_OR_MIGRATE. (kuniyu@amazon.co.jp)
  + [d25334203719] [2021-06-12] libbpf: Set expected_attach_type for BPF_PROG_TYPE_SK_REUSEPORT. (kuniyu@amazon.co.jp)
  + [13ceff0ed91d] [2021-06-12] bpf: Support socket migration by eBPF. (kuniyu@amazon.co.jp)
  + [c40fd4fa55bc] [2021-06-12] bpf: Support BPF_FUNC_get_socket_cookie() for BPF_PROG_TYPE_SK_REUSEPORT. (kuniyu@amazon.co.jp)
  + [6cae525427ae] [2021-06-12] tcp: Migrate TCP_NEW_SYN_RECV requests at receiving the final ACK. (kuniyu@amazon.co.jp)
  + [e568cdb5880f] [2021-06-12] tcp: Migrate TCP_NEW_SYN_RECV requests at retransmitting SYN+ACKs. (kuniyu@amazon.co.jp)
  + [f3bd9b12cb20] [2021-06-12] tcp: Migrate TCP_ESTABLISHED/TCP_SYN_RECV sockets in accept queues. (kuniyu@amazon.co.jp)
  + [4b7c084eb88f] [2021-06-12] tcp: Add reuseport_migrate_sock() to select a new listener. (kuniyu@amazon.co.jp)
  + [64d62ef2f175] [2021-06-12] tcp: Keep TCP_CLOSE sockets in the reuseport group. (kuniyu@amazon.co.jp)
  + [e0e41529df2e] [2021-06-12] tcp: Add num_closed_socks to struct sock_reuseport. (kuniyu@amazon.co.jp)
  + [ff5bbb8e18d1] [2021-06-12] net: Introduce net.ipv4.tcp_migrate_req. (kuniyu@amazon.co.jp)
  + [3b177aecec62] [2021-07-01] bpf: Add ASSERT_NEQ(), ASSERT_FALSE(), and ASSERT_GE() for selftest. (kuniyu@amazon.co.jp)
  + [1f392bcc97f9] [2021-02-10] bpf: Expose bpf_get_socket_cookie to tracing programs (revest@chromium.org)
  + [75666835b34b] [2021-03-29] tcp: fix tcp_min_tso_segs sysctl (edumazet@google.com)
  + [67c4cca1719d] [2021-03-25] tcp: convert elligible sysctls to u8 (edumazet@google.com)
  + [324e8b8e46a8] [2021-03-25] inet: convert tcp_early_demux and udp_early_demux to u8 (edumazet@google.com)
  + [d72c15de6615] [2021-03-25] ipv4: convert ip_forward_update_priority sysctl to u8 (edumazet@google.com)
  + [4a2cb621abde] [2021-03-25] ipv4: shrink netns_ipv4 with sysctl conversions (edumazet@google.com)
  + [3f707ec687de] [2021-03-25] sysctl: add proc_dou8vec_minmax() (edumazet@google.com)
  + [28826f20ffa1] [2021-07-14] perf sched: Cast PTHREAD_STACK_MIN to int as it may turn into sysconf(__SC_THREAD_STACK_MIN_VALUE) (acme@redhat.com)
  + [bac1a65d4adb] [2021-09-15] mm, memcg: throttle the memory reclaim given dirty/writeback pages to avoid early OOMs (shaoyi@amazon.com)
  + [976179fcee05] [2021-02-24] drivers/virt: vmgenid: add vm generation id driver (acatan@amazon.com)
  + [acb319d739a7] [2021-02-24] drivers/misc: sysgenid: add system generation id driver (acatan@amazon.com)
  + [396073e7f9b1] [2021-05-09] tools headers UAPI: Sync linux/kvm.h with the kernel sources (acme@redhat.com)
  + [2d8a51a50af9] [2021-04-20] ptp: Don't print an error if ptp_kvm is not supported (jonathanh@nvidia.com)
  + [5cbe36f9c66a] [2020-12-09] ptp: arm/arm64: Enable ptp_kvm for arm/arm64 (jianyong.wu@arm.com)
  + [50789df8a951] [2020-12-09] KVM: arm64: Add support for the KVM PTP service (jianyong.wu@arm.com)
  + [11d30c344924] [2020-12-09] clocksource: Add clocksource id for arm arch counter (jianyong.wu@arm.com)
  + [a4e429eed93a] [2020-12-09] time: Add mechanism to recognize clocksource in time_get_snapshot (tglx@linutronix.de)
  + [03e86274ec93] [2020-12-09] ptp: Reorganize ptp_kvm.c to make it arch-independent (jianyong.wu@arm.com)
  + [0bf88545ecdf] [2020-12-09] KVM: arm64: Advertise KVM UID to guests via SMCCC (will@kernel.org)
  + [4fdddf86321e] [2020-12-09] arm/arm64: Probe for the presence of KVM hypervisor (will@kernel.org)
  + [682d698bdd16] [2021-08-30] mm/page_alloc: Use accumulated load when building node fallback list (krupa.ramakrishnan@amd.com)
  + [8b72c6df69a2] [2021-08-30] mm/page_alloc: Print node fallback order (bharata@amd.com)
  + [9ce8e4843575] [2021-07-26] efi/libstub: arm64: Warn when efi_random_alloc() fails (ardb@kernel.org)
  + [f479589794b4] [2021-07-27] lustre: update to AmazonFSxLustreClient v2.10.8-8 (shaoyi@amazon.com)
  + [50b23ea0364b] [2021-07-14] arm64/mm: Enable sysfs based memory hot remove probe (rohiwali@amazon.com)
  + [b04b75f40906] [2019-04-03] Sysfs memory probe interface (anshuman.khandual@arm.com)
  + [6998e5d3ba24] [2021-03-17] NFS: Only change the cookie verifier if the directory page cache is empty (trond.myklebust@hammerspace.com)
  + [da0ffb48de8f] [2021-03-16] NFS: Fix handling of cookie verifier in uncached_readdir() (trond.myklebust@hammerspace.com)
  + [d2a5c01d4d88] [2021-03-16] nfs: Subsequent READDIR calls should carry non-zero cookieverifier (natomar@microsoft.com)
  + [d4874373d860] [2021-06-24] igb_uio: add (fllinden@amazon.com)
  + [7597ec6e347c] [2021-06-08] Revert: crypto: jitterentropy - change back to module_init() (hailmo@amazon.com)
  + [cbafbfaac42a] [2021-06-07] ena: Update to 2.5.0 (yishache@amazon.com)
  + [f9a901efdfeb] [2021-05-12] x86: Disable KASLR when Xen is detected (benh@amazon.com)
  + [8310d921111a] [2021-04-26] lustre: update to AmazonFSxLustreClient v2.10.8-7 (shaoyi@amazon.com)
  + [54928e7e8bd6] [2021-02-22] hwrng: Add Gravition RNG driver (vaerov@amazon.com)
  + [c53b60257d2a] [2021-02-22] arm64: Export acpi_psci_use_hvc() symbol (vaerov@amazon.com)
  + [25f13983f99c] [2021-03-30] Revert "vmlinux.lds.h: Add PGO and AutoFDO input sections" (anchalag@amazon.com)
  + [be2ccc97f227] [2020-07-21] damon/dbgfs: Support physical memory monitoring (sjpark@amazon.de)
  + [34b309ceb48d] [2020-12-10] mm/damon: Implement primitives for physical address space monitoring (sjpark@amazon.de)
  + [ca34eb33fb6c] [2020-12-09] mm/damon/vaddr: Separate commonly usable functions (sjpark@amazon.de)
  + [ceb5c647800c] [2020-07-21] damon/dbgfs: Allow users to set initial monitoring target regions (sjpark@amazon.de)
  + [613503520d54] [2020-05-19] mm/damon/schemes: Implement statistics feature (sjpark@amazon.de)
  + [0c5ad1c4579d] [2020-02-10] mm/damon/dbgfs: Support DAMON-based Operation Schemes (sjpark@amazon.de)
  + [664abfc561ce] [2020-10-06] mm/damon/vaddr: Support DAMON-based Operation Schemes (sjpark@amazon.de)
  + [c72222b5ca51] [2021-02-02] mm/damon/core: Implement DAMON-based Operation Schemes (DAMOS) (sjpark@amazon.de)
  + [5acfb93504fd] [2020-06-15] mm/damon/core: Account age of target regions (sjpark@amazon.de)
  + [d76e0d42d75d] [2020-10-01] mm/damon/dbgfs: Support multiple contexts (sjpark@amazon.de)
  + [829ea5aaabd7] [2020-10-01] mm/damon/dbgfs: Export kdamond pid to the user space (sjpark@amazon.de)
  + [2e449cd20300] [2020-10-02] mm/damon/dbgfs: Implement recording feature (sjpark@amazon.de)
  + [d35fe87a0694] [2020-10-01] mm/damon: Implement a debugfs-based user space interface (sjpark@amazon.de)
  + [c0eb142609d2] [2020-02-02] mm/damon: Add a tracepoint (sjpark@amazon.de)
  + [eb3fb3eb42d0] [2020-09-29] mm/damon: Implement primitives for the virtual memory address spaces (sjpark@amazon.de)
  + [0b48cedeec86] [2020-07-27] mm/idle_page_tracking: Make PG_idle reusable (sjpark@amazon.de)
  + [e529c6c44890] [2021-02-02] mm/damon: Adaptively adjust regions (sjpark@amazon.de)
  + [2e06ae2788f2] [2021-02-04] mm/damon/core: Implement region-based sampling (sjpark@amazon.de)
  + [8b3d85d3c6ba] [2020-09-29] mm: Introduce Data Access MONitor (DAMON) (sjpark@amazon.de)
  + [a94b0d4d8bfe] [2019-09-05] Add Amazon EFA driver version 1.11.1 (samjonas@amazon.com)
  + [1a04ea7f979e] [2021-02-04] ena: update to 2.4.1 (anchalag@amazon.com)
  + [b6103fd77225] [2020-11-06] NFS: Do uncached readdir when we're seeking a cookie in an empty page cache (trond.myklebust@hammerspace.com)
  + [019ed469891b] [2020-11-06] NFS: Reduce number of RPC calls when doing uncached readdir (trond.myklebust@hammerspace.com)
  + [872e7739b9be] [2020-11-04] NFS: Optimisations for monotonically increasing readdir cookies (trond.myklebust@hammerspace.com)
  + [58e9be28ce41] [2020-11-02] NFS: Improve handling of directory verifiers (trond.myklebust@hammerspace.com)
  + [db4b37629274] [2020-11-02] NFS: Handle NFS4ERR_NOT_SAME and NFSERR_BADCOOKIE from readdir calls (trond.myklebust@hammerspace.com)
  + [775f0544a3cf] [2020-11-02] NFS: Allow the NFS generic code to pass in a verifier to readdir (trond.myklebust@hammerspace.com)
  + [a0e7f21463b4] [2020-11-03] NFS: Cleanup to remove nfs_readdir_descriptor_t typedef (trond.myklebust@hammerspace.com)
  + [c934df5bebee] [2020-11-02] NFS: Reduce readdir stack usage (trond.myklebust@hammerspace.com)
  + [ac3793e54e3c] [2020-11-01] NFS: nfs_do_filldir() does not return a value (trond.myklebust@hammerspace.com)
  + [30dd21b0a70b] [2020-11-01] NFS: More readdir cleanups (trond.myklebust@hammerspace.com)
  + [e470c0c5c54b] [2020-11-01] NFS: Support larger readdir buffers (trond.myklebust@hammerspace.com)
  + [c960521b49dd] [2020-11-01] NFS: Simplify struct nfs_cache_array_entry (trond.myklebust@hammerspace.com)
  + [8f536ab64b31] [2020-11-01] NFS: Replace kmap() with kmap_atomic() in nfs_readdir_search_array() (trond.myklebust@hammerspace.com)
  + [269827bfa4cf] [2020-11-01] NFS: Remove unnecessary kmap in nfs_readdir_xdr_to_array() (trond.myklebust@hammerspace.com)
  + [5120dd8f37d2] [2020-11-01] NFS: Don't discard readdir results (trond.myklebust@hammerspace.com)
  + [865bc121c277] [2020-11-01] NFS: Clean up directory array handling (trond.myklebust@hammerspace.com)
  + [6b52761ead1b] [2020-11-01] NFS: Clean up nfs_readdir_page_filler() (trond.myklebust@hammerspace.com)
  + [7989f8e16b9a] [2020-11-01] NFS: Clean up readdir struct nfs_cache_array (trond.myklebust@hammerspace.com)
  + [b4362f450799] [2020-11-01] NFS: Ensure contents of struct nfs_open_dir_context are consistent (trond.myklebust@hammerspace.com)
  + [44f20699d19b] [2020-12-31] lustre: don't try fault fast path if we can't retry (fllinden@amazon.com)
  + [34884f4c46c8] [2020-12-01] ena: Update to 2.4.0 (surajjs@amazon.com)
  + [39d5001dbb43] [2020-12-23] lustre: lprocfs: work around set_fs removal (fllinden@amazon.com)
  + [e90e02f597de] [2020-12-22] lustre: get network interface configs directly (fllinden@amazon.com)
  + [dde2bb0600a8] [2020-12-22] lustre: remove get/set_fs from ptask code (fllinden@amazon.com)
  + [73113dadd7a5] [2020-12-22] lustre: disable compiling sec_ctx.c (fllinden@amazon.com)
  + [09b5bb2ad21b] [2020-12-02] Disable HAVE_LINUX_SELINUX_IS_ENABLED, as it's gone for recent kernels. (fllinden@amazon.com)
  + [e6652fb0132b] [2020-10-16] lustre: use uaccess_kernel instead of segment_eq (fllinden@amazon.com)
  + [342cee15b8be] [2020-10-16] lustre: remove the pgprot argument to __vmalloc (fllinden@amazon.com)
  + [658a70ea5082] [2020-10-16] lustre: mmap_sem -> mmap_lock (fllinden@amazon.com)
  + [7e7cf77f7491] [2020-10-14] lustre: fixup for kernel_{get,set}sockopt removal (fllinden@amazon.com)
  + [705839eafafc] [2020-10-14] lustre: fix fiemap.h include (fllinden@amazon.com)
  + [e0fc9de644f1] [2020-10-14] lustre: seperate debugfs and procfs handling (fllinden@amazon.com)
  + [34d95af6ca06] [2020-10-13] lustre: Fix compilation with MOFED 5.1 (fllinden@amazon.com)
  + [f80eff5d9325] [2020-10-13] lustre: handle removal of NR_UNSTABLE_NFS (fllinden@amazon.com)
  + [c84894209d2f] [2020-10-13] lustre: stop using struct timeval (fllinden@amazon.com)
  + [3cb72e005299] [2020-10-13] lustre: add time_t define (fllinden@amazon.com)
  + [4964e70149ac] [2020-10-13] lustre: remove CRYPTO_TFM_RES_BAD_KEY_LEN (fllinden@amazon.com)
  + [2fd5c0757fa3] [2020-06-22] Update lustre to tag v2.10.8-5 in AmazonFSxLustreClient (astroh@amazon.com)
  + [0f4882d82feb] [2020-05-26] lustre: restore mgc binding for sptlrpc (astroh@amazon.com)
  + [c011c56a1c32] [2020-10-05] drivers/amazon: config: don't use '--help--' anymore (fllinden@amazon.com)
  + [1001a4d5087f] [2020-07-14] ena: Update to 2.2.10 (surajjs@amazon.com)
  + [5ccf2059fa74] [2020-04-07] ena: update to 2.2.6 (fllinden@amazon.com)
  + [c6c0e4afb5a0] [2020-02-19] lustre: llite: ll_fault fixes (fllinden@amazon.com)
  + [89e4158cac1f] [2020-02-12] lustre: adapt to changed padata interfaces in 5.4 -stable (fllinden@amazon.com)
  + [bfd46dd1f43e] [2020-03-06] ena: update to 2.2.3 (fllinden@amazon.com)
  + [8b0875429795] [2019-12-04] lustre: hold lock while walking changelog dev list (astroh@amazon.com)
  + [261e3970e5eb] [2019-11-27] block/xen-blkfront: bump the maximum number of indirect segments up to 64 (fllinden@amazon.com)
  + [7b226a43f120] [2019-08-15] xen: Restore xen-pirqs on resume from hibernation (anchalag@amazon.com)
  + [602ed430e4f8] [2019-08-29] iommu: use config option to specify if iommu mode should be strict (fllinden@amazon.com)
  + [58e5a141057c] [2019-10-12] lustre: adapt to changed padata interfaces. (fllinden@amazon.com)
  + [31617a199fab] [2019-09-13] lustre: fix lnet makefile (fllinden@amazon.com)
  + [4ef0d40b000a] [2019-09-13] lustre: fix file_lock usage (fllinden@amazon.com)
  + [310e00656ddf] [2019-09-13] lustre: fix fall through warnings. (fllinden@amazon.com)
  + [c96016816e25] [2019-05-20] lustre: adapt to stacktrace infrastructure change (fllinden@amazon.com)
  + [d49a66d91502] [2019-04-03] lustre: fix ACL handling (fllinden@amazon.com)
  + [7435e4c41c27] [2019-03-24] lustre: adapt to get_ds() removal (fllinden@amazon.com)
  + [2842a40ad2ec] [2019-03-24] lustre: add HAVE_VM_FAULT_T to config.h (fllinden@amazon.com)
  + [1e36c0bc40ed] [2019-03-24] lustre: adapt for fault / page_mkwrite return type change (fllinden@amazon.com)
  + [5c58103f62b5] [2019-03-24] lustre: account for the SO_*TIMEO -> SO_*TIME_OLD rename (fllinden@amazon.com)
  + [13e60ace2ab6] [2019-03-06] lustre: config.h file for Linux 5.0 (fllinden@amazon.com)
  + [777d4ac4e59d] [2019-03-05] lustre: adapt for totalram_pages change (fllinden@amazon.com)
  + [418ff2ffcc2e] [2019-03-05] lustre: reintroduce ATTR_ATTR_FLAG (fllinden@amazon.com)
  + [280f9e7084df] [2019-03-08] lustre: adapt to changed kernel socket interfaces (fllinden@amazon.com)
  + [b1c0159e8e20] [2019-03-05] lustre: adapt to upstream atomic_open interface change (fllinden@amazon.com)
  + [5d68d45d6a88] [2019-03-04] lustre: adapt to upstream struct address_space changes (fllinden@amazon.com)
  + [639b5226e55c] [2019-03-04] lustre: adapt to sys_close -> ksys_close change (fllinden@amazon.com)
  + [18e29dc3f71b] [2019-03-04] lustre: adapt to struct posix_acl atomic_t -> refcount_t change (fllinden@amazon.com)
  + [6622e1e3762c] [2019-03-04] lustre: adapt to setup_timer -> timer_setup change (fllinden@amazon.com)
  + [07745c3dd959] [2019-03-06] lustre: use SB_* instead of MS_* as superblock flags. (fllinden@amazon.com)
  + [c824ae5065ff] [2019-03-07] lustre: silence printk format warnings about timespec.tv_sec (fllinden@amazon.com)
  + [ee030974f596] [2019-03-04] lustre: change printf format strings for 64bit time in struct inode (fllinden@amazon.com)
  + [6016b5eba47b] [2019-03-01] Config glue for lustre client. (fllinden@amazon.com)
  + [de99b4ea32d5] [2019-03-01] Import lustre client 2.10.5 (fllinden@amazon.com)
  + [ab0a4cb8c6ec] [2019-03-06] iov_iter: fix iov_for_each after accessor function introduction (fllinden@amazon.com)
  + [33514623a515] [2019-02-12] net: ena: replace dma_zalloc_coherent with dma_alloc_coherent (fllinden@amazon.com)
  + [6b73eb20d711] [2019-01-31] xen-netfront: call netif_device_attach on resume (fllinden@amazon.com)
  + [7a2e2636a05b] [2018-11-10] net: ena: Import the ENA v2 driver (2.0.2g) (alakeshh@amazon.com)
  + [ab54b010024b] [2018-11-10] xen: Only restore the ACPI SCI interrupt in xen_restore_pirqs. (fllinden@amazon.com)
  + [1dc16b36f606] [2018-10-26] xen: restore pirqs on resume from hibernation. (fllinden@amazon.com)
  + [9bd0bad0f4c3] [2018-10-18] block: xen-blkfront: consider new dom0 features on restore (eduval@amazon.com)
  + [4993664ab9fe] [2018-04-09] x86: tsc: avoid system instability in hibernation (eduval@amazon.com)
  + [268d9e89936c] [2018-06-05] xen-blkfront: Fixed blkfront_restore to remove a call to negotiate_mq (anchalag@amazon.com)
  + [9e67537bda8b] [2018-03-27] Revert "xen: dont fiddle with event channel masking in suspend/resume" (anchalag@amazon.com)
  + [719e06e7a5ae] [2017-10-27] PM / hibernate: update the resume offset on SNAPSHOT_SET_SWAP_AREA (cyberax@amazon.com)
  + [aee0a238766b] [2017-08-24] x86/xen: close event channels for PIRQs in system core suspend callback (kamatam@amazon.com)
  + [8967b7667653] [2017-08-24] xen/events: add xen_shutdown_pirqs helper function (kamatam@amazon.com)
  + [0e7945ad3c32] [2017-07-21] x86/xen: save and restore steal clock (kamatam@amazon.com)
  + [51959ccea5a6] [2017-07-13] xen/time: introduce xen_{save,restore}_steal_clock (kamatam@amazon.com)
  + [e793cc07edb4] [2017-01-09] xen-netfront: add callbacks for PM suspend and hibernation support (kamatam@amazon.com)
  + [2157f7d936a9] [2017-06-08] xen-blkfront: add callbacks for PM suspend and hibernation (kamatam@amazon.com)
  + [df5aac74d223] [2017-02-11] x86/xen: add system core suspend and resume callbacks (kamatam@amazon.com)
  + [41baee969a42] [2018-02-22] x86/xen: Introduce new function to map HYPERVISOR_shared_info on Resume (anchalag@amazon.com)
  + [3c1403560569] [2017-07-13] xenbus: add freeze/thaw/restore callbacks support (kamatam@amazon.com)
  + [b24d02a1a1c6] [2017-07-13] xen/manage: introduce helper function to know the on-going suspend mode (kamatam@amazon.com)
  + [c349988a0972] [2017-07-12] xen/manage: keep track of the on-going suspend mode (kamatam@amazon.com)
  + [f5f19790f8b5] [2018-02-27] Importing Amazon ENA driver 1.5.0 into amazon-4.14.y/master. (vallish@amazon.com)
  + [121d27306e26] [2018-02-12] drivers/amazon: introduce AMAZON_ENA_ETHERNET (vallish@amazon.com)
  + [db35ad7c32f1] [2018-02-12] drivers/amazon: add network device drivers support (vallish@amazon.com)
  + [be79f7db18ab] [2018-02-12] drivers: introduce AMAZON_DRIVER_UPDATES (vallish@amazon.com)
  + [98d6151ac52e] [2017-10-27] not-for-upstream: testmgr config changes to enable FIPS boot (alakeshh@amazon.com)
  + [648a2c186a3a] [2012-02-10] scsi: sd_revalidate_disk prevent NULL ptr deref (kernel-team@fedoraproject.org)


