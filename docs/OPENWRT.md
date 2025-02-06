# Openwrt
## Instructions for compiling the module:

* download sdk https://downloads.openwrt.org/releases/23.05.5/targets/mvebu/cortexa9/openwrt-sdk-23.05.5-mvebu-cortexa9_gcc-12.3.0_musl_eabi.Linux-x86_64.tar.xz

/!\ Add to env if you compile as root user
```
export FORCE_UNSAFE_CONFIGURE="1"
```

update and install feeds, checkout v23.05.5 tag
```
./scripts/feeds update -a
./scripts/feeds install -a
cd feeds/base && git checkout v23.05.5 && cd ../..
make menuconfig
```

#### remove:
* Select all target specific packages by default
* Select all kernel module packages by default
* Select all userspace packages by default
* Advanced configuration options (for developers)
1. Automatic rebuild of packages
2. Automatic removal of build directories

## Target a commit (sha1)
1. edit Makefile
```
nano ./feeds/base/package/kernel/mwlwifi/Makefile
```
2. compile
```
make -j$(nproc) package/mwlwifi/compile
```
3. Find ipk here
```
ls -al bin/targets/mvebu/cortexa9/packages/kmod-mwlwifi_*
```