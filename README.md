# TOTP-SPDM-buildroot-module (WIP)
Buildroot module for TOTP + SPDM integration

requires setting the following variables on Buildroot:
- `BR2_EXTERNAL`  to this directory (e.g. `BR2_EXTERNAL=/home/user/this_repo/`)
- `BR2_ROOTFS_OVERLAY` to the `rootfs-overlay` directory in this repository (e.g. `BR2_ROOTFS_OVERLAY=$(BR2_EXTERNAL_TOTP_SPDM_PATH)/rootfs-overlay`
  -  alternatively, during `menuconfig`, set System configurations -> Root filesystem overlay directories to `$(BR2_EXTERNAL_TOTP_SPDM_PATH)/rootfs-overlay`

any new or renamed .c files must be added to the `S16totp-spdm` script in order to be initialized during startup
