# TOTP-SPDM-buildroot-module (WIP)
Buildroot module for TOTP + SPDM integration

- Copy the files in [drivers](drivers) and [include](include) folders into the kernel tree
- Recompile the kernel. Set `SPDM_DIR` and `SPDM_BUILD_DIR` variables properly
	- E.g. `SPDM_DIR=/opt/libspdm SPDM_BUILD_DIR=/opt/libspdm/build_buildroot make linux-rebuild`
- `BR2_ROOTFS_OVERLAY` to the `rootfs-overlay` directory in this repository (e.g. `BR2_ROOTFS_OVERLAY=[this-directory]/rootfs-overlay`
  -  alternatively, during `menuconfig`, set System configurations -> Root filesystem overlay directories to `[this-directory]/rootfs-overlay`

Any new or renamed .c files must be added to the `S16totp-spdm` script in order to be initialized during startup with the `modprobe` command.
