# TOTP-SPDM-buildroot-module (WIP)
Buildroot module for TOTP + SPDM integration

This module was developed as an in-tree module for Buildroot, using [libpsdm](https://github.com/DMTF/libspdm/), which must be built on the host machine.

- Copy the files in the [drivers](drivers) directory into the kernel tree
- Recompile the kernel. Set `SPDM_DIR` and `SPDM_BUILD_DIR` variables properly
	- E.g. `make SPDM_DIR=path/to/libspdm SPDM_BUILD_DIR=path/to/libspdm/build_buildroot linux-rebuild`
