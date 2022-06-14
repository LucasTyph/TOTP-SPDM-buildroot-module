obj-m += $(addsuffix .o, $(notdir $(basename $(wildcard $(BR2_EXTERNAL_TOTP_SPDM_PATH)/*.c))))
ccflags-y := -g -std=gnu99 -Wno-declaration-after-statement

# SPDM stuff
SPDM_INCLUDE := -Iinclude/spdm -Iinclude/spdm/hal
ccflags-y += $(SPDM_INCLUDE)

.PHONY: all clean

all:
	$(MAKE) -C '$(LINUX_DIR)' M='$(PWD)' modules

clean:
	$(MAKE) -C '$(LINUX_DIR)' M='$(PWD)' clean
