TOTP_SPDM_VERSION = 08ab8e2782805c554690b412874985404b2cc4bc
TOTP_SPDM_SITE = https://github.com/LucasTyph/TOTP-SPDM-driver.git
TOTP_SPDM_SITE_METHOD = git
TOTP_SPDM_LICENSE = GPL-2.0+
TOTP_SPDM_LICENSE_FILES = COPYING

$(eval $(kernel-module))
$(eval $(generic-package))
