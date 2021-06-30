# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.


# Installs a PKCS#11 driver and PKCS#15 file system support.
#
# See <https://github.com/OpenSC/OpenSC/wiki/macOS-Quick-Start>
#
# Config is stored at /Library/OpenSC/etc/opensc.conf
# PKCS#11 driver is stored at /usr/local/lib/opensc-pkcs11.so and /Library/OpenSC/lib/opensc-pkcs11.so (?Why?)
# A second PKCS#11 driver is stored at /Library/OpenSC/lib/onepin-opensc-pkcs11.so (but NOT in /usr/local/lib)!
#
# Should be called PIV_II, but seems to be absent from Keychain Access.
#
# Supports many smart card variants, but the two most of interest to us:-
#
# * PIV-II (Personal Identity Verification Card)
# * openpgp
#
# It seems a PIV-II card used by OpenSC DOES NOT support RSA 4096 but only RSA 3072.
opensc_install()
{
	brew_install_cask opensc
}

depends sudo
opensc_uninstall()
{
	brew_uninstall_cask opensc
}

# Default PIV PIN is 123456.
opensc_test()
{
	pkcs11-tool --login --test
}
