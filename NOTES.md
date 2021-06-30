
# Standards


## FIDO / U2F 1.2

Legacy standard replaced with FIDO2.


## FIDO2 and WebAuthn


### Uses

* Most convenient way of providing for OpenSSH access in combination with OpenSSH certificates.
* Modern standard for password-less multi-factor authentication.


## PIV

A NIST standard (technically, PIV II), used to work with keys, X.509 certificates and related operations on a smart card.


### Shortcomings

* Sadly limited to a maximum of 2048 bits for RSA.
* Only supports two of the ?weaker NIST ECDSA curves.
* Does not support Ed25519.
* Does not support Ed448.
* Does not support SHA3 or SHAKE.


### Slots

Has the concept of 'slots'; each slot is a number from 0 to 255, expressed as a lower case 2 character hexadecimal number.
Each slot contains either an asymmetric key pair's private key or a symmetric key.
Each slot has a specific purpose, eg signing, encrypting, authentication, etc.
Some slots are 'hidden', for instance, for storing a management key.
Each slot can have an associated key algorithm; the range of supported algorithms is restricted by the purpose of the slot.


### Uses

* OS X smart card sign-on instead of a password
* NFC smart cards for touch access entry to doors ('passes')
* OpenSSH user keys
* OpenSSL client certificates
* Signing git commits using X.509


## OpenPGP Smart Card


### Slots

Has the concept of 'slots'; each slot is named using a three letter abbreviation, but its associated key is accessed using an identifier, eg `OPENPGP.1`. Slots, when numbered, are numbered from 1 (not zero). Each slot has a specific purpose, eg signing, encrypting, authentication, etc.


### Shortcomings

* Public keys are not stored on the smart card and can not be recreated from data on the smart card!
	* eg <https://stackoverflow.com/questions/46689885/how-to-get-public-key-from-an-openpgp-smart-card-without-using-key-servers>
* Requires the use of a panoply of GnuPG tools, all of which are brittle, complex to operate and have arcane configuration. All of the tools are not shell script friendly.


## PKCS#11

A soft API for interacting with smart card operations.
Usually implemented by a card manufacturer as a 'module' (driver).
Used by OpenSSH and OpenSSL.
Usually used to access PIV smart card functionality.
Now under [OASIS](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11).


##  PKCS#15

This standard, now part of Cryptoki at OASIS, is used to standardize a pseudo-filesystem for objects (files) on Smart Cards.


## Modhex

A Yubico encoding of data that uses a very restricted range of characters in order to work with the widest possible range of keyboard layouts ('scan codes').
Modhex strings can be prefixed with `m:` or `M:`, but are often the default for most older Yubico tools.
Hexadecimal strings may be supported and prefixed with `h:` or `H:`.


# Use Cases


## Supported


### OpenSSH User keys

* Use FIDO2 security keys


#### GitHub SSH Access

* Use FIDO2 security keys


### WebAuthn and other web logins

* Use FIDO2 security keys


### 2FA / MFA with OATH & 'Google Authenticator'

* Use Yubikey 5 OATH HOTP / TOTP
* Use Yubico Authenticator


## Git commit signing

* Use OpenPGP smart card


## Local password stores


### `pass`

* Use OpenPGP smart card
* Can be backed up with git or with rclone (custom plugin needed)
* A better alternative is probably to use 'age'.
* Integrates with Firefox and Chrome
* A QT and a Go UI


### [Ripasso](https://github.com/cortex/ripasso)

* Written in Rust


### lastpass

* Has a CLI
* Requires a cask for some features.


### 1password

* Has a CLI, but requires cask.


# Uninvestigated Use Cases


## OpenSSH server keys or certificates

* FIDO2 is not an option as it is unattended
* Possibly via OpenSSL PKCS#11 or OpenPGP, but not obvious.


## OpenSSH Certificate Signing of User Keys

* This uses `ssh-keysign`, so it's a question of what backends this can use.


## OpenSSL / gpgsm Certificate Authority

* Unless there is a PKCS#11 provider for OpenPGP smart cards (there is [this](https://github.com/sektioneins/scd-pkcs11) prototype, and OpenSC is supposed to be an option), then it is a non-starter.
* gpgsm can generate CAs: <https://www.gnupg.org/documentation/manuals/gnupg/Howto-Create-a-Server-Cert.html>


## LUKS encrypted volume with PGP Smart Card

* <https://blog.fugoes.xyz/2018/11/16/LUKS-Encrypted-Root-with-GPG-Smartcard.html>


## Credentials in a git repo

* git-crypt vs git-secret


## Other local password stores

* eg 1Pass, etc
* These need to have a command line


## PKCS#11 with GnuPG

* Uses 'scute', a separate GnuPG package


# Unsupported / Badly Supported Use Cases


## X.509 for Git Commit Signing

* smimesign is really a non-starter, as it needs OpenSC with a PIV smart card; PIV is not secure enough
* gpgsm might work, eg see <https://github.com/darinegan/signed-commits-x509>


## OS X password-less login

* Requires OpenSC with a PIV smart card; PIV is not secure enough


## OS X encrypted disk

* Not supported directly.








# Programs and Packages


## `libyubikey`

* Fundamental C shared library.
* Basic binaries to work with modhex encoding.


### Binaries

* `modhex`
* `ykgenerate`
* `ykparse`


## `ykpers`

* Legacy Yubico tooling to work with their smart cards.
* Mostly used for configuring the Yubico password and specialized OTP functionality.
* Needed (as `ykpers` binary) to reset Yubico password and specialized OTP functionality.


### Binaries

* `ykinfo`
	* Access information about card not easily available otherwise
		* Touch Level
		* USB vendor and product identifiers
		* Capabilities
		* Programming sequence (?what is this)
* `ykpers`
	* Control password and specialized OTP functionality.
* `ykchalresp`
	* Command line tool to do OTP challenge-responses.

## `ykman`

* Python tool consisting of the binary `ykman`
* Best way to work with configuring a Yubikey, including PIV functionality
* Can not configure PIV CHUID or CCC fields
* Buggy when configuring the Yubico password and specialized OTP functionality.


## `yubico-piv-tool`

* PKCS#11 module, `ykcs11` (`libykcs11.*`), for accessing Yubkiy PIV.
* Low-level tool, in C, for configuring Yubikey PIV functionality
* Mostly not needed if using `ykman`
* Can be used to configure the PIV CHUID and CCC fields.


### PKCS#11 Modules

* `ykcs11`


### Binaries

* `yubico-piv-tool`


## `yubikey-personalization`

* Graphical client for configuring all aspects of Yubikeys.


## `pinentry`


## `pinentry-mac`


## `hopenpgp-tools`

Convenience tools for working with OpenPGP


### Binaries

* `hkt`
* `hokey`
* `hop`
* `hot`


## `ykclient`

Deprecated package to validate Yubico OTPs against Yubico cloud.


## `ykenomgr`

Deprecated package to work with Yubikey NEO.


## `p11-kit`

Library to support the use of PKCS#11 modules (drivers).


### Binaries

* `p11-kit`
	* Server daemon (over Unix domain sockets) to run PKCS#11 modules.


## `yubico-pam`

* <https://developers.yubico.com/yubico-pam/>
* Available via Homebrew on OS X
* Provides PAM integration for OS X, Linux and Solaris


## `yubikey-agent`

* SSH agent in Go for Yubikeys, provided independently (<https://github.com/FiloSottile/yubikey-agent>).
* Uses PIV functionality, sadly.
* Otherwise a first-class tool.


## GnuPG


### Binaries

* `gpg`
	* A daddy of a program, with a truly insane number of configuraiton options designed around human interaction.
	* The classic example of why security is mad far, far harder than it need be.
	* Three incompatible versions (1.x, 2.1, 2.3).
* `gpg-agent`
	* A Unix domain socket service for connecting to all sorts of things, including smart cards.
	* Also used as a ssh-agent replacement.
	* An absolute nightmare to work with.
* `gpg-connect-agent`
	* A general purpose tool for talking to smart cards, amongst other things, with a peculiar scripting language that isn't particularly script friendly.
* `gpgsm`
	* A tool for using GPG keys with S/MIME and some X.509 features.
	* See <https://github.com/jymigeon/gpgsm-as-ca> for using it as a poor man's CA.
	* And <https://security.stackexchange.com/questions/31098/how-to-use-a-yubikey-neo-or-any-openpgp-card-or-gnupg-in-general-to-sign-x-509>
* `gpgv`
	* A 'simpler' tool for verifying signatures.
* `gpg-card`
	* A modern tool (2021) for working with cards, but repeating the mistakes of `gpg`.


## OpenSC

* Provides integration with OS X Keychain Access
* Needs to be installed as a homebrew cask, not a homebrew formula in order to work with OS X Keychain Access.
* Prefers to use a PIV smart card driver over a OpenPGP smart card driver.
* Keychain Access integration seems brittle (PIV_II chain does not always appear)
* Integrates only PIV smart cards with Keychain Access, not OpenPGP smart cards (apparently).


### Shortcomings

* Needs a package installer
* Brittle
* Woeful history of CVEs and other security defects
* Poor documentation


### PKCS#11 Modules

* `opensc-pkcs11`
* `onepin-opensc-pkcs11`


### Binaries

* Generic
	* `opensc-tool`
	* `opensc-asn1`
	* `opensc-explorer`
	* `opensc-notify`
* PKCS#11
	* `pkcs11-tool`
	* `pkcs11-register`
* PKCS#15
	* `pkcs15-crypt`
	* `pkcs15-init`
	* `pkcs15-tool`
		* Change PIV PINs
		* Get public keys
* Card Specific
	* Useful
		* `openpgp-tool`
		* `piv-tool`
	* Other
		* `cardos-tool`
		* `cryptoflex-tool`
		* `dnie-tool`
		* `egk-tool`
		* `eidenv`
		* `gids-tool`
		* `goid-tool`
		* `iasec-tool`
		* `netkey-tool`
		* `npa-tool`
		* `sc-hsm-tool`


## `smimesign`

* GitHub static binary for signing git commits et al with X.509 certificates from OS X Keychain Access.
* Needs `OpenSC` installed to be usable with a smart card.


## <https://github.com/sektioneins/scd-pkcs11>

* PKCS#11 wrapper of gpg smart card daemon `scdaemon`


## `pkcs11-helper`

* Mid-level wrapper library for PKCS#11 providers.


## `gnupg-pkcs11-scd`

* A daemon to enable GnuPG to access PKCS#11 smart card tokens as keys.


### Binaries

* `gnupg-pkcs11-scd`
	* Run as a daemon.


## Age

* <https://github.com/FiloSottile/age>
* A modern encryption tool by someone who knows what they are doing.


## mkcert

* <https://github.com/FiloSottile/mkcert>
* Makes a locally trusted CA, for locally signed certificates.
