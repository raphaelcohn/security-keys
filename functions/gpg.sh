# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.


depends env
_gpg_run_command()
{
	local binary="$1"

	brew_ensure_binary gnupg "$binary"

	_gpg_set_home
	
	local is_usable
	
	_gpg_ensure_home_configuration
	
	_gpg_ensure_scdaemon_configuration
	
	_gpg_ensure_gpg_agent_configuration true
	
	_gpg_ensure_gpg_configuration
	
	env -i PATH="$PATH" GNUPGHOME="$GNUPGHOME" HOME="$device_configuration_folder_path" "$binary" "$@"
}

_gpg_ensure_home_configuration()
{
	local is_usable
	folder_is_usable "$GNUPGHOME"
	if ! $is_usable; then
		_gpg_create_home
	fi
}

_gpg_ensure_gpg_configuration()
{
	local is_usable
	local configuration_file_path="$GNUPGHOME"/gpg.conf
	file_is_usable "$configuration_file_path"
	if ! $is_usable; then
		_gpg_create_configuration "$configuration_file_path"
	fi
}

_gpg_ensure_gpg_agent_configuration()
{
	local reload="$1"
	
	local is_usable
	local gpg_agent_configuration_file_path="$GNUPGHOME"/gpg-agent.conf
	file_is_usable "$gpg_agent_configuration_file_path"
	if ! $is_usable; then
		_gpg_create_agent_configuration "$gpg_agent_configuration_file_path"
		
		if $reload; then
			env -i PATH="$PATH" GNUPGHOME="$GNUPGHOME" HOME="$device_configuration_folder_path" gpg-connect-agent reloadagent /bye
		fi
	fi
}

_gpg_ensure_scdaemon_configuration()
{
	local is_usable
	local scdaemon_configuration_file_path="$GNUPGHOME"/scdaemon.conf
	file_is_usable "$scdaemon_configuration_file_path"
	if ! $is_usable; then
		_gpg_create_scdaemon_configuration "$scdaemon_configuration_file_path"
	fi
}

_gpg_run_command_gpgconf()
{
	gpg_run_command gpgconf "$@"
}

_gpg_run_command_gpg()
{
	gpg_run_command gpg --quiet --utf8-strings --no-options --homedir "$GNUPGHOME" --options "$configuration_file_path" --batch --no-tty --yes --pinentry-mode loopback "$@"
}

_gpg_run_command_gpg_agent_foreground()
{
	_gpg_set_home
	local gpg_agent_configuration_file_path="$GNUPGHOME"/gpg-agent.conf
	
	local log_file="$TMPDIR"/gpg-agent.log
	
	# it is possible to run the gpg-agent in the foreground listening on stdin.
	# this seems like it might be a bit easier.
	# To debug pinentry: --debug 1024 --debug-pinentry
	_gpg_run_command gpg-agent --quiet --batch --options "$gpg_agent_configuration_file_path" --homedir "$GNUPGHOME" --log-file "$log_file" --server --no-detach --no-grab "$@"
}

_gpg_run_command_gpg_connect_agent()
{
	standard_out_file_path="$TMPDIR"/gpg-connect-agent.standard-out
	gpg_run_command gpg-connect-agent --quiet --no-history --homedir "$GNUPGHOME" "$@" /bye >"$standard_out_file_path"	
}

depends rm
_gpg_run_command_scdaemon_foreground()
{
	local commands_file_path="$1"
	local output_file_path="$2"
	
	local file_path
	brew_ensure_file gnupg libexec/scdaemon
	
	_gpg_set_home
	_gpg_ensure_scdaemon_configuration
	
	# PIN has a maximum length of 100.
	
	# Produces output on standard out with lines like:-
	#
	# OK GNU Privacy Guard's Smartcard server ready
	# # NOP
	# OK
	# S PINCACHE_PUT 0/openpgp/1
	# S PINCACHE_PUT 0/openpgp/2
	# S PINCACHE_PUT 0/openpgp/3
	# INQUIRE NEEDPIN ||Please enter the PIN
	# ERR 100663570 Unexpected IPC command <SCD>
	#
	# In essence, there is a format.
	# OK (optional text) - success
	# ERR <Number> <Text> - failure
	# INQUIRE <ACTION> ||<Message> - input required.
	# INQUIRE NEEDPIN |A|Please enter the Admin PIN%0A%0ANumber: 16 133 288%0AHolder:   (See getpin_cv() in divert-scd.c for how this string is parsed)
	# Line starting with '# ' - Comment
	# Line starting with 'S ' - Status information
	# ?Line starting with 'D ' - Data
	"$file_path" --quiet --server --no-detach --sh --options "$GNUPGHOME"/scdaemon.conf --debug mpi,crypto,memory,cache,memstat,hashing,ipc,cardio,reader,app --log-file "$TMPDIR"/scdaemon.log <"$commands_file_path" 1>"$output_file_path" 2>"$TMPDIR"/scdaemon.standard-error
	rm "$commands_file_path"
}

_gpg_set_home()
{
	export GNUPGHOME="$device_configuration_folder_path"/.gnupg
}

depend mkdir
_gpg_create_home()
{
	mkdir -m 0700 "$GNUPGHOME"
}

depends rm chmod cat
_gpg_create_configuration()
{
	local configuration_file_path="$1"

	rm -rf "$configuration_file_path"
	
	# Also
	# --status-fd or --status-file
	# --logger-fd or --logger-file
	# --attribute-fd or --attribute-file
	# --passphrase-fd or --passphrase-file
	# --command-fd or --command-file

	# When creating a message:-
	# --no-default-recipient
	# --output message.asc
	# --armor (if text file)
	# --cipher-algo AES256 --digest-algo SHA512 --compress-algo Uncompressed --cert-digest-algo SHA512 --aead-algo OCB
	# --sig-policy-url URL --cert-policy-url URL --sig-keyserver-url URL
	# --set-filename '' --for-your-eyes-only --escape-from-lines
	
	# Sources of configuration information:-
	# * https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html
	# * https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html
	# * https://github.com/ioerror/duraconf/blob/master/configs/gnupg/gpg.conf
	cat >"$configuration_file_path" <<-EOF
		# Lock down crypto algorithms.
		default-preference-list SHA512 AES256 Uncompressed OCB
		default-new-key-algo ed25519/cert,sign+cv25519/encr
		personal-cipher-preferences AES256
		personal-digest-preferences SHA512
		personal-compress-preferences Uncompressed
		personal-aead-preferences OCB
		compress-level 0
		bzip2-compress-level 0
		cert-digest-algo SHA512
		# These are a poor man's version of PBKDF2 or scrypt
		# s2k stands for String-to-Key.
		s2k-digest-algo SHA512
		s2k-cipher-algo AES256
		s2k-mode 3
		s2k-count 1015808
		disable-cipher-algo IDEA 3DES CAST5 BLOWFISH TWOFISH CAMELLIA256 CAMELLIA192 CAMELLIA128 AES192
		disable-pubkey-algo ELG DSA ECDSA ECDH
		weak-digest MD5 SHA1 RIPEMD160 SHA224 SHA384
		# Maximum depth of a certificate chain
		max-cert-depth 5
		# Cross-certify subkeys are present and valid.
		require-cross-certification
		disable-dsa2
		enable-large-rsa
		no-allow-non-selfsigned-uid
		default-preference-list AES256 SHA512 Uncompressed MDC OCB
		
		# default-keyserver-url name
		
		keyserver hkps://keys.openpgp.org/

		# When using --refresh-keys, if the key in question has a preferred keyserver
		# URL, then disable use of that preferred keyserver to refresh the key from
		keyserver-options no-honor-keyserver-url

		# When searching for a key with --search-keys, include keys that are marked on the keyserver as revoked
		keyserver-options include-revoked
		
		# Remove version and comments from signatures and remove recipient key ID in messages.
		no-comments
		no-emit-version
		throw-keyids
		no-textmode
		
		# Runtime security
		no-symkey-cache
		no-random-seed-file
		require-secmem
		lock-once
		exit-on-status-write-error
		limit-card-insert-tries 1
		no-use-embedded-filename
		passphrase-repeat 1
		pinentry-mode default
		# Limit to processing compressed messages under 100Mb
		max-output 104857600
		
		# Expiry
		no-ask-sig-expire
		default-sig-expire 1y
		no-ask-cert-expire
		default-cert-expire 8w
		
		#no-default-keyring
		#no-keyring
		
		# Web of Trust (we make no claims, but require extensive verification)
		no-ask-cert-level
		default-cert-level 0
		min-cert-level 3
		trust-model tofu+pgp
		tofu-default-policy unknown
		completes-needed 1
		marginals-needed 3
		
		auto-key-locate clear,local,dane,cert,wkd
		auto-key-import
		auto-key-retrieve
		keyserver-options include-revoked,no-include-disabled,no-honour-keyserver-url,no-honor-pka-record,include-subkeys
		
		# Key import
		import-options no-import-local-sigs,no-repair-pks-subkey-bug,no-import-show,no-import-export,no-merge-only,no-import-clean,repair-keys,no-import-minimal,no-import-restore
		
		# Display options.
		with-colons
		fixed-list-mode
		with-fingerprint
		with-subkey-fingerprint
		with-icao-spelling
		with-keygrip
		with-key-origin
		with-wkd-hash
		with-secret
		keyid-format 0xlong
		display-charset utf-8
		list-options no-show-photos,show-usage,show-policy-urls,show-std-notations,show-uid-validity,no-show-unusable-uids,noshow-unusable-subkeys,no-show-keyring,show-sig-expire,no-show-sig-subpackets,no-show-only-fpr-mbox
		verify-options no-show-photos,show-policy-urls,show-std-notations,show-keyserver-urls,show-uid-validity,no-show-unusable-uids,no-pka-lookups,no-pka-trust-increase
		no-greeting
	EOF
	chmod 0400 "$configuration_file_path"
}

depends rm chmod cat
_gpg_create_scdaemon_configuration()
{
	local configuration_file_path="$1"
	
	rm -rf "$configuration_file_path"
	cat >"$configuration_file_path" <<-EOF
		application-priority openpgp
		disable-application piv
		disable-ccid
	EOF
	chmod 0400 "$configuration_file_path"
}

depends rm chmod cat
_gpg_create_agent_configuration()
{
	local configuration_file_path="$1"
	
	rm -rf "$configuration_file_path"
	cat >"$configuration_file_path" <<-EOF
		# pinentry
		# Choices are:-
		# * pinentry (defaults to pinentry-curses)
		# * pinentry-curses
		# * pinentry-tty
		# * pinentry-mac (installed by pinentry-mac package)
		# Is passed the environment variable PINENTRY_USER_DATA if it is defined; used by pinentry-mac; example usage in an alternative pinentry program is <https://gist.github.com/kevinoid/189a0168ef4ceae76ed669cd696eaa37>.
		pinentry-program /usr/local/bin/pinentry-tty
		allow-loopback-pinentry
		
		# Security
		no-allow-mark-trusted
		enable-extended-key-format
		#s2k-calibration 101
		#s2k-count 35695616
		
		# Runtime security
		ignore-cache-for-signing
		extra-socket /dev/null
		
		# Cache
		default-cache-ttl 600
		default-cache-ttl-ssh 1800
		max-cache-ttl 7200
		max-cache-ttl-ssh 7200
		
		# Passphrases
		enforce-passphrase-constraints
		min-passphrase-len 8
		min-passphrase-nonalpha 1
		#check-passphrase-pattern /path/to/file
		max-passphrase-days 30
		enforce-passphrase-contraints
		
		# Other
		listen-backlog 64
		
		#allow-preset-passphrase
		#no-allow-external-cache
	EOF
	chmod 0400 "$configuration_file_path"
}

# depends rm
# _gpg_connect_agent_data_to_file()
# {
# 	local data_file_path="$1"
# 	local scdaemon_command="$2"
#
# 	local standard_out_file_path
# 	_gnupg_connect_agent "/datafile $data_file_path" "SCD $scdaemon_command"
#
# 	local result="$(< "$standard_out_file_path")"
# 	rm -rf "$standard_out_file_path"
# 	# eg "ERR 100663297 General error <SCD>"
# 	if [ "$result" != 'OK' ]; then
# 		rm -rf "$data_file_path"
# 		exit_error_message "gpg-connect-agent SCD $scdaemon_command failed with $result"
# 	fi
# }
#
# # Requires a variable 'data'.
# depends rm
# _gpg_connect_agent_data()
# {
# 	local scdaemon_command="$1"
#
# 	_gpg_connect_agent_data_to_file "$TMPDIR"/scdaemon-data
# 	data="$(< "$data_file_path")"
# 	rm "$data_file_path"
# }

# gpg_enable_kdf()
# {
# 	# Check for support using GETATTR EXTCAP
# 	# S EXTCAP gc=1+ki=1+fc=1+pd=1+mcl3=2048+aac=1+sm=0+si=5+dec=0+bt=1+kdf=1
# 	# 'kdf=1' in the line above.
#
# 	# Consists of binary data with the following layout (left is lower, right is higher byte) (see gen_kdf_data() in card-util.c):-
# 	#
# 	# h0: 0x81 0x01 0x03
# 	#     0x82 0x01 0x08
# 	#     0x83 0x04
# 	# s2k iterations count (little endian): 0xN1 0xN2 0xN3 0xN3 (eg 0xN1 is (count >> 24) and 0xN3 is (count & 0xFF) )
# 	# h1: 0x84 0x08
# 	# salt_user: 8 (0x08) random bytes
# 	# h2: 0x85 0x08
# 	# salt_reset: 8 (0x08) random bytes
# 	# h3: 0x86 0x08
# 	# salt_admin: 8 (0x08) random bytes
# 	# h4: 0x87 0x20
# 	# kdf data (user): 32 (0x20) bytes, derived from salt_user, s2k iterations count, SHA256, default user pin
# 	# h5: 0x88 0x20
# 	# kdf data (admin): 32 (0x20) bytes, derived from salt_user, s2k iterations count, SHA256, default admin pin
#
# 	# OR
# 	# off: 0x80 0x01 0x00
#
# 	# kdf data is created using gcry_kdf_derive(), a libgcrypt function.
#
# 	local commands="$TMPDIR"/scdaemon-commands
# 	# 90 to 110 bytes
# 	cat >"$commands" <<-EOF
# 		SETATTR KDF xxxxx
# 	EOF
# }

depends tail awk
_gpg_scdaemon()
{
	local commands_file_path="$1"
	
	local output_file_path="$TMPDIR"/scdaemon.standard-out
	_gpg_run_command_scdaemon_foreground "$commands_file_path" "$output_file_path"
	
	local result="$(tail -n 1 "$output_file_path" | awk '{print $1}')"
	case "$result" in
		
		OK)
			:
		;;
		
		ERR)
			{
				printf "Failed to change $user_or_admin PIN\n\n"
				
				printf 'Log\n'
				cat "$TMPDIR"/scdaemon.log
		
				printf 'Standard Out\n'
				cat "$output_file_path"
		
				printf 'Standard Error\n'
				cat "$TMPDIR"/scdaemon.standard-error
		
				printf '\n'
			} 1>&2
			
			exit_error_message "Failed to change $user_or_admin PIN"
		;;	
		
		*)
			exit_error_message "?Failed to change $user_or_admin PIN because $result"
		;;
		
	esac
}

depends grep cut
_gpg_scdaemon_extract()
{
	# One of 'S', 'D' or '#'
	local status_or_data="$1"
	local strip_attribute_name="$2"
	local commands_file_path="$3"
	local data_file_path="$4"
	
	if $strip_attribute_name; then
		local first_field_index=3
	else
		local first_field_index=2
	fi
	
	_gpg_scdaemon "$commands_file_path"
	
	local output_file_path="$TMPDIR"/scdaemon.standard-out
	grep '^S ' "$output_file_path" | cut -d ' ' -f"$first_field_index"- >"$data_file_path"
}

depends cat
gpg_change_pin()
{
	# A PIN seems to be upto 100 UTF-8 characters.
	local user_or_admin="$1"
	local old_pin="$2"
	local new_pin="$3"
	
	# CHV number (Card Holder Verification Vector)
	local chvno
	case "$user_or_admin" in
		
		user)
			chvno=1
		;;
		
		admin)
			chvno=3
		;;
		
		*)
			exit_error_message "Invalid user_or_admin $user_or_admin"
		;;
		
	esac
	
	local commands_file_path="$TMPDIR"/scdaemon-commands
	cat >"$commands_file_path" <<-EOF
		PASSWD ${chvno}

		# Old PIN
		D ${old_pin}%00
		END

		# New PIN
		D ${new_pin}%00
		END
	EOF
	
	_gpg_scdaemon "$commands_file_path"
}

# Known attributes are:-
#
# SERIALNO		D2760001240100000006161332880000
# KEY-FPR		(zero or more lines)
# CHV-STATUS	+1+127+127+127+3+0+3
# DISP-NAME		
# EXTCAP		gc=1+ki=1+fc=1+pd=1+mcl3=2048+aac=1+sm=0+si=5+dec=0+bt=1+kdf=1
# KEY-ATTR		1 1 rsa2048 17 1
#				2 1 rsa2048 17 1
#				3 1 rsa2048 17 1
# KDF			 ?%01%03?%01%08?%04%02@%00%00?%08??s\?˫˅%08?QP??%0B??%08%13????SI??+?F?)?~??knL?Y?%09%1B%2B?%01?%1D<??%1D&n?}?Ո+?r????y?C?|??q?|???%1A?N5???n%13YS
# PUBKEY-URL	(zero or more lines)
# SIG-COUNTER	0
# $SIGNKEYID	OPENPGP.1
# $ENCRKEYID	OPENPGP.2
# $AUTHKEYID	OPENPGP.3
# LOGIN-DATA	(zero or more more lines)
# DISP-LANG		
# DISP-SEX		9
# UIF-1			%00+
# UIF-2			%00+
# UIF-3			%00+
# UIF			
#				%00+
#				%00+
#				%00+
# CA-FPR		(zero or more lines)
# PRIVATE-DO-1	(zero or more lines)
# PRIVATE-DO-2	(zero or more lines)
# PRIVATE-DO-3	(zero or more lines)
# PRIVATE-DO-4	(zero or more lines)
# MANUFACTURER	6 Yubico
# KEY-TIME		?
# AID			?v%00%01$%01%03%04%00%06%16%132?%00%00
# $DISPSERIALNO 16+133+288
# KEY-STATUS
# 				OPENPGP.1 0
# 				OPENPGP.2 0
# 				OPENPGP.3 0
# 				OPENPGP.129 2
# KEY-ATTR-INFO
# OPENPGP.1 rsa2048
# OPENPGP.1 rsa3072
# OPENPGP.1 rsa4096
# OPENPGP.1 nistp256
# OPENPGP.1 nistp384
# OPENPGP.1 nistp521
# OPENPGP.1 secp256k1
# OPENPGP.1 brainpoolP256r1
# OPENPGP.1 brainpoolP384r1
# OPENPGP.1 brainpoolP512r1
# OPENPGP.1 ed25519
# OPENPGP.1 cv25519
# OPENPGP.2 rsa2048
# OPENPGP.2 rsa3072
# OPENPGP.2 rsa4096
# OPENPGP.2 nistp256
# OPENPGP.2 nistp384
# OPENPGP.2 nistp521
# OPENPGP.2 secp256k1
# OPENPGP.2 brainpoolP256r1
# OPENPGP.2 brainpoolP384r1
# OPENPGP.2 brainpoolP512r1
# OPENPGP.2 ed25519
# OPENPGP.2 cv25519
# OPENPGP.3 rsa2048
# OPENPGP.3 rsa3072
# OPENPGP.3 rsa4096
# OPENPGP.3 nistp256
# OPENPGP.3 nistp384
# OPENPGP.3 nistp521
# OPENPGP.3 secp256k1
# OPENPGP.3 brainpoolP256r1
# OPENPGP.3 brainpoolP384r1
# OPENPGP.3 brainpoolP512r1
# OPENPGP.3 ed25519
# OPENPGP.3 cv25519
# OPENPGP.129 rsa2048
# OPENPGP.129 rsa3072
# OPENPGP.129 rsa4096
# OPENPGP.129 nistp256
# OPENPGP.129 nistp384
# OPENPGP.129 nistp521
# OPENPGP.129 secp256k1
# OPENPGP.129 brainpoolP256r1
# OPENPGP.129 brainpoolP384r1
# OPENPGP.129 brainpoolP512r1
# OPENPGP.129 ed25519
# OPENPGP.129 cv25519
#
# Notes
# * KDF
# 	* returns binary data with some escape sequences (eg %08); ? signifies something the terminal could not display (eg a control code).
# * SERIALNO
# 	* starts 'D27600012401' for OpenPGP cards.
# 	* contains Yubico serial number, eg 'D2760001240100000006161332880000' contains 16 133 288 for my Yubico Series 5.
# * LOGIN-DATA
#	* probably only ever set.
# * DISP-SEX
#	* Values are 9 (unset / unknown), 1 (male) and 2 (female)
# * UIF
#	* Values are 0x00 0x20 (off), 0x01 0x20 (on) and 0x02 0x20 (permanent); 0x20 is encoded as a '+'
# * PRIVATE-DO-3 and PRIVATE-DO-4 are unavailable on my yubikey or ?PIN protected?
# Unsure:-
# * CA-FPR-1 / CA-FPR-2 / CA-FPR-3
# * CHV-STATUS-1
gpg_get_attribute()
{
	local attribute="$1"
	local data_file_path="$2"
	
	local commands_file_path="$TMPDIR"/scdaemon-commands
	cat >"$commands_file_path" <<-EOF
		GETATTR ${attribute}
	EOF
	
	_gpg_scdaemon_extract 'S' true "$commands_file_path" "$data_file_path"
}

# Requires a variable, 'attribute_value'.
gpg_get_attribute_value()
{
	local attribute="$1"
	
	local data_file_path="$TMPDIR"/data
	gpg_get_attribute "$attribute" "$data_file_path"
	attribute_value="$(< "$data_file_path")"
}

# Requires a variable, 'attribute_value'.
gpg_get_attribute_value_SERIALNO()
{
	gpg_get_attribute_value SERIALNO
}

# Requires a variable, 'attribute_value'.
gpg_get_attribute_value_DISP_NAME()
{
	gpg_get_attribute_value DISP-NAME
}

# Requires a variable, 'attribute_value'.
gpg_get_attribute_value_SIG_COUNTER()
{
	gpg_get_attribute_value SIG-COUNTER
}

# Requires a variable, 'attribute_value'.
gpg_get_attribute_value_SIGNKEYID()
{
	gpg_get_attribute_value '$SIGNKEYID'
}

# Requires a variable, 'attribute_value'.
gpg_get_attribute_value_ENCRKEYID()
{
	gpg_get_attribute_value '$ENCRKEYID'
}

# Requires a variable, 'attribute_value'.
gpg_get_attribute_value_AUTHKEYID()
{
	gpg_get_attribute_value '$AUTHKEYID'
}

# Requires a variable, 'attribute_value'.
gpg_get_attribute_value_DISP_LANG()
{
	gpg_get_attribute_value 'DISP-LANG'
}

# Requires a variable, 'attribute_value'.
#
# Also called SALUT and SALUTATION.
gpg_get_attribute_value_DISP_SEX()
{
	gpg_get_attribute_value 'DISP-SEX'
}

# Requires a variable, 'attribute_value'.
gpg_get_attribute_value_AID()
{
	gpg_get_attribute_value 'AID'
}

# Requires a variable, 'attribute_value'.
depends tr
gpg_get_attribute_value_DISPSERIALNO()
{
	gpg_get_attribute_value '$DISPSERIALNO'
	
	attribute_value="$(tr '+' ' ' "$attribute_value")"
}

# Returns key-value lines:-
# gc 1
# ki 1
# fc 1
# pd 1
# mcl3 2048
# aac 1
# sm 0
# si 5
# dec 0
# bt 1
# kdf 1
depends tr
gpg_get_attribute_values_EXTCAP()
{
	local data_file_path="$1"
	
	local our_data_file_path="$TMPDIR"/data
	gpg_get_attribute EXTCAP "$our_data_file_path"
	
	tr '+=' '\n ' <"$our_data_file_path" >"$data_file_path"
}

# Sets the variables:-
# pin_x=X
# pin_on=1
# pin_user_length=127
# pin_reset_length=127
# pin_admin_length=127
# pin_user_retries=3
# pin_reset_retries=0
# pin_admin_retries=3
depends sed tr
gpg_get_attribute_values_CHV_STATUS()
{
	local our_data_file_path="$TMPDIR"/data
	gpg_get_attribute CHV-STATUS "$our_data_file_path"
	
	local data_file_path="$TMPDIR"/data.sed
	sed 's/^\+/X+/g' "$our_data_file_path" >"$data_file_path"
	IFS='+' read -r pin_x pin_on pin_user_length pin_reset_length pin_admin_length pin_user_retries pin_reset_retries pin_admin_retries <"$data_file_path"
}

# Sets the variables:-
# manufacturer_code=6
# manufacturer_name=Yubico
gpg_get_attribute_values_CHV_STATUS()
{
	local our_data_file_path="$TMPDIR"/data
	gpg_get_attribute MANUFACTURER "$our_data_file_path"
	
	IFS=' ' read -r manufacturer_code manufacturer_name <"$data_file_path"
}

gpg_set_attribute_value()
{
	local attribute_name="$1"
	local attribute_value="$2"
	local admin_pin="$3"
	
	local commands_file_path="$TMPDIR"/scdaemon-commands
	cat >"$commands_file_path" <<-EOF
		SETATTR ${attribute_name} ${attribute_value}
		D ${admin_pin}%00
		END
	EOF
}

gpg_set_attribute_KEY_ATTR()
{
	# This is a slot number, 1, 2, 3 or 129 without the leading 'OPENPGP.'.
	local slot_number="$1"
	local algorithm="$2"
	local admin_pin="$3"

	# 1		RSA			Encrypt or Sign
	# 2		RSA			Encrypt Only; sometimes called RSA-E; legacy
	# 3		RSA			Sign Only; sometimes called RSA-S; legacy
	# 16	ElGamal		Encrypt Only
	# 17	DSA
	# 18	ECDH		RFC 6637
	# 19	ECDSA		RFC 6637
	# 22	EdDSA		(Unofficial)
	local algorithm_identifier
	local algorithm_details
	case "$algorithm" in
		
		rsa2048)
			algorithm_identifier=1
			algorithm_details=rsa2048
		;;
		
		rsa3072)
			algorithm_identifier=1
			algorithm_details=rsa3072
		;;
		
		rsa4096)
			algorithm_identifier=1
			algorithm_details=rsa4096
		;;
		
		nistp256)
			algorithm_identifier=19
			algorithm_details=nistp256
		;;
		
		nistp384)
			algorithm_identifier=19
			algorithm_details=nistp384
		;;
		
		nistp521)
			algorithm_identifier=19
			algorithm_details=nistp521
		;;
		
		secp256k1)
			algorithm_identifier=19
			algorithm_details=secp256k1
		;;
		
		brainpoolP256r1)
			algorithm_identifier=19
			algorithm_details=brainpoolP256r1
		;;
		
		brainpoolP384r1)
			algorithm_identifier=19
			algorithm_details=brainpoolP384r1
		;;
		
		brainpoolP512r1)
			algorithm_identifier=19
			algorithm_details=brainpoolP512r1
		;;
		
		ed25519)
			algorithm_identifier=22
			algorithm_details=ed25519
		;;
		
		cv25519)
			algorithm_identifier=22
			algorithm_details=cv25519
		;;
		
		*)
			exit_error_message "Unsupported algorithm $algorithm"
		;;
		
	esac
	
	local commands_file_path="$TMPDIR"/scdaemon-commands
	cat >"$commands_file_path" <<-EOF
		SETATTR KEY-ATTR --force ${slot_number} ${algorithm_identifier} ${algorithm_details}
		D ${admin_pin}%00
		END
	EOF
	
	_gpg_scdaemon "$commands_file_path"
}

depends date
gpg_iso_date_for_now()
{
	date -j -u '+%Y%m%dT%H%M%SZ'
}

# Returns in data_file_path for ed25519:-
# 
# PINCACHE_PUT 0/openpgp/3 1B369C16DA4E771E3AAFF1F6BCDEA185E1E7D62B205C5711
# KEY-CREATED-AT 1625070085
# KEY-DATA q 40E19ED509E06FF89B797B168C5B26219402AF63B3C9D21BC73AA399A8FD12769B
# KEY-DATA curve 092B06010401DA470F01
# KEY-FPR F9B00702FFC1952732D27D83F6717F720D817790
#
# And for rsa4096:-
# 
# PINCACHE_PUT 0/openpgp/3 513071DBCCCFC0609DE88D1AD5849479278835F3E18CCCEB
# KEY-CREATED-AT 1625070085
# KEY-DATA n C7CD603E5776703737AC4D6CBB6BA8E65EC570869203131FC8954BDC53BCC73F6B7D5DA67E83ACE2BBFD15C55C4945900F440DE99D3ADFC6D245F4F6E489268DD28E4A3A1F5311007B59B85D127710B71534D019B720A96F9FFD3F048902AFCD5856A4928B9C008C8DEB417BE7606F0DAFFF25D54EBBC3C0225C1006FBB8BAF1BD02C6B007CF1B26006B2C3419B389706EF4D694D14FF812521FC1F637AB2E636C3416283376F4A9AF3B9DCC446D5270B3D2386CC236E7F4E218064397500EED51D8318CDADE9EA431CC78D36F3DC0A082AE38FEDFCC9A3B3F989AE6A034CB0B75AE6244939E652CA751D3D3DC99EE1C4EB666027AF3A636921F1F4AB4155035
# KEY-DATA e 010001
# KEY-FPR 8B3DE1989C22E2E8488C1CAD91C64D3791F3464A
depends date
gpg_generate_key()
{
	local slot_number="$1"
	local admin_pin="$2"
	local data_file_path="$3"
	local iso_date="$4"
	
	local commands_file_path="$TMPDIR"/scdaemon-commands
	cat >"$commands_file_path" <<-EOF
		GENKEY --force --timestamp=${iso_date} OPENPGP.${slot_number}
		D ${admin_pin}%00
		END
	EOF
	
	_gpg_scdaemon_extract 'S' false "$commands_file_path" "$data_file_path"
}