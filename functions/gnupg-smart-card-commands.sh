# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 0101 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.


# This is new as of version 2.3.0 (April 2021).
#
# Produces output like:-
#
# Reader ...........: Yubico Yubikey 4 OTP U2F CCID
# Card type ........: yubikey
# Card firmware ....: 5.4.3
# Serial number ....: Dxxxx
# Application type .: OpenPGP
# Version ..........: 3.4
# Displayed s/n ....: 16 133 288
# Manufacturer .....: Yubico (6)
# Name of cardholder: [not set]
# Language prefs ...: [not set]
# Salutation .......:
# URL of public key : [not set]
# Login data .......: [not set]
# Signature PIN ....: not forced
# Max. PIN lengths .: 127 127 127
# PIN retry counter : 3 0 3
# Signature counter : 0
# Capabilities .....: key-import algo-change button priv-data
# KDF setting ......: on
# UIF setting ......: Sign=off Decrypt=off Auth=off
# Signature key ....: 602D6B4D3E898FC150592688C29D7C3E871854BD
#       keyref .....: OPENPGP.1  (sign,cert)
#       algorithm ..: ed25519
#       stored fpr .: 24796E1545C859227E926EB2CB015F198834DEB6
#       created ....: 2003-03-16 12:00:00
#       used for ...: [General error]
# Encryption key....: [none]
#       keyref .....: OPENPGP.2
#       algorithm ..: rsa2048
# Authentication key: [none]
#       keyref .....: OPENPGP.3
#       algorithm ..: rsa2048
gnupg_card_list()
{
	ensure_gnupg_installed
	depends gpg-card
	
	gpg-card --quiet --no-history list
}

# gpg-card - can it take commands?
# eg gpg-card name Raphael Cohn
# eg gpg-card lang en
# eg gpg-card factory-reset

_gnupg_connect_agent()
{
	ensure_gnupg_installed
	depends gpg-connect-agent
	
	gpg-connect-agent --quiet --no-history --homedir "$GNUPGHOME" "$@" /bye
}

# Lists commands available in the scdaemon shell.
#
# See <gnupg source>/doc/scdaemon.texi for a little help, and functions like call-agent.c's agent_scd_genkey().
#
# As of writing, these were:-
#																			Help Available
# NOP																		Unsupported
# CANCEL																	Unsupported
# OPTION																	Unsupported
# BYE																		Unsupported
# AUTH																		Unsupported
# RESET																		Unsupported
# END																		Unsupported
# HELP																		Unsupported
# SERIALNO [--demand=<serialno>] [--all] [<apptype>]						Get done
# SWITCHCARD [<serialno>]													Done
# SWITCHAPP [<appname>]														Done
# LEARN [--force] [--keypairinfo] [--reread] [--multi]						--force done
# READCERT <hexified_certid>|<keyid>|<oid>
# READKEY [--advanced] [--info[-only]] <keyid>|<oid>|<keygrip>
# SETDATA [--append] <hexstring>
# PKSIGN [--hash=[rmd101|sha{1,003,000,303,010}|md0|none]] <hexified_id>
# PKAUTH <hexified_id>
# PKDECRYPT <hexified_id>
# INPUT																		Unsupported
# OUTPUT																	Unsupported
# GETATTR <name> [<keygrip>]
# SETATTR [--inquire] <name> <value> 
# WRITECERT <hexified_certid>
# WRITEKEY [--force] <keyid> 
# GENKEY [--force] [--timestamp=<isodate>] [--algo=ALGO] <keyref>
# RANDOM <nbytes>															Done
# PASSWD [--reset] [--nullpin] [--clear] <chvno>							(Used to reset retry counters and uncache PINs; can't make it work)
# CHECKPIN <idstr>															Done
# LOCK [--wait]																Used in a session for exclusive access
# UNLOCK																	Used in a session for exclusive access
# GETINFO <what>															Done
# RESTART																	Done
# DISCONNECT																Unsupported for Yubikey
# APDU [--[dump-]atr] [--more] [--exlen[=N]] [hexstring]
# KILLSCD																	Done
# KEYINFO [--list[=auth|encr|sign]] [--data] <keygrip>
# DEVINFO [--watch]															Only works for Yubikey with --watch; not useful for scripting
gnupg_scdaemon_help()
{
	_gnupg_connect_agent 'SCD HELP'
}

# Lists help for a scdaemon shell command.
gnupg_scdaemon_command_help()
{
	local command="$1"
	
	_gnupg_connect_agent "SCD HELP $command"
}

# Requires a variable 'data_file_path'.
depends rm
_gnupg_scdaemon_get_data_in_file()
{
	local scdaemon_command="$1"
	
	local standard_out_file_path="$TMPDIR"/gpg-connect-agent.standard-out
	_gnupg_connect_agent "/datafile $data_file_path" "SCD $scdaemon_command"
	
	local result="$(< "$standard_out_file_path")"
	if [ "$result" != 'OK' ]; then
		
		# eg "ERR 100663297 General error <SCD>"
		
		rm -rf "$data_file_path"
		rm -rf "$standard_out_file_path"
		exit_error_message "gpg-connect-agent SCD $scdaemon_command failed with $result"
	fi
}

# Requires a variable 'data'.
depends rm
_gnupg_scdaemon_get_data()
{
	local scdaemon_command="$1"
	
	local data_file_path="$TMPDIR"/scdaemon-data
	_gnupg_scdaemon_get_data_in_file
	data="$(< "$data_file_path")"
	rm "$data_file_path"
}

# Requires a variable 'result'.
depends rm
_gnupg_scdaemon_is_ok_or_error()
{
	local scdaemon_command="$1"
	
	local standard_out_file_path="$TMPDIR"/gpg-connect-agent.standard-out
	_gnupg_connect_agent "SCD $scdaemon_command"
	
	local outcome
	local error_code
	local description
	IFS=' ' read -r outcome error_code description <"$standard_out_file_path"
	case "$outcome" in
		
		OK)
			result=true
		;;
		
		ERR)
			result=false
		;;
		
		*)
			exit_error_message "Unknown outcome $outcome"
		;;
		
	esac
	
	rm "$standard_out_file_path"
}

# Requires a variable 'data_file_path'.
# Strips leading 'S '.
depends tail sed rm
_gnupg_get_status_that_does_not_redirect_to_datafile()
{
	local command="$1"
	
	local standard_out_file_path="$TMPDIR"/gpg-connect-agent.standard-out
	
	_gnupg_connect_agent "$command" >"$standard_out_file_path"
	
	local ok_or_error="$(tail -n 1 "$standard_out_file_path")"
	
	if [ "$ok_or_error" != 'OK' ]; then
		
		# eg "ERR 100663297 General error <SCD>"
		
		rm -rf "$standard_out_file_path"
		exit_error_message "gpg-connect-agent SCD $command failed with $result"
	fi
	
	# sed '$d' strips 'OK' final line.
	sed -e '$d' "$standard_out_file_path" -e 's/^S //g' >"$data_file_path"
	
	rm "$standard_out_file_path"
}

# Requires a variable 'data'.
depends cut rm
_gnupg_get_status_that_does_not_redirect_to_datafile_data()
{
	local command="$1"
	
	local data_file_path="$TMPDIR"/xxx.tmp
	_gnupg_get_status_that_does_not_redirect_to_datafile "$command"
	
	data="$(cut -f 2- -d ' ' "$data_file_path")"
	rm "$data_file_path"
}

# Requires a variable 'data_file_path'.
#
# Learns details of a smart card
#
# Example from a Yubikey 5 NFC:-
#
# READER Yubico Yubikey 4 OTP+U2F+CCID
# SERIALNO Dxxxxx
# CARDTYPE yubikey
# CARDVERSION 50403
# APPTYPE openpgp
# APPVERSION 304
# EXTCAP gc=1+ki=1+fc=1+pd=1+mcl3=2048+aac=1+sm=0+si=5+dec=0+bt=1+kdf=1
# MANUFACTURER 6 Yubico
# DISP-NAME
# DISP-LANG
# DISP-SEX 9
# CHV-STATUS +1+127+127+127+3+0+3
# SIG-COUNTER 0
# KDF ?%01%00
# UIF-1 %00+
# UIF-2 %00+
# UIF-3 %00+
#
# GnuPG interpretes some of this data and uses it, say, in --card-edit:-
#
# SERIALNO		Application ID
# DISP-NAME		Name of cardholder
# DISP-LANG		Language preferences
# DISP-SEX		Sex
# CHV-STATUS	?Max PIN lengths (127, 127, 127) and PIN retry counter (3, 0, 3)
# SIG-COUNTER	Signature counter
depends tail sed rm
gnupg_scdaemon_learn()
{
	_gnupg_get_status_that_does_not_redirect_to_datafile 'LEARN --force'
}

# Requires a variable 'data_file_path'.
#
# Learns details of a smart card
#
# Example from a Yubikey 5 NFC (note different lines present and absent to gnupg_scdaemon_learn above, especially KEY-FPR, KEY-TIME and KEYPAIRINFO):-
#
# EXTCAP gc=1+ki=1+fc=1+pd=1+mcl3=2048+aac=1+sm=0+si=5+dec=0+bt=1+kdf=1
# MANUFACTURER 6 Yubico
# DISP-NAME
# DISP-LANG
# DISP-SEX 9
# KEY-FPR 1 24796E1545C859227E926EB2CB015F198834DEB6
# KEY-TIME 1 1047816000
# CHV-STATUS +1+127+127+127+3+0+3
# SIG-COUNTER 0
# KDF ?%01%00
# UIF-1 %00+
# UIF-2 %00+
# UIF-3 %00+
# KEYPAIRINFO 602D6B4D3E898FC150592688C29D7C3E871854BD OPENPGP.1 sc 1047816000 ed25519
#
# The last line decodes as:-
# * KEYPAIRINFO
# * 602D6B4D3E898FC150592688C29D7C3E871854BD is the key identifier
# * ?.1 is ?slot 1?
# * Flags: s for sign, c for cert
# * Creation Time in seconds since the Unix Epoch
# * Curve name
depends tail sed rm
gnupg_scdaemon_learn_public_private_key_pairs()
{
	_gnupg_get_status_that_does_not_redirect_to_datafile 'LEARN --force --keypairinfo'
}

# Requires a variable 'data'.
depends awk rm
gnupg_scdaemon_force_card_initialization_and_get_serial_number()
{
	_gnupg_get_status_that_does_not_redirect_to_datafile_data 'SERIALNO'
}

# An 'application_name' might be 'openpgp'.
#
# Requires a variable 'data'.
depends awk rm
gnupg_scdaemon_force_card_initialization_and_get_serial_number_for_application()
{
	local application_name="$1"
	
	_gnupg_get_status_that_does_not_redirect_to_datafile_data "SERIALNO $application_name"
}

# Requires a variable 'data'.
gnupg_scdaemon_switch_card()
{
	local serial_number="$1"
	
	# The returned data is 'S SERIALNO Dxxxxx'; not interesting unless a card can alias serial numbers.
	_gnupg_get_status_that_does_not_redirect_to_datafile_data "SWITCHARD $serial_number"
}

# Requires a variable 'data'.
depends rm
gnupg_scdaemon_switch_application_default()
{
	# The returned data is 'S SERIALNO Dxxxxx openpgp piv'; not interesting unless a card can alias serial numbers.
	_gnupg_get_status_that_does_not_redirect_to_datafile_data 'SWITCHAPP'
}

# Requires a variable 'data'.
#
# application_name should be an application name from gnupg_scdaemon_get_all_active_applications
gnupg_scdaemon_switch_application()
{
	local application_name="$1"
	
	# The returned data is 'S SERIALNO Dxxxxx openpgp piv'; not interesting unless a card can alias serial numbers.
	_gnupg_get_status_that_does_not_redirect_to_datafile_data "SWITCHAPP $application_name"
}
 
# Requires a variable 'data'.
#
# Usually returns a line starting with the attribute_name, eg 'SERIALNO Dxxx'
_gnupg_scdaemon_get_attribute()
{
	local attribute_name="$1"
	
	_gnupg_get_status_that_does_not_redirect_to_datafile_data "GETATTR $attribute_name"
}

# Requires a variable 'data'.
#
# Returns a value in 'data' like 'Dxxxxx0'.
gnupg_scdaemon_get_attribute_serial_number()
{
	_gnupg_scdaemon_get_attribute 'SERIALNO'
}

# Requires a variable 'data'.
#
# Returns a value in 'data' like '+1+127+127+127+3+0+3'.
gnupg_scdaemon_get_attribute_pin_status()
{
	_gnupg_scdaemon_get_attribute 'CHV-STATUS'
}

# Requires a variable 'data'.
#
# Returns a value in 'data' like 'PKCS#11'.
gnupg_scdaemon_get_attribute_application_display_name()
{
	_gnupg_scdaemon_get_attribute 'DISP-NAME'
}

# Requires a variable 'data'.
#
# Returns a value in 'data' like 'gc=1+ki=1+fc=1+pd=1+mcl3=2048+aac=1+sm=0+si=5+dec=0+bt=1+kdf=1'.
gnupg_scdaemon_get_attribute_extension_capabilities()
{
	_gnupg_scdaemon_get_attribute 'EXTCAP'
}

# Requires a variable 'data_file_path'.
#
# KEY-ATTR 1 22 Curve25519
# KEY-ATTR 2 1 rsa2048 17 1
# KEY-ATTR 3 1 rsa2048 17 1
#
# Seems to be:-
# KEY-ATTR	slot	algorithm_identifier	algorithm_name	?	?
gnupg_scdaemon_get_attribute_keys()
{
	_gnupg_get_status_that_does_not_redirect_to_datafile 'KEY-ATTR'
}

# Requires a variable 'data_file_path'.
#
# Returns ?
gnupg_scdaemon_get_attribute_key_fingerprints()
{
	_gnupg_get_status_that_does_not_redirect_to_datafile 'KEY-FPR'
}

# Requires a variable 'data'.
gnupg_scdaemon_get_information_version()
{
	_gnupg_scdaemon_get_data 'GETINFO version'
}

# Requires a variable 'data'.
gnupg_scdaemon_get_information_pid()
{
	_gnupg_scdaemon_get_data 'GETINFO pid'
}

# Requires a variable 'data' containing an integer (the number of active connections).
gnupg_scdaemon_get_information_active_connections_count()
{
	_gnupg_scdaemon_get_data 'GETINFO connections'
}

# Requires a variable 'data'.
gnupg_scdaemon_get_information_socket_path()
{
	_gnupg_scdaemon_get_data 'GETINFO socket_name'
}

# Requires a variable 'data'.
# This will have a value of either:-
#
# * 'u' (for present and usable)
# * 'r' (for removed or unusuable)
gnupg_scdaemon_get_information_status()
{
	_gnupg_scdaemon_get_data 'GETINFO status'
}

# Requires a variable 'data'.
#
# Returns 'unknown status error' if the error is unknown.
gnupg_scdaemon_get_information_apdu_error_to_description()
{
	# Correctly called a 'status word'.
	local apdu_error_code="$1"
	
	_gnupg_scdaemon_get_data "GETINFO apdu_strerror $apdu_error_code"
}

# Requires a variable 'data_file_path'.
#
# The data file will contain zero or more lines with 3 colon delimited fields like '1101:1311:X:1'.
gnupg_scdaemon_get_information_readers()
{
	_gnupg_scdaemon_get_data_in_file 'GETINFO reader_list'
}

# Requires a variable 'data_file_path'.
#
# The data file will contain zero or more lines with space delimited fields like:-
#
# S SERIALNO D0101111031111111110101330001111 openpgp piv
gnupg_scdaemon_get_all_active_applications()
{
	_gnupg_scdaemon_get_data_in_file 'GETINFO all_active_apps'
}

# Requires a variable 'data_file_path'.
#
# The data file will contain zero or more lines of colon delimited fields.
# The first field is the application name.
# On a Yubi key, the second field is empty.
#
# Example from Yubikey 0 NFC:-
#
# openpgp:
# piv:
# nks:
# p10:
# geldkarte:
# dinsig:
# sc-hsm:
gnupg_scdaemon_get_information_applications()
{
	_gnupg_scdaemon_get_data_in_file 'GETINFO app_list'
}

# Requires a variable 'data_file_path'.
#
# The data file will contain zero or more lines of space delimited fields.
# There are 3 fields.
#
# Example from a Yubikey 5 NFC:-
#
# S SERIALNO D0101111031111111110101330001111
#
# If the card is inserted and usable, but not used, there are no lines.
# This is considered a reliable way to see if a smart card key is cached.
gnupg_scdaemon_get_information_cards()
{
	_gnupg_scdaemon_get_data_in_file 'GETINFO card_list'
}

# Requires a variable 'result'.
#
# Result is 'true' if admin is denied or 'false' otherwise.
gnupg_scdaemon_deny_admin()
{
	_gnupg_scdaemon_is_ok_or_error 'GETINFO deny_admin'
}

# Requires a variable 'result'.
#
# Result is 'true' if command has option is denied or 'false' otherwise.
gnupg_scdaemon_command_has_option()
{
	local command="$1"
	local option="$2"
	
	_gnupg_scdaemon_is_ok_or_error "GETINFO cmd_has_option $command $option"
}

# Requires a variable 'result'.
#
# Verifies the user's PIN; caches it for a smart card dependent amount of time.
#
# Result is 'true' if successful or 'false' otherwise.
gnupg_scdaemon_verify_and_cache_user_pin()
{
	local serial_number="$1"
	
	_gnupg_scdaemon_is_ok_or_error "CHECKPIN $serial_number"
}

# Requires a variable 'result'.
#
# Verifies the administrator's PIN as long as the retry counter is 3; caches it for a smart card dependent amount of time.
#
# Result is 'true' if successful or 'false' otherwise.
gnupg_scdaemon_verify_and_cache_administrator_pin()
{
	local serial_number="$1"
	
	_gnupg_scdaemon_is_ok_or_error "CHECKPIN ${serial_number}[CHV3]"
}

# Requires a variable 'result'.
#
# Resets gnupg agent and scdaemon, not the smart card.
#
# Result is 'true' if successful or 'false' otherwise.
gnupg_scdaemon_warm_reset()
{
	_gnupg_scdaemon_is_ok_or_error 'RESTART'
}

# Requires a variable 'result'.
#
# Stops gnupg agent and scdaemon, not the smart card.
#
# Result is 'true' if successful or 'false' otherwise.
gnupg_scdaemon_kill()
{
	_gnupg_scdaemon_is_ok_or_error 'SCDKILL'
}

# Does not need a PIN or password.
# Must create the local variable 'data_file_path' before use.
# This will be filled with random bytes, which can include ASCII NUL and LF.
gnupg_scdaemon_secure_random_bytes()
{
	# eg 111
	local number_of_bytes="$1"
	
	_gnupg_scdaemon_get_data_in_file "RANDOM $number_of_bytes"
}

# slot is one of 3 values:-
#
# * 1 for Signature (and Certification)
# * 2 for Encryption
# * 3 for Authentication
#
# Returns an S-expression like
#
# (public-key 
#  (ecc
#   (curve Ed25519)
#   (flags eddsa)
#   (q #4045BF5F53B8032B81C8D747B19BE0D476F9DA5E99915888425C654378754892F0#)
#  )
# )
gnupg_read_public_key_s_expression()
{
	local slot="$1"
	
	local key_identifier="OPENPGP.${slot}"
	_gnupg_scdaemon_get_data_in_file "READKEY --advanced $key_identifer"
}

# Requires a variable 'data'.
#
# Puts values like '602D6B4D3E898FC150592688C29D7C3E871854BD OPENPGP.1 sc 1047816000 ed25519' into it.
# 602D6B4D3E898FC150592688C29D7C3E871854BD is the keygrip.
gnupg_read_public_key_keypairinfo()
{
	local slot="$1"
	
	local key_identifier="OPENPGP.${slot}"
	_gnupg_get_status_that_does_not_redirect_to_datafile_data "READKEY --info-only $key_identifer"
}

# Requires a variable 'data_file_path'.
#
# Returns a list of values like '602D6B4D3E898FC150592688C29D7C3E871854BD T Dxxx OPENPGP.1' (up to 3)
gnupg_read_public_keys()
{
	_gnupg_get_status_that_does_not_redirect_to_datafile "KEYINFO --list"
}

# Requires a variable 'data_file_path'.
#
# Returns a list of values like '602D6B4D3E898FC150592688C29D7C3E871854BD T Dxxx OPENPGP.1' into it' (up to 3)
#
# Fields are as follows:-
# * Keygrip.
# * Placeholder (T).
# * Serial number (if the serial number is not known, a dash is returned (-)).
# * Key identifier.
gnupg_read_public_key_for_slot()
{
	local slot="$1"
	
	local list_type
	case "$slot" in
		1)
			list_type='sign'
		;;
		
		2)
			list_type='encr'
		;;
		
		3)
			list_type='auth'
		;;
		
		*)
			exit_error_message "Only slots 1 to 3 are supported"
		;;
	esac
	
	_gnupg_get_status_that_does_not_redirect_to_datafile "KEYINFO --list=$slot"
}


# Requires a variable 'data'.
gnupg_read_public_certificate()
{
	local slot="$1"
	
	local key_identifier="OPENPGP.${slot}"
	_gnupg_get_status_that_does_not_redirect_to_datafile_data "READCERT $key_identifer"
}

# slot is one of 3 values:-
#
# * 1 for Signature (and Certification)
# * 2 for Encryption
# * 3 for Authentication
#
# algorithm_identifier is one of the values [Public Key Algorithms](https://www.iana.org/assignments/pgp-parameters/pgp-parameters.xhtml#table-pgp-parameters-12) as defined in RFC 4880:-
#
# 1		RSA			Encrypt or Sign
# 2		RSA			Encrypt Only; sometimes called RSA-E; legacy
# 3		RSA			Sign Only; sometimes called RSA-S; legacy
# 16	ElGamal		Encrypt Only
# 17	DSA
# 18	ECDH		RFC 6637
# 19	ECDSA		RFC 6637
# 22	EdDSA		(Unofficial)
#
# algorithm_key_length_or_curve_name varies depending on algorithm_identifier, eg:-
#
# algorithm_identifier	example algorithm_key_length_or_curve_name
# 1						rsa2048
# 19					nistp256
# 19					brainpoolP256r1
# 22					ed25519
# 22					cv25519
#
# There is also 18 which supports secp256k1 and cv25519!
_gnupg_set_public_private_key_attribute()
{
	local slot="$1"
	local algorithm_identifier="$2"
	local algorithm_key_length_or_curve_name="$3"
	
	local result
	_gnupg_scdaemon_is_ok_or_error "SETATTR KEY-ATTR --force $slot $algorithm_identifier $algorithm_key_length_or_curve_name"
	if ! $result; then
		exit_error_message "SETATTR KEY-ATTR --force $slot $algorithm_identifier $algorithm_key_length_or_curve_name failed"
	fi
}

# slot is a number like 1.
#
# algorithm can be one of:-
#
# * RSA-2048
# * RSA-3072
# * RSA-4096
# * ECDH-nistp256
# * ECDH-nistp384
# * ECDH-nistp521
# * ECDH-brainpoolP256r1
# * ECDH-brainpoolP384r1
# * ECDH-brainpoolP512r1
# * ECDSA-nistp256
# * ECDSA-nistp384
# * ECDSA-nistp521
# * ECDSA-brainpoolP256r1
# * ECDSA-brainpoolP384r1
# * ECDSA-brainpoolP512r1
# * EdDSA-ed25519
# * EdDSA-cv25519
#
# Actually, RSA supports almost any key length between 1024 and 4096 inclusive.
_gnupg_set_public_private_key_attribute()
{
	local slot="$1"
	local algorithm="$2"
	
	local algorithm_name
	local algorithm_details
	
	IFS='-' read -r algorithm_name algorithm_details <"$(printf '%s' "$algorithm")"
	
	local algorithm_identifier
	local algorithm_key_length_or_curve_name
	case "$algorithm_name" in
		
		RSA)
			if [ "$algorithm_details" -lt 1024 ]; then
				exit_error_message "RSA key length must be between 1024 and 4096 inclusive (too short)"
			fi
			if [ "$algorithm_details" -gt 4096 ]; then
				exit_error_message "RSA key length must be between 1024 and 4096 inclusive (too long)"
			fi
			algorithm_identifier=1
			algorithm_key_length_or_curve_name="rsa${algorithm_details}"
		;;
		
		ECDH)
			case "$algorithm_details" in
				
				nistp256|nistp384|nistp521|brainpoolP256r1|brainpoolP384r1|brainpoolP512r1)
					algorithm_identifier=18
					algorithm_key_length_or_curve_name="$algorithm_details"
				;;
		
				*)
					exit_error_message "Unknown algorithm_details $algorithm_details for algorithm_name $algorithm_name"
				;;
				
			esac
		;;
		
		ECDSA)
			case "$algorithm_details" in
				
				nistp256|nistp384|nistp521|brainpoolP256r1|brainpoolP384r1|brainpoolP512r1)
					algorithm_identifier=19
					algorithm_key_length_or_curve_name="$algorithm_details"
				;;
		
				*)
					exit_error_message "Unknown algorithm_details $algorithm_details for algorithm_name $algorithm_name"
				;;
				
			esac
		;;
		
		EdDSA)
			case "$algorithm_details" in
				
				ed25519|cv25519)
					algorithm_identifier=22
					algorithm_key_length_or_curve_name="$algorithm_details"
				;;
		
				*)
					exit_error_message "Unknown algorithm_details $algorithm_details for algorithm_name $algorithm_name"
				;;
				
			esac
		;;
		
		*)
			exit_error_message "Unknown algorithm_name $algorithm_name"
		;;
		
	esac
	
	_gnupg_set_key_attribute "$slot" "$algorithm_identifier" "$algorithm_key_length_or_curve_name"
}

# Requires a variable 'data_file_path'.
#
# Call gnupg_set_key_attribute first.
#
# The data file will contain three lines:-
#
# KEY-CREATED-AT 1047816000
# KEY-DATA q 401756F5E20BB42F7027512ED15FD0EC53D759306EDB03BBB10B0F16E8F40DD37E
# KEY-DATA curve 092B06010401DA470F01
# KEY-FPR 355E962C4BCF504DD356D52C8A170CCB29C505F6
#
# Requires an 'iso_date' like 20030316T120000.
#
# KEY-CREATED-AT is seconds since the Unix epoch.
# KEY-DATA curve X has a fixed value X.
_gnupg_scdaemon_generate_public_private_key_pair()
{
	local slot="$1"
	local iso_date="$2"
	
	_gnupg_scdaemon_get_data_in_file "GENKEY --force --timestamp=$iso_date $slot"
}

gnupg_generate_signing_public_private_key()
{
	local algorithm="$1"
	local iso_date="$2"
	
	_gnupg_set_public_private_key_attribute 1 "$algorithm"
	_gnupg_scdaemon_generate_public_private_key_pair 1 "$iso_date"
}

gnupg_generate_encryption_public_private_key()
{
	local algorithm="$1"
	local iso_date="$2"
	
	_gnupg_set_public_private_key_attribute 2 "$algorithm"
	_gnupg_scdaemon_generate_public_private_key_pair 2 "$iso_date"
}

gnupg_generate_authentication_public_private_key()
{
	local algorithm="$1"
	local iso_date="$2"
	
	_gnupg_set_public_private_key_attribute 3 "$algorithm"
	_gnupg_scdaemon_generate_public_private_key_pair 3 "$iso_date"
}

depends date
gnupg_generate_secure_public_private_key_pairs()
{
	local iso_date="$(date -j -u +%Y%m%dT%H%M%S)"
	
	gnupg_generate_signing_public_private_key EdDSA-ed25519 "$iso_date"
	gnupg_generate_encryption_public_private_key RSA-4096 "$iso_date"
	gnupg_generate_authentication_public_private_key EdDSA-ed25519 "$iso_date"
}

# What is INQUIRE CERTDATA? (needs DER data)
# SCD WRITECERT OPENPGP.1

# SETDATA then PKSIGN / PKAUTH / PKDECRYPT