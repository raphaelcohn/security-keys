# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.


# Depends on modhex installed by the brew package libyubikey.
_yubikey_modhex()
{
	brew_ensure_binary libyubikey modhex
	depends modhex
	
	modhex "$@"
}

# Encodes an ASCII string to a MODHEX string.
#
# ModHex only contains the letters c b d e f g h i j k l n r t u v.
# It is intended to work on any keyboard layout.
yubikey_modhex_encode_ascii_to_modhex()
{
	local ascii_string="$1"
	
	_yubikey_modhex "$ascii_string"
}

# Decodes a MODHEX string to an ASCII string
yubikey_modhex_decode_ascii_to_modhex()
{
	local modhex_string="$1"
	
	_yubikey_modhex -d "$modhex_string"
}

# Hexadecimal numbers must have even numbers of digits.
yubikey_encode_hexadecimal_number_to_modhex()
{
	local hexadecimal_number="$1"
	
	_yubikey_modhex -h "$ascii_string"
}

# Hexadecimal numbers must have even numbers of digits.
yubikey_decode_modhex_to_hexadecimal_number()
{
	local hexadecimal_number="$1"
	
	_yubikey_modhex -d -h "$ascii_string"
}

yubikey_generate()
{
	brew_ensure_binary libyubikey ykgenerate
	
	local AESKEY_hex_encoded="$1"
	local YK_INTERNALNAME_hex_encoded_48_bits="$2"
	local YK_COUNTER_hex_encoded_16_bits="$3"
	local YK_LOW_hex_encoded_16_bits="$4"
	local YK_HIGH_hex_encoded_8_bits="$5"
	local YK_USE_hex_encoded_8_bits="$6"
	
	ykgenerate "$AESKEY_hex_encoded" "$YK_INTERNALNAME_hex_encoded_48_bits" "$YK_COUNTER_hex_encoded_16_bits" "$YK_LOW_hex_encoded_16_bits" "$YK_HIGH_hex_encoded_8_bits" "$YK_USE_hex_encoded_8_bits"
 }

yubikey_parse()
{
	brew_ensure_binary libyubikey ykparse
	
	local AESKEY_hex_encoded_32_characters="$1"
	local TOKEN_modhex_encoded="$2"
	
	ykparse "$AESKEY_hex_encoded_32_characters" "$TOKEN_modhex_encoded"
}

# A more script friendly tool for finding yubi key information than ykman.
# 
# Depends on ykinfo installed by the brew package ykpers.
# Recognized flags are:-
# -s	Serial Number eg 16133288
# -m	Serial Number (modhex) eg vhdrlj
# -H	Serial Number (hex) eg f62ca8
# -v	Version eg 5.4.3
# -t	Touch Level eg 1536
# -1	Slot 1 status (1 or 0) eg 0
# -2	Slot 2 status (1 or 0) eg 0
# -p	Programming Sequence eg 0
# -i	Vendor Id (USB VID) eg 1050
# -I	Product Id (USB PID) eg 407
# -c	Capabilities long hexadecimal string eg 2e0102033f0302033f020400f62ca804010105030504030602000007010f0801000d02033f0e02033f0a01000f0100
# One or more flags can be specified.
# Duplicate flags are allowed, but only the first instance is acted on.
# Output is one line per flag, sorted by the order of flags on the command line.
_yubikey_info()
{
	brew_ensure_binary ykpers ykinfo
	
	ykinfo -q "$@"
}

yubikey_info_serial_number()
{
	_yubikey_info -s
}

yubikey_info_version()
{
	_yubikey_info -v
}

yubikey_info_touch_level()
{
	_yubikey_info -t
}

# This is really a legacy feature.
_yubikey_ykpersonalize()
{
	brew_ensure_binary ykpers ykpersonalize
	
	ykpersonalize -y "$@"
}

# Provides a PKCS#11 (Cryptoki) module called YKCS11 and a tool to manage PIV at a slightly lower level.
#
# See https://developers.yubico.com/yubico-piv-tool/YKCS11/
#
# In particular, allows the setting of the CHUID and CCC fields.
#
# slot is a 2 digit hexadecimal code; it can be one of:-
#
#												YKCS11 Slot
# * 9a	PIV Authentication						1
# * 9b	Management Key (can not be acessed)
# * 9c	Digital Signature (PIN always checked)	2
# * 9d	Key Management							3
# * 9e	Card Authentication (PIN never checked)	4
# * 82	Retired Key Management					5
# * 83	Retired Key Management					6
# * 84	Retired Key Management					7
# * 85	Retired Key Management					8
# * 86	Retired Key Management					9
# * 87	Retired Key Management					10
# * 88	Retired Key Management					11
# * 89	Retired Key Management					12
# * 8a	Retired Key Management					13
# * 8b	Retired Key Management					14
# * 8c	Retired Key Management					15
# * 8d	Retired Key Management					16
# * 8e	Retired Key Management					17
# * 8f	Retired Key Management					18
# * 90	Retired Key Management					19
# * 91	Retired Key Management					20
# * 92	Retired Key Management					21
# * 93	Retired Key Management					22
# * 94	Retired Key Management					23
# * 95	Retired Key Management					24
# * f9	Attestation								25
#
# algorithm is one of:-
#
# * RSA1024	(Insecure)
# * RSA2048	(Insecure)
# * ECCP256	(Insecure)
# * ECCP384	(Insecure)
#
# hash is one of:-
#
# * SHA1	(Insecure)
# * SHA256	(Not Ideal)
# * SHA384	(Not Ideal)
# * SHA512
_yubikey_piv_tool()
{
	local slot="$1"
	local algorithm="$2"
	local hash="$3"
	shift 3
	
	brew_ensure_binary yubico-piv-tool yubico-piv-tool
		
	yubico-piv-tool --reader='Yubikey' --slot="$slot" --algorithm="$algorithm" --hash="$hash" "$@"
}

_yubikey_ykman()
{
	local device_number="$1"
	
	brew_ensure_binary ykman ykman
	
	ykman --device "$device_number" "$@"
}

_yubikey_reset_config_start()
{
	local device_number="$1"
	local old_config_lock_code="$2"
	if [ -z "$old_config_lock_code" ]; then
		_yubikey_ykman "$device_number" config set-lock-code --clear --force
	else
		_yubikey_ykman "$device_number" config set-lock-code --clear --force --lock-code "$old_config_lock_code"
	fi
	
	_yubikey_ykman "$device_number" config usb --enable-all --force
	
	_yubikey_ykman "$device_number" config nfc --enable-all --force
}

_yubikey_reset_config_end()
{
	local device_number="$1"
	local new_config_lock_code="$2"
	
	_yubikey_ykman "$device_number" config usb --enable 'FIDO2' --force
	_yubikey_ykman "$device_number" config usb --enable 'OATH' --force
	_yubikey_ykman "$device_number" config usb --enable 'OPENPGP' --force
	_yubikey_ykman "$device_number" config usb --disable 'U2F' --force
	_yubikey_ykman "$device_number" config usb --disable 'OTP' --force
	_yubikey_ykman "$device_number" config usb --disable 'HSMAUTH' --force
	_yubikey_ykman "$device_number" config usb --disable 'PIV' --force
	
	_yubikey_ykman "$device_number" config nfc --enable 'FIDO2' --force
	_yubikey_ykman "$device_number" config nfc --enable 'OATH' --force
	_yubikey_ykman "$device_number" config nfc --enable 'OPENPGP' --force
	_yubikey_ykman "$device_number" config nfc --disable 'U2F' --force
	_yubikey_ykman "$device_number" config nfc --disable 'OTP' --force
	_yubikey_ykman "$device_number" config nfc --disable 'HSMAUTH' --force
	_yubikey_ykman "$device_number" config nfc --disable 'PIV' --force
	
	_yubikey_ykman "$device_number" config set-lock-code --new-lock-code "$new_config_lock_code" --force
}

_yubikey_reset_fido2()
{
	local device_number="$1"
	local new_fido2_pin="$2"
	
	# --force must occur within 5 seconds of key insertion (hence we don't specify it)
	_yubikey_ykman "$device_number" fido reset
	
	_yubikey_ykman "$device_number" fido access change-pin --new-pin "$new_fido2_pin"
}

_yubikey_reset_oath()
{
	local device_number="$1"
	local new_oath_password="$2"
	
	# This resets the OATH password as well.
	_yubikey_ykman "$device_number" oath reset --force
	
	_yubikey_ykman "$device_number" oath access change --new-password "$new_oath_password"
}

_yubikey_reset_yubi_otp()
{
	# Resets OTP scanmap to '06050708090a0b0c0d0e0f111517181986858788898a8b8c8d8e8f9195979899271e1f202122232425269e2b28'.
	_yubikey_ykpersonalize -S
	
	_reset_otp_slot()
	{
		local slot="$1"
	
		# Reset OTP settings.
		_yubikey_ykpersonalize -"$slot" -z
		
		# Reprogram:-
		#
		# * the public identifier using a 32 character (16 byte) hex string
		# * A 12 character (6 byte) ?? string
		# * A 12 character (6 byte) hex string
		# * Ticket flags
		# 	* tab-first append-tab1 append-tab2 append-cr protect-cfg2 oath-hotp cha1-resp
		# * Configuration flags
		#	* send-ref pacing-10ms pacing-20ms static-ticket short-ticket strong-pw1 strong-pw2 man-update
		#	* loads more - see man pages
		# * Extended flags
		#
		# 'h:' tells ykpersonalize to not interpret the value as modhex (not supported for uid=).
		#
		# Disable the lock code with '000000000000'.
		# ykpersonalize -y -"$slot" \
		# 	-ofixed=h:0123456789abcdef0123456789abcdef \
		# 	-ouid=000000000000 \
		# 	-oaccess=h:000000000000 \
		# 	-oappend-cr -ostatic-ticket -ostring-pw1 -ostrong-pw2 -oman-update
	}
	_reset_otp_slot 1
	_reset_otp_slot 2
}

# PIV does not support RSA 4096 or greater; PIV does not support Ed25519 or Ed448.
# PIV is tightly controlled by NIST, so is of questionable value.
# Yubico does not support uncompressed certificates greater than 2048 bytes.
# PIV can be used for (https://developers.yubico.com/PIV/Guides/Smart_card-only_authentication_on_macOS.html):-
#
# * Android code signing (via OpenSC)
# * Mac smart card login (Using self-signed certificates and sc_auth)
# * Mac code signing
# * A sub-CA
#
# The yuibco-piv-tool is still needed to set CHUID and CCC fields
depends chmod
_yubikey_reset_piv_generate_key_pair()
{
	local device_number="$1"
	local management_key="$2"
	local pin="$3"
	local piv_exported_public_key_folder_path="$4"
	local slot="$5"
	
	chmod 0700 "$piv_exported_public_key_folder_path"
	
	local public_key_file_path="$piv_exported_public_key_folder_path"/slot."$slot".public-key.pem
	_yubikey_ykman "$device_number" "$device_number" piv keys generate --management-key "$management_key" --pin "$pin" --algorithm RSA2048 --format PEM --pin-policy ONCE --touch-policy CACHED "$slot" "$public_key_file_path"
	chmod 0400 "$public_key_file_path"
	
	# Generates an attestation certificate, signed by the Yubico PIV CA: https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem
	# See also https://developers.yubico.com/yubico-piv-tool/Attestation.html
	local attestation_pem_certificate_file_path="$piv_exported_public_key_folder_path"/slot."$slot".attestation-certificate.pem
	local attestation_der_certificate_file_path="$piv_exported_public_key_folder_path"/slot."$slot".attestation-certificate.der
	_yubikey_ykman "$device_number" "$device_number" piv keys attest --format PEM "$slot" "$attestation_pem_certificate_file_path"
	_yubikey_ykman "$device_number" "$device_number" piv keys attest --format DER "$slot" "$attestation_der_certificate_file_path"
	chmod 0400 "$attestation_pem_certificate_file_path"
	chmod 0400 "$attestation_der_certificate_file_path"
	
	chmod 0500 "$piv_exported_public_key_folder_path"
}

_yubikey_reset_piv_generate_key_pairs()
{
	local device_number="$1"
	local management_key="$2"
	local pin="$3"
	local piv_exported_public_key_folder_path="$4"
	
	
	# * 9a	PIV Authentication
	# * 9c	Digital Signature (PIN always checked)
	# * 9d	Key Management (Encryption)
	# * 9e	Card Authentication (PIN never checked) (Physical Access)
	local slot
	for slot in 9a 9c 9d 9e
	do
		_yubikey_reset_piv_generate_key_pair "$device_number" "$mangement_key" "$pin" "$piv_exported_public_key_folder_path" "$slot"
	done
}

# PINs are 6 to 8 alphanumeric characters.
_yubikey_reset_piv()
{
	local device_number="$1"
	local new_piv_pin="$2"
	local new_piv_pin_unlock_pin="$3"
	local new_piv_retries="$4"
	local new_piv_pin_unlock_retries="$5"
	local new_piv_management_key="$6"
	local piv_exported_public_key_folder_path="$7"
	
	_yubikey_ykman "$device_number" "$device_number" piv reset --force
	
	local default_pin='123456'
	local default_piv_pin_unlock_pin='12345678'
	local default_mangement_key='010203040506070801020304050607080102030405060708'
	
	_yubikey_ykman "$device_number" "$device_number" piv access retries --pin "$default_pin" --management-key "$default_mangement_key" --force "$new_piv_retries" "$new_piv_pin_unlock_retries"
	
	_yubikey_reset_piv_generate_key_pairs "$device_number" "$default_mangement_key" "$default_pin" "$piv_exported_public_key_folder_path"
	
	# Note that the management key itself is stored in slot 9b.
	_yubikey_ykman "$device_number" "$device_number" piv access change-management-key --management-key "$default_mangement_key" --new-management-key "$new_piv_management_key" --algorithm AES256 --touch
	
	_yubikey_ykman "$device_number" "$device_number" piv access change-pin --pin "$default_pin" --new-pin "$new_piv_pin"
	
	_yubikey_ykman "$device_number" "$device_number" piv access change-puk --puk "$default_piv_pin_unlock_pin" --new-puk "$new_piv_pin_unlock_pin"
}

_yubikey_reset_openpgp()
{
	local device_number="$1"
	local new_openpgp_user_pin="$2"
	local new_openpgp_admin_pin="$3"
	local new_openpgp_pin_retries="$4"
	local new_openpgp_reset_code_retries="$5"
	local new_openpgp_admin_pin_retries="$6"
	local openpgp_exported_public_key_folder_path="$7"
	local new_surname="$8"
	local new_given_name="$9"
	shift 9
	local new_sex="$1"
	local new_display_language="$2"
	
	local default_user_pin=123456
	local default_admin_pin=12345678
	
	# This resets the PINs as well to the defaults of 123456 and 12345678.
	_yubikey_ykman "$device_number" "$device_number" openpgp reset --force
		
	_yubikey_ykman "$device_number" "$device_number" openpgp access --admin-pin "$default_openpgp_admin_pin" "$new_openpgp_pin_retries" "$new_openpgp_reset_code_retries" "$new_openpgp_admin_pin_retries"
	
	local sign_slot_number=1
	local encrypt_slot_number=2
	local authenticate_slot_number=3
	
	local iso_date="$(gpg_iso_date_for_now)"
	
	local iso_name="$new_surname"'>>'"$new_given_name"

	gpg_set_attribute_value DISP-NAME "$iso_name" "$default_openpgp_admin_pin"
	gpg_set_attribute_value DISP-LANG "$new_display_language" "$default_openpgp_admin_pin"
	gpg_set_attribute_value DISP-SEX "$new_sex" "$default_openpgp_admin_pin"
	
	_set_key_touch_policy()
	{
		local slot_name="$2"
		
		# We have to reset touch policy AFTER generating keys.
		# Forces touch policy on but caches each touch for 15 seconds.
		# This isn't the most secure setting, but it is useful for doing key manipulation; think sudo.
		_yubikey_ykman "$device_number" openpgp keys set-touch --admin-pin "$default_openpgp_admin_pin" "$slot_name" Cached-Fixed
	}
	
	_attest_key_format()
	{
		local slot_name="$1"
		local format_lower_case="$2"
		local format_upper_case="$3"
		
		local key_attestation_file_path="$openpgp_exported_public_key_folder_path"/slot."$slot_name".attestation-certificate."$format_lower_case"
		_yubikey_ykman "$device_number" openpgp keys attest --format "$format_upper_case" --pin "$default_user_pin" "$slot_name" "$key_attestation_file_path"
		chmod 0400 "$key_attestation_file_path"
	}
	
	_generate_key()
	{
		local slot_number="$1"
		local slot_name="$2"
		local algorithm="$3"
	
		gpg_set_attribute_KEY_ATTR "$slot_number" "$algorithm" "$default_openpgp_admin_pin"
		
		local key_file_path="$openpgp_exported_public_key_folder_path"/slot."$slot_name".ssv
		gpg_generate_key "$slot_number" "$default_openpgp_admin_pin" "$key_file_path" "$iso_date"
		chmod 0400 "$key_file_path"
	
		_attest_key_format "$slot_name" pem PEM
		_attest_key_format "$slot_name" der DER
	
		_set_key_touch_policy "$slot_name"
	}
	
	_export_certificate_format()
	{
		local slot_name="$1"
		local format_lower_case="$2"
		local format_upper_case="$3"
		
		local certificate_file_path="$openpgp_exported_public_key_folder_path"/slot."$slot_name".certificate."$format_lower_case"
		_yubikey_ykman "$device_number" openpgp certificates export --format "$format_upper_case" "$slot_name" "$certificate_file_path"
		chmod 0400 "$certificate_file_path"
	}
	
	_export_certificate()
	{
		local slot_name="$1"
		
		_export_certificate_format "$slot_name" pem PEM
		_export_certificate_format "$slot_name" der DER
	}
	
	chmod 0700 "$openpgp_exported_public_key_folder_path"

		_set_key_touch_policy att
	
		_generate_key "$sign_slot_number" sig ed25519 
		_generate_key "$encrypt_slot_number" enc rsa4096
		_generate_key "$authenticate_slot_number" aut ed25519
		
		_export_certificate att
		
	chmod 0500 "$openpgp_exported_public_key_folder_path"
	
	# kdf-setup (via gpg_enable_kdf()) is too difficult to script.
	gpg_change_pin 'admin' "$default_openpgp_user_pin" "$new_openpgp_user_pin"
	gpg_change_pin 'user' "$default_openpgp_admin_pin" "$new_openpgp_admin_pin"
}

# gpg-card-edit is needed to set language preferences, cardholder name and salutation.
# device_number is a value such as 16133288.
# 	Sometimes it is displayed with spaces, eg 16 133 288; remove these before use.
#
# new_config_lock_code is a 32 character hexadecimal string.
# new_piv_management_key is a 48 character hexadecimal string.
yubikey_reset()
{
	local device_number="$1"
	
	local old_config_lock_code="$2"
	local new_config_lock_code="$3"
	
	local new_fido2_pin="$4"
	
	local new_oath_password="$5"
	
	local new_piv_pin="$6"
	local new_piv_pin_unlock_pin="$7"
	local new_piv_retries="$8"
	local new_piv_pin_unlock_retries="$9"
	shift 9
	local new_piv_management_key="$1"
	local piv_exported_public_key_folder_path="$2"

	local new_openpgp_pin="$3"
	local new_openpgp_admin_pin="$4"
	local new_openpgp_pin_retries="$5"
	local new_openpgp_reset_code_retries="$6"
	local new_openpgp_admin_pin_retries="$7"
	local openpgp_exported_public_key_folder_path="$8"
	local new_openpgp_surname="$9"
	shift 9
	local new_openpgp_given_name="$1"
	local new_openpgp_sex="$2"
	local new_openpgp_display_language="$3"
	
	_yubikey_reset_config_start "$device_number" "$old_config_lock_code"
	_yubikey_reset_fido2 "$device_number" "$new_fido2_pin"
	_yubikey_reset_oath "$device_number" "$new_oath_password"
	_yubikey_reset_yubi_otp
	_yubikey_reset_piv "$device_number" "$new_piv_pin" "$new_piv_pin_unlock_pin" "$new_piv_retries" "$new_piv_pin_unlock_retries" "$new_piv_management_key" "$piv_exported_public_key_folder_path"
	_yubikey_reset_openpgp "$device_number" "$new_openpgp_pin" "$new_openpgp_admin_pin" "$new_openpgp_pin_retries" "$new_openpgp_reset_code_retries" "$new_openpgp_admin_pin_retries" "$openpgp_exported_public_key_folder_path" "$new_openpgp_surname" "$new_openpgp_given_name" "$new_openpgp_sex" "$new_openpgp_display_language"
	_yubikey_reset_config_end "$device_number" "$new_config_lock_code"
}

yubikey_oath_add_uri()
{
	local device_number="$1"
	local uri="$2"

	_yubikey_ykman "$device_number" "$device_number" oath accounts uri "$uri"
}


# No longer in active development
#
# Used to configure the OTP applet which has two slots:-
#
# Slot 1: Short Touch
# Slot 2: Long Touch (by default, used for a static password)
#
# One of 4 non-standard modes of operation is possible:-
#
# * Yubico OTP
# * OATH-HOTP
# * HMAC Challenge-Response
# * Static Password
#	* Scan Code
#	* Advanced
#		* Upto 64 characters (if using the public identity, private identity and AES key)
#		* Public identity is 1 to 16 bytes, but 1 to 5 bytes is considered 'private scope'
#		* Need to generate new private and public identities
#
# There are two slots; each slot can be used by one of the non-standard modes of operation.
# _yubikey_personalize()
# {
# 	brew_ensure_binary ykpers ykpersonalize
# }

# Used to generate HOTP and TOTP challenge-responses in various formats:-
# * Yubico OTP
# * OATH-HOTP
# * HMAC Challenge-Response
#
# Example usage:-
# ykpersonalize -y -2 -ochal-resp -ochal-hmac -ohmac-lt64 -a303132333435363738393a3b3c3d3e3f40414243
# ykchalresp -2 'Sample #2'
#
# See also <https://developers.yubico.com/yubikey-personalization/>
# _yubikey_challenge_response()
# {
# 	brew_ensure_binary ykpers ykchalresp
# }