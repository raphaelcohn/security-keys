# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.


ensure_ykman_installed()
{
	ensure_package_installed ykman
}

ensure_ykpers_installed()
{
	ensure_package_installed ykpers
}

# Depends on modhex installed by the brew package libyubikey.
_yubi_modhex()
{
	ensure_ykman_installed
	depends modhex
	
	modhex "$@"
}

# Encodes an ASCII string to a MODHEX string.
yubi_modhex_encode_ascii_to_modhex()
{
	local ascii_string="$1"
	
	_yubi_modhex "$ascii_string"
}

# Decodes a MODHEX string to an ASCII string
yubi_modhex_decode_ascii_to_modhex()
{
	local modhex_string="$1"
	
	_yubi_modhex -d "$modhex_string"
}

# Hexadecimal numbers must have even numbers of digits.
yubi_encode_hexadecimal_number_to_modhex()
{
	local hexadecimal_number="$1"
	
	_yubi_modhex -h "$ascii_string"
}

# Hexadecimal numbers must have even numbers of digits.
yubi_decode_modhex_to_hexadecimal_number()
{
	local hexadecimal_number="$1"
	
	_yubi_modhex -d -h "$ascii_string"
}

# Depends on ykgenerate installed by the brew package libyubikey.
yubi_generate()
{
	ensure_ykman_installed
	depends ykgenerate
	
	local AESKEY_hex_encoded="$1"
	local YK_INTERNALNAME_hex_encoded_48_bits="$2"
	local YK_COUNTER_hex_encoded_16_bits="$3"
	local YK_LOW_hex_encoded_16_bits="$4"
	local YK_HIGH_hex_encoded_8_bits="$5"
	local YK_USE_hex_encoded_8_bits="$6"
	
	ykgenerate "$AESKEY_hex_encoded" "$YK_INTERNALNAME_hex_encoded_48_bits" "$YK_COUNTER_hex_encoded_16_bits" "$YK_LOW_hex_encoded_16_bits" "$YK_HIGH_hex_encoded_8_bits" "$YK_USE_hex_encoded_8_bits"
 }

# Depends on ykparse installed by the brew package libyubikey.
yubi_parse()
{
	ensure_ykman_installed
	depends ykparse
	
	local AESKEY_hex_encoded_32_characters="$1"
	local TOKEN_modhex_encoded="$2"
	
	ykparse "$AESKEY_hex_encoded_32_characters" "$TOKEN_modhex_encoded"
}

# A more script friendly tool for finding yubi key information than ykman.
# 
# Depends on ykinfo installed by the brew package ykpers.
# Recognized flags are:-
# -s	Serial Number
# -m	Serial Number (modhex)
# -H	Serial Number (hex)
# -v	Version
# -t	Touch Level
# -1	Slot 1 status (1 or 0)
# -2	Slot 2 status (1 or 0)
# -p	Programming Sequence
# -i	Vendor Id (USB VID)
# -I	Product Id (USB PID)
# -c	Capabiliyies long hexadecimal string
# One or more flags can be specified.
# Duplicate flags are allowed, but only the first instance is acted on.
# Output is one line per flag, sorted by the order of flags on the command line.
yubi_personalize_info()
{
	ensure_ykpers_installed
	depends ykinfo
	
	ykinfo -q "$@"
}

# Used to configure Yubi OTP (as an alternative to ykman).
#
# One of 4 non-standard modes of operation is possible:-
#
# * Yubico OTP
# * OATH-HOTP
# * Static Password
#	* Scan Code
#	* Advanced
# * HMAC Challenge-Response
#
# There are two slots; each slot can be used by one of the non-standard modes of operation.
#
# Depends on ykpersonalize installed by the brew package ykpers.
yubi_personalize_info()
{
	ensure_ykpers_installed
	depends ykpersonalize 
}

# Depends on ykchalresp installed by the brew package ykpers.
yubi_personalize_info()
{
	ensure_ykpers_installed
	depends ykchalresp 
}
