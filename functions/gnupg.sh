# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.


depends date
now_utc_epoch_seconds()
{
	date -j -u '+%s'
}

depends rm
gnupg_destroy_temporary_home()
{
	rm -rf "$GNUPGHOME"
}

depends mkdir
gnupg_create_temporary_home()
{	
	mkdir 0700 "$GNUPGHOME"
	mkdir 0700 "$GNUPGHOME"/openpgp-revocs.d
	
	create_strong_gnupg_configuration
}

depends cat
create_strong_gnupg_configuration()
{
	# Use as gpg --quiet --no-options --homedir XXX --options gpg.conf --batch --no-tty --no  for unattended usage.
	
	# Also
	# --status-fd or --status-file
	# --logger-fd or --logger-file
	# --attribute-fd or --attribute-file
	# --passphrase-fd or --passphrase-file
	# --command-fd or --command-file

	# When creating a message:-
	# --quiet --utf8-strings --batch --no-tty --yes --no-options --options /path/to/gpg.conf
	# --no-default-recipient
	# --output message.asc
	# --armor (if text file)
	# --cipher-algo AES256 --digest-algo SHA512 --compress-algo Uncompressed --cert-digest-algo SHA512 --aead-algo OCB
	# --sig-policy-url URL --cert-policy-url URL --sig-keyserver-url URL
	# --set-filename '' --for-your-eyes-only --escape-from-lines
	
	# ? --personal-aead-preferences ?
	
	# Sources of configuration information:-
	# * https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html
	# * https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html
	cat >"$GNUPGHOME"/gpg.conf <<-EOF
		# Reset compliance and defaults
		gnupg
		
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
		keyserver-options no-include-revoked,no-include-disabled,no-honour-keyserver-url,no-honor-pka-record,include-subkeys
		
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
}

depends env gpg
gnupg_run()
{	
	env -i PATH="$PATH" gpg --quiet --no-options --option "$GNUPGHOME"/gpg.conf --homedir "$GNUPGHOME" --batch --no-tty --yes "$@"
}

gnupg_generate_random_number()
{
	local number_of_bytes="$1"
	local base64_encrypted="$2"
	
	# Levels 0 to 2.
	local quality_level='0'
	
	if $base64_encrypted; then
		set -- --armor
	else
		set --
	fi
	
	gnupg_run --armor --gen-random "$quality_level" "$number_of_bytes"
}

depends cat
gnupg_generate_master_key()
{
	# eg 'Raphael Cohn'
	local name="$1"
	
	# eg 'raphael.cohn@stormmq.com'
	local email="$2"
	
	local creation_seconds_since_unix_epoch="$3"
	
	local utf8_encoded_passphrase="$4"
	
	local write_key_to_file_name="$5"
	
	local comment="$name (Master Key)"
	
	local response_file="$TMPDIR"/response-file
	cat >"$response_file" <<-EOF
		%echo Generating a Master key with a RSA-4096 Encryption Subkey
		
		%pubring ${write_key_to_file_name}
		
		# Must be the first parameter.
		#
		# Possible values:-
		# * ELG: El Gamal
		# * ELG-E: Same as ELG
		# * EdDSA
		# * ECDSA
		# * ECDH
		# * A number
		# * A libgcrypt name (gcry_pk_map_name())
		# 	* ECC: Elliptic Curve (generic)
		#	* RSA: RSA
		#	* DSA: DSA
		Key-Type: EDDSA
		
		# Ignored for EdDSA, ECDSA, ECDH and ECC keys.
		# Must be 1024 for DSA keys.
		#Key-Length: 4096
		
		# Possible values if using ECDH:-
		# * Curve25519 (or cv25519)
		# * X448 (or cv448)
		# Possible values if using EdDSA:-
		# * Ed25519 (or ed25519)
		# * Ed448 (or ed448)
		# Other values:-
		# * NIST P-256
		# * NIST P-384
		# * NIST P-521
		# * brainpoolP256r1
		# * brainpoolP384r1
		# * brainpoolP512r1
		# * secp256k1
		Key-Curve: Ed25519
		
		# SHA1 hash of key material; used to build a file name of a secret key.
		# A hexstring.
		# Alias is Keygrip.
		# Used to find a key.
		# Key-Grip: XXX
		
		# A comma or space separated list of:-
		# * cert (always required)
		# * encrypt (Aliased as 'encr')
		# * sign
		# * auth
		#
		# Restricted by public key algorithm (Key-Type):-
		#
		# * RSA
		# 	* cert, encrypt, sign and auth
		# * ECDH
		# 	* encrypt
		# * ELG (or ELG-E)
		# 	* encrypt
		# * DSA
		# 	* cert, sig and auth
		# * ECDSA
		# 	* cert, sig and auth
		# * EdDSA
		# 	* cert, sig and auth
		Key-Usage: cert
		
		# Only used if compatibility has been set with RFC 4880bis.
		#
		# Valid integer values:-
		#
		# * 2: deprecated
		# * 3: deprecated
		# * 4: valid but dated
		# * 5: current
		Key-Version: 5
		
		# Embed a passphrase rather than use pin-entry
		Passphrase: ${passphrase}
		
		Name-Real: ${name}
		Name-Comment: ${comment}
		Name-Email: ${email}
		
		# Can be specified in three formats:-
		#
		# * 1986-04-26
		# * 20000815T145012
		# * seconds=50 (the number of seconds since the Unix Epoch)
		#
		# Internally, always made into a UTC date.
		Creation-Date: seconds=${creation_seconds_since_unix_epoch}
		
		# Master keys should never expire.
		#
		# Can be specified in many formats:-
		#
		# * never / none / - (never expires)
		# * 1986-04-26
		# * 20000815T145012
		# * 5d or 5D
		# * 2w or 2W
		# * 23m or 23M
		# * 5y or 5Y
		# * 9 (interpreted as days)
		# * seconds=50 (the number of seconds since the Unix Epoch)
		#
		# Internally, always made into a UTC date.
		Expire-Date: never
		
		# Like setpref and --default-personal-preferences
		# Can also use codes like H10 (SHA256), A2 (OCB) and S9 (AES256).
		Preferences: AES256 SHA512 Uncompressed OCB MDC NO-KS-MODIFY
		
		# Specify a revocation key as 'algo:fpr sensitive' where algo is a number and fpr is a key fingerprint.
		#Revoker: X
		
		# A valid keyserver URI, eg one starting hkp:// or hkps://
		#Keyserver: hkps://keyserver.ubuntu.com
		
		# A comment for the batch operation; used if key generation fails
		Handle: Master key for ${name} at ${email}
		
		# See Key-Type above for details.
		#Subkey-Type: RSA
		
		# See Key-Length above for details.
		#Subkey-Length: 4096
		
		# See Key-Curve above for details.
		#Subkey-Curve: N/A
		
		# See Key-Usage above for details.
		#Subkey-Usage: encrypt
		
		# See Key-Grip above for details.
		#Subkey-grip: XXXX
		
		# See Key-Version above for details.
		#Subkey-Version: 5
		
		%commit
		%echo done
	EOF
	
	gnupg_run --generate-key "$response_file"
}

gnupg_master_keys_fingerprints()
{
	local master_key_file="$1"
	
	gnupg_run --keyring "$master_key_file" --primary-keyring "$master_key_file" --list-options show-only-fpr-mbox --list-secret-keys
}

gnupg_first_master_key_fingerprint()
{
	local master_key_file="$1"
	
	gnupg_master_keys_fingerprints "$master_key_file" | awk '{ print $1; exit 0 }'
}

# This is far more painful than it should be: https://serverfault.com/questions/818289/add-second-sub-key-to-unattended-gpg-key
gnupg_add_sub_key()
{
	local master_key_file="$1"
	
	# eg rsa4096
	# eg ed25519
	local algorithm_with_key_length_or_curve="$2"
	
	# sign, auth or encrypt
	local usage="$3"
	
	# eg 1y
	local expiry="$4"
	
	local master_key_fingerprint="$(gnupg_first_master_key_fingerprint "$master_key_file")"
	
	gnupg_run --keyring "$master_key_file" --primary-keyring "$master_key_file" --quick-add-key "$master_key_fingerprint" "$algorithm_with_key_length_or_curve" "$usage" "$expiry"
}

gnupg_add_sub_keys()
{
	local master_key_file="$1"
	
	local expiry='1y'

	gnupg_add_sub_key "$master_key_file" ed25519 sign "$expiry"
	gnupg_add_sub_key "$master_key_file" ed25519 auth "$expiry"
	
	gnupg_add_sub_key "$master_key_file" rsa4096 sign "$expiry"
	gnupg_add_sub_key "$master_key_file" rsa4096 auth "$expiry"
	gnupg_add_sub_key "$master_key_file" rsa4096 encrypt "$expiry"
}
