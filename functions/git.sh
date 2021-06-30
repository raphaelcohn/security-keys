# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.


# Documentation: https://git-scm.com/docs/git-config


# 'destination' is one of:-
#
# * system, to write to $(prefix)/etc/gitconfig.
# * global, to write to ~/.gifconfig or ~/.config/git/config (if the latter exists).
# * local, to write to the repository's .git/config.
# * worktree, to write to the repositor .git/config.worktree.
#
# Ignore all GIT_ environment variables, of which there are many.
depends env git
_git_config()
{
	env git config --"$destination" "$@"
}

git_user_configuration()
{
	local destination="$1"
	local name="$2"
	local email="$3"
	
	_git_config \
		user.name "$name" user.email "$email" \
		author.name "$name" author.email "$email" \
		committer.name "$name" committer.email "$email" \
		user.useConfigOnly true
}

git_line_endings_configuration()
{
	local destination="$1"
	
	_git_config \
		core.eol lf \
		core.autocrlf false
}

git_os_x_configuration()
{
	local destination="$1"
	
	_git_config \
		core.symlinks true \
		core.ignorecase true \
		core.precomposeunicode true \
		core.protecthfs true 
}

# signing_key is the value passed to gpg --local-user.
git_security_configuration()
{
	local destination="$1"
	local signing_key="$2"
	
	# May be one of:-
	# * openpgp
	# * x509
	local format='openpgp'
	
	# May be one of:-
	# * undefined
	# * never
	# * marginal
	# * fully
	# * ultimate
	local minimum_trust_level='marginal'
	
	local openpgp_program='gpg'
	
	# Default is gpgsm; this needs to be on the PATH (which is problematic)
	local x509_program='smimesign'
	
	local git_219_and_older_program
	case "$format" in
		
		openpgp)
			git_219_and_older_program="$openpgp_program"
		;;
		
		x509)
			git_219_and_older_program="$x509_program"
		;;
		
		*)
			exit_error_message "Unsupported git signing format $format"
		;;
		
	esac
	
	# https://security.stackexchange.com/questions/129474/how-to-raise-a-key-to-ultimate-trust-on-another-machine explains how to change a GPG key's trust level (as with everything GPG, it's horrible).
	
	_git_config "$destination" \
		commit.gpgsign true \
		push.gpgsign true \
		tag.gpgsign true \
		merge.verifysignatures true \
		gpg.program "$git_219_and_older_program" \
		gpg.format "$format" \
		gpg.openpgp.program "$openpgp_program" \
		gpg.x509.program "$x509_program" \
		gpg.minTrustLevel "$minimum_trust_level" \
		user.signingKey "$signing_key"
}
