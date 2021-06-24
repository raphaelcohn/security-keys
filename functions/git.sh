# This file is part of os-x-backup. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/os-x-backup/master/COPYRIGHT. No part of os-x-backup, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of os-x-backup. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/os-x-backup/master/COPYRIGHT.


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
	local destination="$1"
	
	# Can also be x509
	local format='openpgp'
	
	# Default is gpgsm
	# GitHub provides smimesign
	local x509program=smimesign
	
	# gpg.x509.program can be mimesign
	
	# https://security.stackexchange.com/questions/129474/how-to-raise-a-key-to-ultimate-trust-on-another-machine explains how to change a GPG key's trust level (as with everything GPG, it's horrible).
	
	# Writes to `~/.config` or `
	env git config --"$destination" \
		commit.gpgsign true \
		gpg.program gpg \
		gpg.format "$format" \
		gpg.openpgp.program gpg \
		gpg.x509.program gpgsm \
		gpg.minTrustLevel marginal
}

# user.signingkey