# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.



depends brew env
command_brew()
{
	env PATH="$PATH" HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew "$@"
}

update_using_brew()
{
	command_brew update --quiet
}

package_is_installed()
{
	local package="$1"
	
	command_brew ls --versions "$package" 1>/dev/null
}

depends cat
install_using_brew()
{
	local package="$1"
	
	if package_is_installed "$package"; then
		return 0
	fi
	
	printf 'Installing package %s using homebrew… ' "$package" 1>&2
	set +e
		command_brew install --quiet --require-sha "$package" 2>"$TMPDIR"/std-err 1>&2
		local exit_code=$?
	set -e
	if [ $exit_code -ne 0 ]; then
		printf 'failed.\n' 1>&2
		exit_error_message "$(< "$TMPDIR"/std-err)"
	else
		printf 'done.\n' 1>&2
	fi
	
	changes_made_using_brew=true
}

uninstall_using_brew()
{
	local package="$1"
	
	if ! package_is_installed "$package"; then
		return 0
	fi
	
	printf 'Uninstalling package %s using homebrew… ' "$package" 1>&2
	set +e
		command_brew uninstall --quiet --force "$package" 2>"$TMPDIR"/std-err 1>&2
		local exit_code=$?
	set -e
	if [ $exit_code -ne 0 ]; then
		printf 'failed.\n' 1>&2
		exit_error_message "$(< "$TMPDIR"/std-err)"
	else
		printf 'done.\n' 1>&2
	fi
	
	changes_made_using_brew=true
}

depends rm
clean_up_brew()
{
	if $changes_made_using_brew; then
		printf 'Cleaning up homebrew… ' 1>&2
		set +e
			command_brew cleanup --quiet --prune=all -s 2>"$TMPDIR"/std-err 1>&2
		local exit_code=$?
		set -e
		if [ $exit_code -ne 0 ]; then
			printf 'failed.\n' 1>&2
			exit_error_message "$(< "$TMPDIR"/std-err)"
		else
			printf 'done.\n' 1>&2
		fi

		printf 'Removing homebrew cache… ' 1>&2
			rm -rf "$(command_brew --cache)"
		printf 'done.\n' 1>&2
	fi
}
