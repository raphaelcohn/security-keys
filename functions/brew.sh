# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.


depends brew env
_brew()
{
	env PATH="$PATH" HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew "$@"
}

brew_update()
{
	_brew update --quiet
}

brew_prefix()
{
	local package="$1"
	
	_brew --prefix "$package"
}

brew_is_package_installed()
{
	local package="$1"
	
	_brew list --formula --versions "$package" 1>/dev/null
}

brew_is_cask_installed()
{
	local package="$1"
	
	_brew list --cask --versions "$package" 1>/dev/null
}

_brew_install_package_or_cask_without_check()
{
	local package_or_cask="$1"
	local description="$2"
	local action="$3"
	
	printf 'Installing %s %s using homebrew… ' "$description" "$package_or_cask" 1>&2
	set +e
		_brew install --quiet --require-sha --"$action" "$package_or_cask" 2>"$TMPDIR"/std-err 1>&2
		local exit_code=$?
	set -e
	if [ $exit_code -ne 0 ]; then
		printf 'failed.\n' 1>&2
		exit_error_message "$(< "$TMPDIR"/std-err)"
	else
		printf 'done.\n' 1>&2
	fi
}

_brew_install_package_without_check()
{
	local package="$1"
	
	_brew_install_package_or_cask_without_check "$package" 'package' 'formula'
}

brew_install_package()
{
	local package="$1"
	
	if brew_is_package_installed "$package"; then
		return 0
	fi
	
	_brew_install_package_without_check "$package"
	brew_made_changes=true
}

_brew_install_cask_without_check()
{
	local cask="$1"
	
	_brew_install_package_or_cask_without_check "$package" 'cask' 'cask'
}

brew_install_cask()
{
	local cask="$1"
	
	if brew_is_cask_installed "$cask"; then
		return 0
	fi
	
	_brew_install_cask_without_check "$cask"
	brew_made_changes=true
}

_brew_uninstall_package_or_cask_without_check()
{
	local package_or_cask="$1"
	local description="$2"
	local action="$3"
	
	printf 'Uninstalling %s %s using homebrew… ' "$description" "$package_or_cask" 1>&2
	set +e
		_brew uninstall --quiet --force --"$action" "$package_or_cask" 2>"$TMPDIR"/std-err 1>&2
		local exit_code=$?
	set -e
	if [ $exit_code -ne 0 ]; then
		printf 'failed.\n' 1>&2
		exit_error_message "$(< "$TMPDIR"/std-err)"
	else
		printf 'done.\n' 1>&2
	fi
}

_brew_uninstall_package_without_check()
{
	local package="$1"
	
	_brew_uninstall_package_or_cask_without_check "$package" 'package' 'formula'
}

brew_uninstall_package()
{
	local package="$1"
	
	if ! package_is_installed "$package"; then
		return 0
	fi
	
	_brew_uninstall_package_without_check "$package"
	brew_made_changes=true
}

_brew_uninstall_cask_without_check()
{
	local cask="$1"
	
	_brew_uninstall_package_or_cask_without_check "$package" 'cask' 'cask'
}

brew_uninstall_cask()
{
	local cask="$1"
	
	if ! cask_is_installed "$cask"; then
		return 0
	fi
	
	_brew_uninstall_cask_without_check "$cask"
	brew_made_changes=true
}

depends rm
brew_clean_up()
{
	if $brew_made_changes; then
		printf 'Cleaning up homebrew… ' 1>&2
		set +e
			_brew cleanup --quiet --prune=all -s 2>"$TMPDIR"/std-err 1>&2
		local exit_code=$?
		set -e
		if [ $exit_code -ne 0 ]; then
			printf 'failed.\n' 1>&2
			exit_error_message "$(< "$TMPDIR"/std-err)"
		else
			printf 'done.\n' 1>&2
		fi

		printf 'Removing homebrew cache… ' 1>&2
			rm -rf "$(_brew --cache)"
		printf 'done.\n' 1>&2
	fi
}

brew_ensure_binary()
{
	local package="$1"
	local binary="$2"
	
	if command -v "$binary" 1>/dev/null 2>/dev/null; then
		return 0
	fi
	
	_brew_install_package_without_check "$package"
	brew_clean_up
}

brew_run_binary()
{
	local package="$1"
	local binary="$2"
	shift 2
	
	brew_ensure_binary "$package" "$binary"
	"$binary" "$@"
}

brew_ensure_file()
{
	local package="$1"
	local relative_file_path="$2"
	
	file_path="$(brew_prefix "$package")"/"$relative_file_path"
	local exists
	file_exists "$file_path"
	
	if ! $exists; then
		_brew_install_package_without_check "$package"
		brew_clean_up
	fi
}
