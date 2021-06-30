# This file is part of security-keys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT. No part of security-keys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2021 The developers of security-keys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys/master/COPYRIGHT.


smimesign_set_root_path()
{
	smimesign_root_path="$(pwd)"/library/smimesign
}

depends readlink
smimesign_set_version()
{
	smimesign_current_path="$smimesign_root_path"/current
	exit_if_symlink_missing "$smimesign_current_path"
	
	smimesign_version="$(readlink "$smimesign_current_path")"
}

depends uname
smimesign_set_parent_path()
{
	local uname_operating_system="$(uname -s)"
	local uname_architecture="$(uname -m)"
	
	_put_smimesign_on_path_architecture_error()
	{
		local supported_architectures="$1"
		exit_system_file_message "Only the 64-bit architecture${supported_architectures} are supported for smimesign on uname -s "$uname_operating_system" uname -m $uname_architecture"
	}
	
	local smimesign_operating_system
	case "$uname_operating_system" in
		
		Darwin)
			smimesign_operating_system=osx
			
			case "$uname_architecture" in
				
				x86_64)
					smimesign_architecture=amd64
				;;
				
				*)
					_put_smimesign_on_path_architecture_error 's arm64 and x86_64'
				;;
				
			esac
		;;
		*)
			exit_system_file_message "Only Darwin is known for smimesign at this time, not uname -s $uname_operating_system"
		;;

	esac
	
	smimesign_parent_path="$smimesign_root_path"/current/"$smimesign_operating_system"/"$smimesign_architecture"
}


