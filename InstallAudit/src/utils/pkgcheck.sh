#!/bin/zsh

# pkgcheck.sh
#
# Original work Copyright 2019 Armin Briegel (https://github.com/scriptingosx/pkgcheck)
# Licensed under the Apache License, Version 2.0
# SPDX-License-Identifier: Apache-2.0
#
# Modified for integration with InstallAudit

# Enhanced with TODO implementations:
# ✅ Show if components are enabled or disabled (PKG_STATUS field)
# ✅ Clean up code to work on flat components inside a distribution pkg (checkDistributionComponent function)
# ✅ Mount dmg files and inspect pkgs inside (enhanced checkDmg function with error handling)

# this script will look into pkg files and warn if any of the installation scripts
# use one of the following shebangs:
#
# /bin/bash
# /usr/bin/python
# /usr/bin/perl
# /usr/bin/ruby
#
# also checks for signatures and notarization and other information

function mkcleandir() { # $1: dirpath
    local dirpath=${1:?"no dir path"}
    if [[ -d $dirpath ]]; then
        if ! rm -rf "${dirpath:?no dir path}"; then
            return 1
        fi
    fi
    if ! mkdir -p "$dirpath"; then
        return 2
    fi
}

function getPkgSignature() { # $1: pkgpath
    local pkgpath=${1:?"no pkg path"}
    signature=$(pkgutil --check-signature "$pkgpath" | fgrep '1. ' | cut -c 8- )
    if [[ -z $signature ]]; then
        signature="None"
    fi
    echo "$signature"
    return
}

function getPkgNotarized() { # $1: pkgpath
    local pkgpath=${1:?"no pkg path"}

    if notary_result=$(spctl --assess -vvv --type install $pkgpath 2>&1); then
        notary_source=$(echo "$notary_result" | awk -F '=' '/source/ { print $2 }')
        echo "Yes, $notary_source"
    else
        echo "No"
    fi
}

function getComponentStatus() { # $1: distributionxml $2: component_id
    local distributionxml=${1:?"no distribution xml"}
    local component_id=${2:?"no component id"}

    # Check if component is enabled by default
    # Look for pkg-ref with id matching component_id and check for choice elements
    local enabled_status=$(xmllint --xpath "string(//choice[@id='$component_id']/@enabled)" "$distributionxml" 2>/dev/null)

    # If no explicit enabled attribute, check for selected attribute
    if [[ -z "$enabled_status" ]]; then
        enabled_status=$(xmllint --xpath "string(//choice[@id='$component_id']/@selected)" "$distributionxml" 2>/dev/null)
    fi

    # If still no status, check start_enabled or start_selected
    if [[ -z "$enabled_status" ]]; then
        enabled_status=$(xmllint --xpath "string(//choice[@id='$component_id']/@start_enabled)" "$distributionxml" 2>/dev/null)
    fi

    if [[ -z "$enabled_status" ]]; then
        enabled_status=$(xmllint --xpath "string(//choice[@id='$component_id']/@start_selected)" "$distributionxml" 2>/dev/null)
    fi

    # Default to enabled if no explicit setting found
    if [[ -z "$enabled_status" || "$enabled_status" == "true" ]]; then
        echo "enabled"
    else
        echo "disabled"
    fi
}

function checkDistributionComponent() { # $1: component_path $2: distributionxml $3: level
    local component_path=${1:?"no component path"}
    local distributionxml=${2:?"no distribution xml"}
    local level=${3:-1}

    local indent=""
    if [[ level -gt 0 ]]; then
        indent="    "
    fi

    local cname=$(basename "$component_path")
    local component_id=""

    echo "${indent}PKG_INFO:$cname"
    echo "${indent}PKG_TYPE:Flat Component PKG"

    # determine identifier and version, if present
    pkginfo="$component_path/PackageInfo"
    if [[ -f "$pkginfo" ]]; then
        # try to extract identifier
        pkgidentifier=$(xmllint --xpath "string(//pkg-info/@identifier)" "${pkginfo}" 2>/dev/null)
        if [[ -n $pkgidentifier ]]; then
            echo "${indent}PKG_IDENTIFIER:$pkgidentifier"
            component_id="$pkgidentifier"
        fi
        pkgversion=$(xmllint --xpath "string(//pkg-info/@version)" "${pkginfo}" 2>/dev/null)
        if [[ -n $pkgversion ]]; then
            echo "${indent}PKG_VERSION:$pkgversion"
        fi
        pkglocation=$(xmllint --xpath "string(//pkg-info/@install-location)" "${pkginfo}" 2>/dev/null)
        if [[ -n $pkglocation ]]; then
            echo "${indent}PKG_LOCATION:$pkglocation"
        fi

        # Check if component is enabled/disabled in distribution
        if [[ -n "$component_id" && -f "$distributionxml" ]]; then
            component_status=$(getComponentStatus "$distributionxml" "$component_id")
            echo "${indent}PKG_STATUS:$component_status"
        fi
    fi

    # does the pkg have a Scripts directory?
    if [[ -d "$component_path/Scripts" ]] ; then
        checkFilesInDir "$component_path/Scripts" "$level"
    fi
}

function checkFilesInDir() { # $1: dirpath $2: level
    local dirpath=${1:?"no directory path"}

    local level=${2:-0}
    if [[ level -gt 0 ]]; then
        indent="    "
    else
        indent=""
    fi

    local foundscripts=$(find "$dirpath" -type f -print0 )
    local scriptfiles=( ${(0)foundscripts} )
    local scripts_count=${#scriptfiles}

    echo "${indent}Contains $scripts_count resource files"

    for f in "${scriptfiles[@]}"; do
        if [[ -e "$f" ]]; then
            relpath="${f#"$dirpath/"}"

            file_description="$(file -b "$f")"
            if [[ "$file_description" == *"script text executable"* ]]; then

                # check for deprecated shebangs
                shebang=$(head -n 1 "$f" | tr -d $'\n')
                lastelement=${shebang##*/}
                if [[ $shebang == "#!/bin/bash" || \
                      $shebang == "#!/usr/bin/env bash" || \
                      $shebang == "#!/usr/bin/ruby" || \
                      $shebang == "#!/usr/bin/env ruby" || \
                      $shebang == "#!/usr/bin/perl" || \
                      $shebang == "#!/usr/bin/env perl" ]]; then
                    echo "${indent}DEPRECATED_SHEBANG:$relpath:$shebang"
                fi

                # python gets extra treatment since it will break in macOS 12.3+
                if [[ $shebang == "#!/usr/bin/python" || \
                      $shebang == "#!/usr/bin/env python" ]]; then
                    echo "${indent}CRITICAL_DEPRECATED_SHEBANG:$relpath:$shebang"
                fi

                # check for uses of 'python' in code
                if grep --invert-match '^#' "$f" | grep --quiet 'python'; then
                    echo "${indent}PYTHON_USAGE:$relpath"
                fi
            fi
        fi
    done
}

function checkBundlePKG() { # $1: pkgpath $2: level
    local pkgpath=${1:?"no pkg path"}
    local pkgfullname=$(basename $pkgpath)
    local pkgname=${pkgfullname%.*} # remove extension

    local level=${2:-0}
    if [[ level -gt 0 ]]; then
        indent="    "
        echo "${indent}PKG_INFO:$pkgname"
    else
        indent=""
    fi

    echo "${indent}PKG_TYPE:PKG Bundle"

    # get version and identifier
    pkgidentifier=$(getInfoPlistValueForKey "$pkgpath" "CFBundleIdentifier")
    if [[ -n $pkgidentifier ]]; then
        echo "${indent}PKG_IDENTIFIER:$pkgidentifier"
    fi

    pkgversion=$(getInfoPlistValueForKey "$pkgpath" "CFBundleShortVersionString")
    if [[ -n $pkgversion ]]; then
        echo "${indent}PKG_VERSION:$pkgversion"
    fi

    pkglocation=$(getInfoPlistValueForKey "$pkgpath" "IFPkgFlagDefaultLocation")
    if [[ -n $pkglocation ]]; then
        echo "${indent}PKG_LOCATION:$pkglocation"
    fi

    # check files resources folder
    resourcesfolder="$pkgpath/Contents/Resources"
    if [[ -d $resourcesfolder ]]; then
        checkFilesInDir "$resourcesfolder" "$level"
    fi
}

function checkBundleMPKG() { # $1: pkgpath
    local pkgpath=${1:?"no pkg path"}
    local pkgfullname=$(basename $pkgpath)
    local pkgname=${pkgfullname%.*} # remove extension

    echo "PKG_TYPE:MPKG Bundle"

    IFS=$'\n'
    components=( $(find "$pkgpath" -iname '*.pkg') )
    components_count=${#components}
    echo "PKG_COMPONENTS:$components_count"

    for component in "${components[@]}"; do
        checkBundlePKG "$component" 1
    done
}

function checkComponentPKG() { # $1: pkgpath $2: level
    local pkgpath=${1:?"no pkg path"}
    local pkgfullname=$(basename $pkgpath)
    local pkgname=${pkgfullname%.*} # remove extension

    local level=${2:-0}
    if [[ level -gt 0 ]]; then
        indent="    "
        echo "${indent}PKG_INFO:$pkgname"
        echo "${indent}PKG_PATH:$pkgpath"
    else
        indent=""
    fi

    echo "${indent}PKG_TYPE:Flat Component PKG"

    # expand the flat pkg
    local pkgdir="$scratchdir/$pkgname"

    if [[ -d "$pkgdir" ]] ; then
        rm -r "$pkgdir" || return 1
    fi
    pkgutil --expand "$pkgpath" "$pkgdir"

    # determine identifier and version, if present
    pkginfo="$pkgdir/PackageInfo"
    if [[ -f "$pkginfo" ]]; then
        # try to extract identifier
        pkgidentifier=$(xmllint --xpath "string(//pkg-info/@identifier)" "${pkginfo}" 2>/dev/null)
        if [[ -n $pkgidentifier ]]; then
            echo "${indent}PKG_IDENTIFIER:$pkgidentifier"
        fi
        pkgversion=$(xmllint --xpath "string(//pkg-info/@version)" "${pkginfo}" 2>/dev/null)
        if [[ -n $pkgversion ]]; then
            echo "${indent}PKG_VERSION:$pkgversion"
        fi
        pkglocation=$(xmllint --xpath "string(//pkg-info/@install-location)" "${pkginfo}" 2>/dev/null)
        if [[ -n $pkglocation ]]; then
            echo "${indent}PKG_LOCATION:$pkglocation"
        fi
    fi

    # does the pkg have a Scripts dir?
    if [[ -d "$pkgdir/Scripts" ]] ; then
        checkFilesInDir "$pkgdir/Scripts" "$level"
    fi

    # clean up
    rm -rf "$pkgdir"
}

function checkDistributionPKG() { # $1: pkgpath
    local pkgpath=${1:?"no pkg path"}
    local pkgfullname=$(basename $pkgpath)
    local pkgname=${pkgfullname%.*} # remove extension

    echo "PKG_TYPE:Flat Distribution PKG"

    # expand the flat pkg
    local pkgdir="$scratchdir/$pkgname"

    if [[ -d "$pkgdir" ]] ; then
        rm -r "$pkgdir" || return 1
    fi
    pkgutil --expand "$pkgpath" "$pkgdir"

    # determine identifier and version, if present
    distributionxml="$pkgdir/Distribution"
    if [[ -f "$distributionxml" ]]; then
        # distribution pkg, try to extract identifier
        pkgidentifier=$(xmllint --xpath "string(//installer-gui-script/product/@id)" "${distributionxml}" 2>/dev/null)
        if [[ -n $pkgidentifier ]]; then
            echo "PKG_IDENTIFIER:$pkgidentifier"
        fi
        pkgversion=$(xmllint --xpath "string(//installer-gui-script/product/@version)" "${distributionxml}" 2>/dev/null)
        if [[ -n $pkgversion ]]; then
            echo "PKG_VERSION:$pkgversion"
        fi
    fi

    # find component pkgs
    IFS=$'\n'
    components=($(ls -d1 "$pkgdir"/*.pkg))
    components_count=${#components}
    echo "PKG_COMPONENTS:${#components}"

    if [[ $components_count -gt 0 ]]; then
        for c in $components ; do
            checkDistributionComponent "$c" "$distributionxml" 1
        done
    fi
    # clean up
    rm -rf "$pkgdir"
}

function checkPkg() { # $1: pkgpath
    local pkgpath=${1:?"no pkg path"}
    local pkgfullname=$(basename $pkgpath)
    local pkgname=${pkgfullname%.*} # remove extension

    type=""

    # if extension is not pkg or mpkg: no pkg installer
    if [[ $pkgpath != *.(pkg|mpkg) ]]; then
        type="no_pkg"
        echo "ERROR:$pkgname has no pkg or mpkg file extension"
        return 1
    fi

    echo "PKG_NAME:$pkgname"
    echo "PKG_PATH:$pkgpath"
    echo "PKG_SIGNATURE:$(getPkgSignature "$pkgpath")"
    if [[ $devtools == "installed" ]]; then
        echo "PKG_NOTARIZED:$(getPkgNotarized "$pkgpath")"
    fi

    # mpkg extension : mpkg bundle type
    if [[ $pkgpath == *.mpkg ]]; then
        checkBundleMPKG "$pkgpath"
        return 0
    elif [[ -d $pkgpath ]]; then
        checkBundlePKG "$pkgpath"
    else
        # flat pkg, look for Distribution
        distribution=$(xar -tf "$pkgpath" | grep Distribution 2>/dev/null )
        if [[ $? == 0 ]]; then
            checkDistributionPKG "$pkgpath"
        else
            # no distribution xml, likely a component pkg
            checkComponentPKG "$pkgpath"
        fi
    fi
}

function checkDmg() { # $1: dmgpath
    local dmgpath=${1:?"no dmg path"}

    if [[ ! -f $dmgpath ]]; then
        echo "ERROR:DMG file not found: $dmgpath"
        return 1
    fi

    echo "DMG_INFO:$(basename "$dmgpath")"
    echo "DMG_PATH:$dmgpath"

    # mount dmg
    # piping in 'Y' on stdin to auto-approve license agreements
    local mount_output
    if mount_output=$(echo 'Y' | hdiutil attach "$dmgpath" -noverify -nobrowse -readonly 2>/dev/null); then
        local dmg_volume_path=$(echo "$mount_output" | tail -n 1 | cut -c 54-)

        echo "DMG_MOUNTED:$dmg_volume_path"

        # check dmg contents
        checkDirectory "$dmg_volume_path"

        # unmount dmg
        if hdiutil detach "$dmg_volume_path" >/dev/null 2>&1; then
            echo "DMG_UNMOUNTED:$dmg_volume_path"
        else
            echo "DMG_UNMOUNT_ERROR:$dmg_volume_path"
        fi
    else
        echo "DMG_MOUNT_ERROR:Failed to mount $dmgpath"
        return 1
    fi
}

function checkDirectory() { # $1: dirpath
    local dirpath=${1:?"no directory path"}

    if [[ ! -d $dirpath ]]; then
        return 1
    fi

    local foundpkgs=$(find "$dirpath" -not \( -ipath '*.mpkg/*' -or -iname '._*' \) -and \( -iname '*.pkg' -or -iname '*.mpkg' \) -print0 )
    local pkglist=( ${(0)foundpkgs} )
    # find all pkg and mpkgs in the directory, excluding component pkgs in mpkgs
    for x in $pkglist ; do
        checkPkg "$x"
    done

    local founddmgs=$(find "$dirpath" -iname '*.dmg' -print0 )
    local dmglist=( ${(0)founddmgs} )
    # find all the dmgs in the directory
    for x in $dmglist; do
        checkDmg "$x"
    done
}

# reset zsh
emulate -LR zsh

# are the dev tools installed (this is required for the stapler tool)
if xcode-select -p >/dev/null; then
    devtools="installed"
else
    devtools="none"
fi

# this script's dir:
scriptdir=$(dirname $0)

# scratch space
scratchdir="$scriptdir/scratch/"
if ! mkcleandir "$scratchdir"; then
    echo "ERROR:couldn't clean $scratchdir"
    exit 1
fi

for arg in "$@"; do
    arg_ext="${arg##*.}"
    if [[ $arg_ext == "pkg" || $arg_ext == "mpkg" ]]; then
        checkPkg "$arg"
    elif [[ $arg_ext == "dmg" ]]; then
        checkDmg "$arg"
    elif [[ -d $arg ]]; then
        checkDirectory "$arg"
    else
        echo "ERROR:cannot process $arg"
    fi
done

exit 0
