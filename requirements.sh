#!/usr/bin/env bash
# Copyright (C) 2026 Neutrino
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

REQ_GO="go"
REQ_PACK="upx"
REQ_TOR_LINUX="docker curl file sha256sum"
REQ_I2PD_LINUX="docker curl file sha256sum"
REQ_TOR_MAC="curl tar"
REQ_I2PD_MAC="curl tar"
REQ_TOR_ANDROID="curl gpg unzip awk"
REQ_I2PD_ANDROID="curl gpg unzip awk sha512sum"
REQ_FYNECROSS_IMAGE="docker curl go tar unzip awk sha256sum"
REQ_APK="docker go"

req_package() {
    case "$1" in
        go) echo "Go toolchain (https://go.dev/dl/)" ;;
        docker) echo "Docker Engine (https://docs.docker.com/engine/install/)" ;;
        gpg) echo "gnupg" ;;
        awk) echo "gawk" ;;
        sha256sum|sha512sum) echo "coreutils" ;;
        strings) echo "binutils" ;;
        *) echo "$1" ;;
    esac
}

require() {
    local missing=() t
    for t in "$@"; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    [ ${#missing[@]} -eq 0 ] && return 0
    echo "Error: required tools not found: ${missing[*]}" >&2
    for t in "${missing[@]}"; do
        echo "  ${t}: install $(req_package "$t")" >&2
    done
    echo "  (Debian/Ubuntu: apt install <package>)" >&2
    exit 1
}

require_go() {
    local root="$1" want have
    require go
    want="$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' "${root}/go.mod")"
    have="$(cd "${root}" && go env GOVERSION)"
    have="${have#go}"
    if [ "${have}" != "${want}" ]; then
        echo "Error: go.mod requires Go ${want}, found ${have}." >&2
        echo "  A reproducible build needs exactly the same Go toolchain:" >&2
        echo "  install go${want}, or set GOTOOLCHAIN=go${want} (Go downloads it itself)." >&2
        exit 1
    fi
}
