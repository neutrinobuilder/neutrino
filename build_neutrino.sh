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

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "${ROOT}"
. "${ROOT}/requirements.sh"
DIST="${ROOT}/dist"
TOR_SCRIPT="${ROOT}/internal/tornode/download_build_tor-core.sh"
TOR_BIN="${ROOT}/internal/tornode/tor_linux_amd64"
TOR_BIN_ARM="${ROOT}/internal/tornode/tor_linux_arm64"
I2PD_SCRIPT="${ROOT}/internal/i2pnode/download_build_i2pd.sh"
I2PD_BIN="${ROOT}/internal/i2pnode/i2pd_linux_amd64"
I2PD_BIN_ARM="${ROOT}/internal/i2pnode/i2pd_linux_arm64"

ANDROIDAPP_DIR="${ROOT}/cmd/androidapp"
FYNECROSS_IMAGE_SCRIPT="${ANDROIDAPP_DIR}/build_fynecross_image.sh"
INJECT_JNILIBS_SCRIPT="${ANDROIDAPP_DIR}/inject_jnilibs.sh"
NATIVEPROBE_DIR="${ANDROIDAPP_DIR}/nativeprobe"
NATIVEPROBE_BIN_ARM64="${NATIVEPROBE_DIR}/bin/nativeprobe_linux_arm64"
NATIVEPROBE_BIN_AMD64="${NATIVEPROBE_DIR}/bin/nativeprobe_linux_amd64"
DOWNLOAD_TOR_ANDROID_SCRIPT="${ANDROIDAPP_DIR}/download_tor_android.sh"
TOR_ANDROID_CACHE="${ANDROIDAPP_DIR}/.cache-tor-android"
TOR_ANDROID_ARM64_SO="${TOR_ANDROID_CACHE}/libtor-arm64-v8a.so"
TOR_ANDROID_AMD64_SO="${TOR_ANDROID_CACHE}/libtor-x86_64.so"
DOWNLOAD_I2PD_ANDROID_SCRIPT="${ANDROIDAPP_DIR}/download_i2pd_android.sh"
I2PD_ANDROID_CACHE="${ANDROIDAPP_DIR}/.cache-i2pd-android"
I2PD_ANDROID_ARM64_SO="${I2PD_ANDROID_CACHE}/libi2pd-arm64-v8a.so"
I2PD_ANDROID_AMD64_SO="${I2PD_ANDROID_CACHE}/libi2pd-x86_64.so"

VERSION_GO="${ROOT}/internal/version/version.go"
APP_VERSION="$(sed -n 's/.*AppVersion = "\([^"]*\)".*/\1/p' "${VERSION_GO}")"
APP_BUILD="$(sed -n 's/.*Build = "\([^"]*\)".*/\1/p' "${VERSION_GO}")"
if [ -z "${APP_VERSION}" ] || [ -z "${APP_BUILD}" ]; then
    echo "Error: unable to read AppVersion/Build from ${VERSION_GO}." >&2
    exit 1
fi
VERSION_SUFFIX="-v${APP_VERSION}-b${APP_BUILD}"

APK_ARM64="${DIST}/neutrino-android-arm64${VERSION_SUFFIX}.apk"
APK_AMD64="${DIST}/neutrino-android-amd64${VERSION_SUFFIX}.apk"

LDFLAGS='-s -w'
MAIN="./cmd/"

# -trimpath removes host filesystem paths (GOPATH/module cache) from the
# binary; -buildvcs=false stops Go from embedding VCS metadata (commit hash,
# dirty flag, commit time) that varies with the local checkout state.
GO_BUILD_FLAGS="-trimpath -buildvcs=false"

BIN_UX="${BIN_UX:-${DIST}/neutrino-ux-amd64${VERSION_SUFFIX}}"
BIN_UX_ARM="${BIN_UX_ARM:-${DIST}/neutrino-ux-arm64${VERSION_SUFFIX}}"

TARGET="${1:-help}"
DO_PACK=false
for arg in "${@:2}"; do
    case "${arg}" in
        pack) DO_PACK=true ;;
    esac
done

mkdir -p "${DIST}"

build_ux() {
    echo "==> ux/amd64 (static, Tor embedded, I2P via system i2pd)..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -a ${GO_BUILD_FLAGS} \
        -ldflags="${LDFLAGS} -extldflags \"-static\"" \
        -o "${BIN_UX}" \
        "${MAIN}"

    file "${BIN_UX}"
    du -sh "${BIN_UX}"
}

build_ux_arm() {
    echo "==> ux/arm64 (static, Tor + i2pd embedded, e.g. Termux/Android)..."
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
        go build -a ${GO_BUILD_FLAGS} \
        -ldflags="${LDFLAGS} -extldflags \"-static\"" \
        -o "${BIN_UX_ARM}" \
        "${MAIN}"

    file "${BIN_UX_ARM}"
    du -sh "${BIN_UX_ARM}"
}


BINFMT_IMAGE="tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"

ensure_arm64_emulation() {
    [ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] && return
    echo "==> arm64 emulation (QEMU/binfmt) not registered, registering it..."
    if ! docker run --privileged --rm "${BINFMT_IMAGE}" --install arm64 >/dev/null; then
        echo "Error: QEMU/binfmt arm64 registration failed." >&2
        exit 1
    fi
    if [ ! -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
        echo "Error: arm64 emulation still missing after registration." >&2
        exit 1
    fi
}

build_tor() {
    local arch="${1:-amd64}"
    if ! command -v docker &>/dev/null; then
        echo "Error: Docker not found, required to build static Tor." >&2
        exit 1
    fi
    [ "${arch}" = "arm64" ] && ensure_arm64_emulation
    echo "==> Building static Tor (Alpine/Docker, ${arch})..."
    bash "${TOR_SCRIPT}" "${arch}"
}

build_i2pd() {
    local arch="${1:-amd64}"
    if ! command -v docker &>/dev/null; then
        echo "Error: Docker not found, required to build static i2pd." >&2
        exit 1
    fi
    [ "${arch}" = "arm64" ] && ensure_arm64_emulation
    echo "==> Building static i2pd (Alpine/Docker, ${arch})..."
    bash "${I2PD_SCRIPT}" "${arch}"
}

build_native_probe() {
    echo "==> Building the native probe (GOOS=linux CGO_ENABLED=0, static)..."
    mkdir -p "${NATIVEPROBE_DIR}/bin"
    ( cd "${NATIVEPROBE_DIR}" && \
      CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '-s -w' -o "${NATIVEPROBE_BIN_ARM64}" . && \
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -o "${NATIVEPROBE_BIN_AMD64}" . )
}

build_apk() {
    if ! command -v docker &>/dev/null; then
        echo "Error: Docker not found, required for fyne-cross." >&2
        exit 1
    fi
    local fynecross
    fynecross="$(command -v fyne-cross || true)"
    if [ -z "${fynecross}" ] && [ -x "$(go env GOPATH)/bin/fyne-cross" ]; then
        fynecross="$(go env GOPATH)/bin/fyne-cross"
    fi
    if [ -z "${fynecross}" ]; then
        echo "Error: fyne-cross not found, install it with:" >&2
        echo "  go install github.com/fyne-io/fyne-cross@latest" >&2
        exit 1
    fi

    local go_version image_tag
    go_version="$(grep -E '^go [0-9]+\.[0-9]+' "${ROOT}/go.mod" | awk '{print $2}')"
    image_tag="neutrino-fynecross-android:go${go_version}"
    if ! docker image inspect "${image_tag}" &>/dev/null; then
        echo "==> Image ${image_tag} not found, building it (bash ${FYNECROSS_IMAGE_SCRIPT})..."
        bash "${FYNECROSS_IMAGE_SCRIPT}" "${go_version}"
    else
        local image_size
        image_size="$(docker image inspect "${image_tag}" --format '{{.Size}}' | awk '{printf "%.0fM", $1/1024/1024}')"
        echo "==> Image ${image_tag} already present (${image_size}), skipping build."
        echo "    To rebuild it: bash ${FYNECROSS_IMAGE_SCRIPT}"
    fi

    local arches="${1:-arm64,amd64}"
    echo "==> Android APK (${arches}, skeleton, see cmd/androidapp)..."
    "${fynecross}" android -arch="${arches}" \
        -dir "${ROOT}" \
        -cache "$(go env GOPATH)" \
        -app-id neutrino.androidapp \
        -name Neutrino \
        -icon cmd/androidapp/Icon.png \
        -app-version 0.1.0 -app-build 1 \
        -image "${image_tag}" \
        ./cmd/androidapp

    [ -f "${ROOT}/fyne-cross/dist/android-arm64/Neutrino.apk" ] && cp "${ROOT}/fyne-cross/dist/android-arm64/Neutrino.apk" "${APK_ARM64}"
    [ -f "${ROOT}/fyne-cross/dist/android-amd64/Neutrino.apk" ] && cp "${ROOT}/fyne-cross/dist/android-amd64/Neutrino.apk" "${APK_AMD64}"

    build_native_probe
    bash "${DOWNLOAD_TOR_ANDROID_SCRIPT}"
    bash "${DOWNLOAD_I2PD_ANDROID_SCRIPT}"
    if [ -f "${APK_ARM64}" ]; then
        bash "${INJECT_JNILIBS_SCRIPT}" "${APK_ARM64}" arm64-v8a "${image_tag}" \
            "libneutrinoprobe.so=${NATIVEPROBE_BIN_ARM64}" \
            "libtor.so=${TOR_ANDROID_ARM64_SO}" \
            "libi2pd.so=${I2PD_ANDROID_ARM64_SO}"
    fi
    if [ -f "${APK_AMD64}" ]; then
        bash "${INJECT_JNILIBS_SCRIPT}" "${APK_AMD64}" x86_64 "${image_tag}" \
            "libneutrinoprobe.so=${NATIVEPROBE_BIN_AMD64}" \
            "libtor.so=${TOR_ANDROID_AMD64_SO}" \
            "libi2pd.so=${I2PD_ANDROID_AMD64_SO}"
    fi

    echo "==> APKs ready in ${DIST}/:"
    ls -lh "${APK_ARM64}" "${APK_AMD64}" 2>/dev/null || true
    echo "    Install: adb install -r <path.apk>"
}

clean_dist() {
    echo "==> Cleaning dist/ (removing all old binaries/APKs)..."
    rm -f "${DIST}"/neutrino-*
}

pack_ux() {
    echo "==> upx --best $(basename "${BIN_UX}")..."
    upx --best "${BIN_UX}"
    du -sh "${BIN_UX}"
}

case "${TARGET}" in
    tor)
        build_tor "${2:-amd64}"
        ;;
    i2p)
        build_i2pd "${2:-amd64}"
        ;;
    apk)
        require ${REQ_APK}
        require_go "${ROOT}"
        clean_dist
        build_apk "${2:-arm64,amd64}"
        ;;
    ux)
        if [ ! -s "${TOR_BIN}" ]; then
            echo "WARNING: ${TOR_BIN} missing or empty, run first: bash build_neutrino.sh tor" >&2
            exit 1
        fi
        if [ ! -s "${I2PD_BIN}" ]; then
            echo "WARNING: ${I2PD_BIN} missing or empty, run first: bash build_neutrino.sh i2p" >&2
            exit 1
        fi
        require_go "${ROOT}"
        if ${DO_PACK}; then require ${REQ_PACK}; fi
        clean_dist
        build_ux
        if ${DO_PACK}; then pack_ux; fi
        ;;
    ux-arm)
        if [ ! -s "${TOR_BIN_ARM}" ]; then
            echo "WARNING: ${TOR_BIN_ARM} missing or empty, run first: bash build_neutrino.sh tor arm64" >&2
            exit 1
        fi
        if [ ! -s "${I2PD_BIN_ARM}" ]; then
            echo "WARNING: ${I2PD_BIN_ARM} missing or empty, run first: bash build_neutrino.sh i2p arm64" >&2
            exit 1
        fi
        require_go "${ROOT}"
        clean_dist
        build_ux_arm
        ;;

    all)
        require_go "${ROOT}"
        if ${DO_PACK}; then require ${REQ_PACK}; fi
        if [ ! -s "${TOR_BIN}" ]; then
            build_tor
        else
            echo "==> Tor already present ($(du -sh "${TOR_BIN}" | cut -f1)), skipping build."
            echo "    To rebuild it: bash build_neutrino.sh tor"
        fi
        if [ ! -s "${I2PD_BIN}" ]; then
            build_i2pd
        else
            echo "==> i2pd already present ($(du -sh "${I2PD_BIN}" | cut -f1)), skipping build."
            echo "    To rebuild it: bash build_neutrino.sh i2p"
        fi
        if [ ! -s "${TOR_BIN_ARM}" ]; then
            build_tor arm64
        else
            echo "==> Tor arm64 already present ($(du -sh "${TOR_BIN_ARM}" | cut -f1)), skipping build."
            echo "    To rebuild it: bash build_neutrino.sh tor arm64"
        fi
        if [ ! -s "${I2PD_BIN_ARM}" ]; then
            build_i2pd arm64
        else
            echo "==> i2pd arm64 already present ($(du -sh "${I2PD_BIN_ARM}" | cut -f1)), skipping build."
            echo "    To rebuild it: bash build_neutrino.sh i2p arm64"
        fi
        clean_dist
        build_ux
        if ${DO_PACK}; then pack_ux; fi
        build_ux_arm
        echo ""
        echo "==> Binaries ready in dist/:"
        ls -lh "${DIST}/"
        ;;
    help|*)
        echo "Usage: bash build_neutrino.sh <target> [pack]"
        echo ""
        echo "Targets:"
        echo "  ux       builds linux/amd64 (static, Tor + i2pd embedded)"
        echo "  ux-arm   builds linux/arm64 (static, Tor + i2pd embedded, e.g. Termux/Android)"

        echo "  all      builds linux/amd64 + linux/arm64"
        echo "  tor [arm64]  rebuilds the embedded Tor binary, amd64 by default (requires Docker; arm64 requires QEMU binfmt, see download_build_tor-core.sh)"
        echo "  i2p [arm64]  rebuilds the embedded i2pd binary, amd64 by default (requires Docker; arm64 requires QEMU binfmt)"
        echo "  apk [arch]   Android APK skeleton (Fyne, see cmd/androidapp), arm64+amd64 by default, requires Docker + fyne-cross, no real network connection"
        echo ""
        echo "Options for ux and all:"
        echo "  pack     compresses the linux binary with upx"
        echo ""
        echo "Examples:"
        echo "  bash build_neutrino.sh ux"
        echo "  bash build_neutrino.sh ux pack"
        echo "  bash build_neutrino.sh all pack"
        [ "${TARGET}" = "help" ] && exit 0 || exit 1
        ;;
esac
