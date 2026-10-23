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

. "$(cd "$(dirname "$0")/../.." && pwd)/requirements.sh"
require ${REQ_TOR_LINUX}

TOR_VERSION="0.4.9.14"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_KEY="${SCRIPT_DIR}/tor-release-key.asc"

ALPINE_DIGEST_AMD64="sha256:3c81aa9a3d770b316568f4499e30461a5cd3fbd7180bd89e28e34894c7845832"
ALPINE_DIGEST_ARM64="sha256:0a7ed0d449b9318548e66674610d757de19b7645759f74b587b610b59d6b43fd"

APK_PKGS="build-base=0.5-r3 openssl-dev=3.3.7-r2 openssl-libs-static=3.3.7-r2 libevent-dev=2.1.13-r0 libevent-static=2.1.13-r0 zlib-dev=1.3.2-r1 zlib-static=1.3.2-r1 xz-dev=5.8.4-r0 xz-static=5.8.4-r0 autoconf=2.72-r0 automake=1.17-r0 libtool=2.4.7-r3 gnupg"

BUILD_DEPS_TAG="build-deps-f165e170c2c5"
BUILD_DEPS_SHA256_AMD64="4811a2d6069b74f3c7f67cf8001ca4e5ff7962b20b3715a8a43fea7fb240faec"
BUILD_DEPS_SHA256_ARM64="7dd4bc4429a2fdf31e056833c6347768169ba3890443822a3bae852903c46b83"
BUILD_DEPS_URL="https://github.com/neutrinobuilder/neutrino/releases/download"

GOARCH="${1:-amd64}"
case "${GOARCH}" in
    amd64) PLATFORM="linux/amd64"; ALPINE_DIGEST="${ALPINE_DIGEST_AMD64}"; BUILD_DEPS_SHA256="${BUILD_DEPS_SHA256_AMD64}" ;;
    arm64) PLATFORM="linux/arm64"; ALPINE_DIGEST="${ALPINE_DIGEST_ARM64}"; BUILD_DEPS_SHA256="${BUILD_DEPS_SHA256_ARM64}" ;;
    *) echo "Unsupported architecture: ${GOARCH} (valid: amd64, arm64)" >&2; exit 1 ;;
esac
DEST="${SCRIPT_DIR}/tor_linux_${GOARCH}"

if [ -z "${BUILD_DEPS_TAG}" ]; then
    echo "Error: build dependencies not pinned (BUILD_DEPS_TAG empty)." >&2
    exit 1
fi
BUILD_DEPS_FILE="$(cd "${SCRIPT_DIR}/../.." && pwd)/build-deps/${BUILD_DEPS_TAG}-${GOARCH}.tar"
if [ ! -f "${BUILD_DEPS_FILE}" ]; then
    echo "==> Downloading build dependencies ${BUILD_DEPS_TAG}-${GOARCH}.tar..."
    mkdir -p "$(dirname "${BUILD_DEPS_FILE}")"
    curl -fL -o "${BUILD_DEPS_FILE}.tmp" "${BUILD_DEPS_URL}/${BUILD_DEPS_TAG}/${BUILD_DEPS_TAG}-${GOARCH}.tar" \
        || { rm -f "${BUILD_DEPS_FILE}.tmp"; echo "Error: could not download ${BUILD_DEPS_TAG}-${GOARCH}.tar" >&2; exit 1; }
    mv "${BUILD_DEPS_FILE}.tmp" "${BUILD_DEPS_FILE}"
fi
if [ "$(sha256sum "${BUILD_DEPS_FILE}" | cut -d' ' -f1)" != "${BUILD_DEPS_SHA256}" ]; then
    echo "Error: ${BUILD_DEPS_FILE} does not match the pinned sha256 (${BUILD_DEPS_SHA256})." >&2
    exit 1
fi

if [ ! -s "${RELEASE_KEY}" ]; then
    echo "Error: ${RELEASE_KEY} missing or empty — cannot verify the Tor release signature." >&2
    exit 1
fi

SOURCE_DATE_EPOCH="1791384451"

echo "==> Building static tor ${TOR_VERSION} (Alpine/musl, ${PLATFORM}, digest-pinned) via Docker..."

docker run --rm \
  --network host \
  --platform "${PLATFORM}" \
  -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
  -v "${SCRIPT_DIR}:/out" \
  -v "${RELEASE_KEY}:/tor-release-key.asc:ro" \
  -v "${BUILD_DEPS_FILE}:/build-deps.tar:ro" \
  "alpine@${ALPINE_DIGEST}" \
  sh -c "
    set -e
    mkdir /deps && tar -xf /build-deps.tar -C /deps
    apk add --no-network --no-cache /deps/*.apk

    export GNUPGHOME=/tmp/gnupg
    mkdir -p \"\${GNUPGHOME}\" && chmod 700 \"\${GNUPGHOME}\"
    gpg --batch --import /tor-release-key.asc

    cd /tmp
    wget -q https://dist.torproject.org/tor-${TOR_VERSION}.tar.gz
    wget -q https://dist.torproject.org/tor-${TOR_VERSION}.tar.gz.sha256sum
    wget -q https://dist.torproject.org/tor-${TOR_VERSION}.tar.gz.sha256sum.asc

    gpg --batch --verify tor-${TOR_VERSION}.tar.gz.sha256sum.asc tor-${TOR_VERSION}.tar.gz.sha256sum
    sha256sum -c tor-${TOR_VERSION}.tar.gz.sha256sum

    tar xzf tor-${TOR_VERSION}.tar.gz
    cd tor-${TOR_VERSION}

    ./configure \
      --enable-static-tor \
      --with-libevent-dir=/usr \
      --with-openssl-dir=/usr \
      --with-zlib-dir=/usr \
      --disable-asciidoc \
      --disable-manpage \
      --disable-html-manual \
      --disable-system-torrc \
      --disable-zstd \
      LDFLAGS='-static' \
      CFLAGS='-Os -fdebug-prefix-map=/tmp=.'

    make -j\$(nproc) src/app/tor

    strip src/app/tor
    cp src/app/tor /out/tor_linux_${GOARCH}
    chown $(id -u):$(id -g) /out/tor_linux_${GOARCH}
    chmod 755 /out/tor_linux_${GOARCH}
  "

echo ""
echo "==> Done! Static binary: ${DEST}"
file "${DEST}"
du -sh "${DEST}"
echo ""
echo "To bundle it into a release build: bash build_neutrino.sh ux (amd64) or ux-arm (arm64)."
