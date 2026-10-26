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
require ${REQ_I2PD_LINUX}

I2PD_VERSION="2.61.0"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_KEY="${SCRIPT_DIR}/i2pd-release-key.asc"

ALPINE_DIGEST_AMD64="sha256:3c81aa9a3d770b316568f4499e30461a5cd3fbd7180bd89e28e34894c7845832"
ALPINE_DIGEST_ARM64="sha256:0a7ed0d449b9318548e66674610d757de19b7645759f74b587b610b59d6b43fd"

APK_PKGS="git=2.47.3-r0 build-base=0.5-r3 cmake=3.31.1-r0 boost-dev=1.84.0-r2 boost1.84-static=1.84.0-r2 openssl-dev=3.3.7-r2 openssl-libs-static=3.3.7-r2 zlib-dev=1.3.2-r1 zlib-static=1.3.2-r1 gnupg"

BUILD_DEPS_TAG="build-deps-f165e170c2c5"
BUILD_DEPS_SHA256_AMD64="4811a2d6069b74f3c7f67cf8001ca4e5ff7962b20b3715a8a43fea7fb240faec"
BUILD_DEPS_SHA256_ARM64="7dd4bc4429a2fdf31e056833c6347768169ba3890443822a3bae852903c46b83"
BUILD_DEPS_URL="https://github.com/neutrinobuilder/neutrino/releases/download"

SOURCE_DATE_EPOCH="1784571922"

GOARCH="${1:-amd64}"
case "${GOARCH}" in
    amd64) PLATFORM="linux/amd64"; ALPINE_DIGEST="${ALPINE_DIGEST_AMD64}"; BUILD_DEPS_SHA256="${BUILD_DEPS_SHA256_AMD64}" ;;
    arm64) PLATFORM="linux/arm64"; ALPINE_DIGEST="${ALPINE_DIGEST_ARM64}"; BUILD_DEPS_SHA256="${BUILD_DEPS_SHA256_ARM64}" ;;
    *) echo "Unsupported architecture: ${GOARCH} (valid: amd64, arm64)" >&2; exit 1 ;;
esac
DEST="${SCRIPT_DIR}/i2pd_linux_${GOARCH}"

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
    echo "Error: ${RELEASE_KEY} missing or empty — cannot verify the i2pd release tag signature." >&2
    exit 1
fi

echo "==> Building static i2pd ${I2PD_VERSION} (Alpine/musl, ${PLATFORM}, digest-pinned) via Docker..."

docker run --rm \
  --network host \
  --platform "${PLATFORM}" \
  -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
  -v "${SCRIPT_DIR}:/out" \
  -v "${RELEASE_KEY}:/i2pd-release-key.asc:ro" \
  -v "${BUILD_DEPS_FILE}:/build-deps.tar:ro" \
  "alpine@${ALPINE_DIGEST}" \
  sh -c "
    set -e
    mkdir /deps && tar -xf /build-deps.tar -C /deps
    apk add --no-network --no-cache /deps/*.apk

    export GNUPGHOME=/tmp/gnupg
    mkdir -p \"\${GNUPGHOME}\" && chmod 700 \"\${GNUPGHOME}\"
    gpg --batch --import /i2pd-release-key.asc

    git clone --quiet --depth 1 --branch ${I2PD_VERSION} https://github.com/PurpleI2P/i2pd.git /tmp/i2pd
    git -C /tmp/i2pd tag -v ${I2PD_VERSION}

    ACCEPT_HDR=/usr/include/boost/asio/detail/impl/socket_ops.ipp
    [ \"\$(grep -cxE '  socket_type result = ::accept\(s,' \"\$ACCEPT_HDR\")\" = 1 ]
    [ \"\$(grep -cxE '      addrlen \? &tmp_addrlen : 0\);' \"\$ACCEPT_HDR\")\" = 1 ]
    sed -i \
      -e '101s/.*/  socket_type result = ::accept4(s,/' \
      -e '103s/.*/      addrlen ? \&tmp_addrlen : 0, SOCK_CLOEXEC);/' \
      \"\$ACCEPT_HDR\"
    grep -n '::accept4(s,' \"\$ACCEPT_HDR\"

    mkdir -p /build && cd /build
    cmake -DWITH_STATIC=ON -DWITH_UPNP=OFF -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_EXE_LINKER_FLAGS='-static' \
      -DCMAKE_C_FLAGS='-fdebug-prefix-map=/tmp=.' \
      -DCMAKE_CXX_FLAGS='-fdebug-prefix-map=/tmp=.' \
      /tmp/i2pd/build

    make -j\$(nproc)

    strip i2pd
    cp i2pd /out/i2pd_linux_${GOARCH}
    chown $(id -u):$(id -g) /out/i2pd_linux_${GOARCH}
    chmod 755 /out/i2pd_linux_${GOARCH}
  "

echo ""
echo "==> Done! Static binary: ${DEST}"
file "${DEST}"
du -sh "${DEST}"
echo ""
echo "To bundle it into a release build: bash build_neutrino.sh ux (amd64) or ux-arm (arm64)."
