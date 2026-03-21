#!/bin/bash
# Build a .deb package from the release tarball.
# Usage: ./debian/build-deb.sh [path-to-tarball] [version]
#
# If no tarball is provided, downloads the latest release.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TARBALL="${1:-}"
VERSION="${2:-}"
ARCH="amd64"

# If no tarball, download latest
if [[ -z "$TARBALL" ]]; then
  REPO="mwaddip/otzi"
  echo "Fetching latest release..."
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -oP '"tag_name":\s*"\K[^"]+')
  VERSION="${TAG#v}"
  TARBALL="/tmp/permafrost-${TAG}-linux-${ARCH}.tar.gz"
  curl -fsSL "https://github.com/${REPO}/releases/download/${TAG}/permafrost-${TAG}-linux-${ARCH}.tar.gz" \
    -o "$TARBALL"
  echo "Downloaded ${TARBALL}"
fi

[[ -z "$VERSION" ]] && VERSION="0.0.0"

PKG="permafrost-vault"
STAGING="/tmp/${PKG}_${VERSION}_${ARCH}"
rm -rf "$STAGING"

# ── Directory structure ──
mkdir -p "${STAGING}/DEBIAN"
mkdir -p "${STAGING}/opt/permafrost"
mkdir -p "${STAGING}/var/lib/permafrost"
mkdir -p "${STAGING}/etc/systemd/system"
mkdir -p "${STAGING}/etc/nginx/sites-available"

# ── Extract app files ──
tar xzf "$TARBALL" -C "${STAGING}/opt/permafrost"
chmod +x "${STAGING}/opt/permafrost/relay" 2>/dev/null || true

# ── DEBIAN control files ──
sed "s/^Version:.*/Version: ${VERSION}/" "${PROJECT_DIR}/debian/control" > "${STAGING}/DEBIAN/control"
cp "${PROJECT_DIR}/debian/conffiles" "${STAGING}/DEBIAN/conffiles"
cp "${PROJECT_DIR}/debian/templates" "${STAGING}/DEBIAN/templates"

for f in config postinst prerm postrm; do
  cp "${PROJECT_DIR}/debian/${f}" "${STAGING}/DEBIAN/${f}"
  chmod 755 "${STAGING}/DEBIAN/${f}"
done

# ── Systemd units ──
cp "${PROJECT_DIR}/debian/permafrost.service" "${STAGING}/etc/systemd/system/"
cp "${PROJECT_DIR}/debian/permafrost-relay.service" "${STAGING}/etc/systemd/system/"

# ── Build ──
dpkg-deb --build "$STAGING"
mv "${STAGING}.deb" "${PROJECT_DIR}/${PKG}_${VERSION}_${ARCH}.deb"
rm -rf "$STAGING"

echo ""
echo "Built: ${PROJECT_DIR}/${PKG}_${VERSION}_${ARCH}.deb"
echo "Install: sudo dpkg -i ${PKG}_${VERSION}_${ARCH}.deb"
