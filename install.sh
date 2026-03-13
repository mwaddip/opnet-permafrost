#!/usr/bin/env bash
set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────
REPO="mwaddip/otzi"
INSTALL_DIR="/opt/permafrost"
DATA_DIR="/var/lib/permafrost"
SERVICE_USER="permafrost"
NODE_MIN="20"
GO_MIN="1.23"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${BLUE}::${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}!${NC} $*"; }
err()   { echo -e "${RED}✗${NC} $*" >&2; }
die()   { err "$@"; exit 1; }

# ── Argument parsing ────────────────────────────────────────────────────────
MODE="download"
YES=false

usage() {
  cat <<'EOF'
Usage: install.sh [OPTIONS]

Options:
  --build       Build from source instead of downloading a release
  --deps        Check and install build dependencies (Node 20, Go 1.23)
  --uninstall   Remove PERMAFROST Vault and its services
  --yes, -y     Skip confirmation prompts
  --help, -h    Show this help

Examples:
  curl -sL https://github.com/mwaddip/otzi/releases/latest/download/install.sh | sudo bash
  sudo ./install.sh --deps && sudo ./install.sh --build
  sudo ./install.sh --uninstall
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --build)     MODE=build; shift ;;
    --deps)      MODE=deps; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    --yes|-y)    YES=true; shift ;;
    --help|-h)   usage ;;
    *) die "Unknown option: $1 (use --help for usage)" ;;
  esac
done

# ── Root check ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)"

# ── Distro detection ───────────────────────────────────────────────────────
DISTRO="unknown"
DISTRO_FAMILY="unknown"
PKG=""

detect_distro() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    case "${ID:-}" in
      ubuntu|debian|linuxmint|pop)
        DISTRO="$ID"; DISTRO_FAMILY="debian"; PKG="apt" ;;
      fedora)
        DISTRO="fedora"; DISTRO_FAMILY="rhel"; PKG="dnf" ;;
      centos|rhel|rocky|alma)
        DISTRO="$ID"; DISTRO_FAMILY="rhel"
        command -v dnf &>/dev/null && PKG="dnf" || PKG="yum" ;;
      arch|manjaro|endeavouros)
        DISTRO="$ID"; DISTRO_FAMILY="arch"; PKG="pacman" ;;
      alpine)
        DISTRO="alpine"; DISTRO_FAMILY="alpine"; PKG="apk" ;;
      *)
        DISTRO="${ID:-unknown}"; DISTRO_FAMILY="unknown" ;;
    esac
  fi
}

detect_distro

# ── Confirmation helper ────────────────────────────────────────────────────
confirm() {
  local msg="$1"
  if $YES; then return 0; fi
  echo -en "${YELLOW}?${NC} ${msg} [y/N] "
  read -r answer
  [[ "$answer" =~ ^[Yy]$ ]]
}

# ── Version helpers ─────────────────────────────────────────────────────────
version_ge() {
  # Returns 0 if $1 >= $2 (dotted version comparison)
  printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

check_node() {
  if command -v node &>/dev/null; then
    local ver
    ver=$(node -v | sed 's/^v//')
    local major=${ver%%.*}
    if [[ $major -ge $NODE_MIN ]]; then
      ok "Node.js $ver (>= $NODE_MIN required)"
      return 0
    else
      warn "Node.js $ver found, but >= $NODE_MIN required"
      return 1
    fi
  else
    warn "Node.js not found"
    return 1
  fi
}

check_go() {
  if command -v go &>/dev/null; then
    local ver
    ver=$(go version | grep -oP '\d+\.\d+(\.\d+)?' | head -1)
    if version_ge "$ver" "$GO_MIN"; then
      ok "Go $ver (>= $GO_MIN required)"
      return 0
    else
      warn "Go $ver found, but >= $GO_MIN required"
      return 1
    fi
  else
    warn "Go not found"
    return 1
  fi
}

# ── Dependency installation ─────────────────────────────────────────────────
install_node() {
  info "Installing Node.js ${NODE_MIN}.x..."
  case $DISTRO_FAMILY in
    debian)
      curl -fsSL "https://deb.nodesource.com/setup_${NODE_MIN}.x" | bash -
      apt-get install -y nodejs
      ;;
    rhel)
      curl -fsSL "https://rpm.nodesource.com/setup_${NODE_MIN}.x" | bash -
      $PKG install -y nodejs
      ;;
    arch)
      pacman -Sy --noconfirm nodejs npm
      ;;
    alpine)
      apk add --no-cache nodejs npm
      ;;
    *)
      die "Cannot auto-install Node.js on $DISTRO. Install Node.js $NODE_MIN+ manually."
      ;;
  esac
  ok "Node.js installed: $(node -v)"
}

install_go() {
  info "Installing Go ${GO_MIN}..."
  case $DISTRO_FAMILY in
    debian)
      apt-get update -qq
      apt-get install -y golang-go 2>/dev/null || {
        # If repo version is too old, use the official tarball
        local gotar="go${GO_MIN}.linux-amd64.tar.gz"
        curl -fsSL "https://go.dev/dl/${gotar}" -o "/tmp/${gotar}"
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "/tmp/${gotar}"
        ln -sf /usr/local/go/bin/go /usr/local/bin/go
        rm "/tmp/${gotar}"
      }
      ;;
    rhel)
      $PKG install -y golang
      ;;
    arch)
      pacman -Sy --noconfirm go
      ;;
    alpine)
      apk add --no-cache go
      ;;
    *)
      die "Cannot auto-install Go on $DISTRO. Install Go $GO_MIN+ manually."
      ;;
  esac
  ok "Go installed: $(go version)"
}

do_deps() {
  info "Checking build dependencies..."
  echo ""

  local need_node=false need_go=false
  check_node || need_node=true
  check_go   || need_go=true

  echo ""
  if ! $need_node && ! $need_go; then
    ok "All dependencies satisfied"
    return 0
  fi

  local actions=""
  $need_node && actions="${actions}  - Install Node.js ${NODE_MIN}.x via ${PKG:-system package manager}\n"
  $need_go   && actions="${actions}  - Install Go ${GO_MIN} via ${PKG:-system package manager}\n"

  echo -e "\nThe following will be installed:\n${actions}"
  confirm "Proceed?" || { info "Aborted."; exit 0; }

  $need_node && install_node
  $need_go   && install_go

  echo ""
  ok "Dependencies installed successfully"
}

# ── Architecture detection ──────────────────────────────────────────────────
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
}

# ── Download mode ───────────────────────────────────────────────────────────
do_download() {
  local arch
  arch=$(detect_arch)

  # Check for required tools
  command -v curl &>/dev/null || die "curl is required. Install it first."
  command -v tar  &>/dev/null || die "tar is required. Install it first."
  command -v node &>/dev/null || die "Node.js is required to run the backend. Run: sudo $0 --deps"

  info "Fetching latest release from GitHub..."
  local tag
  tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -oP '"tag_name":\s*"\K[^"]+')
  [[ -n "$tag" ]] || die "Could not determine latest release. Check https://github.com/${REPO}/releases"

  local version="${tag#v}"
  local tarball="permafrost-${tag}-linux-${arch}.tar.gz"
  local url="https://github.com/${REPO}/releases/download/${tag}/${tarball}"

  info "Downloading ${tarball}..."
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" EXIT

  curl -fsSL "$url" -o "${tmpdir}/${tarball}" || die "Download failed. Does the release exist?"
  info "Extracting to ${INSTALL_DIR}..."
  mkdir -p "$INSTALL_DIR"
  tar xzf "${tmpdir}/${tarball}" -C "$INSTALL_DIR"
  echo "$version" > "${INSTALL_DIR}/version.txt"

  ok "PERMAFROST ${version} installed to ${INSTALL_DIR}"
}

# ── Build mode ──────────────────────────────────────────────────────────────
do_build() {
  check_node || die "Node.js ${NODE_MIN}+ required. Run: sudo $0 --deps"
  check_go   || die "Go ${GO_MIN}+ required. Run: sudo $0 --deps"

  # Detect repo root — either CWD or need to clone
  local repo_dir=""
  if [[ -f "package.json" ]] && grep -q '"opnet-permafrost"' package.json 2>/dev/null; then
    repo_dir="$(pwd)"
    info "Building from source in ${repo_dir}..."
  else
    info "Source not found in current directory. Cloning from GitHub..."
    local tmpdir
    tmpdir=$(mktemp -d)
    git clone --depth 1 "https://github.com/${REPO}.git" "${tmpdir}/otzi"
    repo_dir="${tmpdir}/otzi"
    trap "rm -rf '$tmpdir'" EXIT
  fi

  info "Building frontend..."
  (cd "$repo_dir" && npm ci && npm run build)

  info "Building backend..."
  (cd "$repo_dir/backend" && npm ci && npx tsc)

  info "Building relay..."
  (cd "$repo_dir/relay" && CGO_ENABLED=0 go build -ldflags="-s -w" -o relay .)

  info "Installing to ${INSTALL_DIR}..."
  mkdir -p "$INSTALL_DIR"
  cp -r "$repo_dir/dist" "$INSTALL_DIR/dist"
  mkdir -p "$INSTALL_DIR/backend"
  cp -r "$repo_dir/backend/dist/"* "$INSTALL_DIR/backend/"
  cp -r "$repo_dir/backend/node_modules" "$INSTALL_DIR/backend/node_modules"
  cp "$repo_dir/relay/relay" "$INSTALL_DIR/relay"
  chmod +x "$INSTALL_DIR/relay"

  # Write version from git tag or package.json
  local version
  version=$(cd "$repo_dir" && git describe --tags --always 2>/dev/null || echo "source")
  echo "$version" > "${INSTALL_DIR}/version.txt"

  ok "PERMAFROST built and installed to ${INSTALL_DIR}"
}

# ── Service setup ───────────────────────────────────────────────────────────
setup_services() {
  # Create system user
  if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin \
            --create-home "$SERVICE_USER" 2>/dev/null || true
    ok "Created system user: ${SERVICE_USER}"
  else
    ok "System user ${SERVICE_USER} already exists"
  fi

  # Data directory
  mkdir -p "$DATA_DIR"
  chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
  ok "Data directory: ${DATA_DIR}"

  # Find node binary path
  local node_bin
  node_bin=$(command -v node)

  # Relay service
  cat > /etc/systemd/system/permafrost-relay.service <<EOF
[Unit]
Description=PERMAFROST Relay
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/relay -addr :8081
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  # Backend service
  cat > /etc/systemd/system/permafrost.service <<EOF
[Unit]
Description=PERMAFROST Vault Backend
After=network.target permafrost-relay.service
Requires=permafrost-relay.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=NODE_ENV=production
Environment=PORT=8080
Environment=RELAY_PORT=8081
Environment=DATA_DIR=${DATA_DIR}
ExecStart=${node_bin} backend/server.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now permafrost-relay permafrost

  ok "Services started: permafrost-relay, permafrost"
  info "Backend listening on http://localhost:8080"
}

# ── Web server configuration ───────────────────────────────────────────────
configure_webserver() {
  echo ""
  info "Detecting web server..."

  # ── Nginx ──
  if command -v nginx &>/dev/null; then
    ok "Nginx detected"

    local nginx_conf=""
    if [[ -d /etc/nginx/sites-available ]]; then
      nginx_conf="/etc/nginx/sites-available/permafrost"
    elif [[ -d /etc/nginx/conf.d ]]; then
      nginx_conf="/etc/nginx/conf.d/permafrost.conf"
    else
      warn "Nginx config directory not found, skipping"
      return 0
    fi

    cat > "$nginx_conf" <<'NGINX'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
    }
}
NGINX
    ok "Wrote ${nginx_conf}"

    # Symlink if using sites-available/sites-enabled pattern
    if [[ -d /etc/nginx/sites-enabled ]] && [[ "$nginx_conf" == */sites-available/* ]]; then
      ln -sf "$nginx_conf" /etc/nginx/sites-enabled/permafrost

      # Remove default site if it would conflict
      if [[ -L /etc/nginx/sites-enabled/default ]]; then
        rm /etc/nginx/sites-enabled/default
        info "Removed default nginx site (was conflicting on port 80)"
      fi
    fi

    if nginx -t &>/dev/null; then
      systemctl reload nginx
      ok "Nginx reloaded — PERMAFROST available on http://localhost"
    else
      warn "Nginx config test failed. Check: nginx -t"
    fi
    return 0
  fi

  # ── Apache ──
  local apache_cmd=""
  local apache_svc=""
  if command -v apachectl &>/dev/null; then
    apache_cmd="apachectl"
    apache_svc="apache2"
  elif command -v httpd &>/dev/null; then
    apache_cmd="httpd"
    apache_svc="httpd"
  fi

  if [[ -n "$apache_cmd" ]]; then
    ok "Apache detected (${apache_cmd})"

    local apache_conf=""
    if [[ -d /etc/apache2/sites-available ]]; then
      apache_conf="/etc/apache2/sites-available/permafrost.conf"
    elif [[ -d /etc/httpd/conf.d ]]; then
      apache_conf="/etc/httpd/conf.d/permafrost.conf"
    else
      warn "Apache config directory not found, skipping"
      return 0
    fi

    cat > "$apache_conf" <<'APACHE'
<VirtualHost *:80>
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:8080/$1 [P,L]
</VirtualHost>
APACHE
    ok "Wrote ${apache_conf}"

    # Enable required modules (Debian/Ubuntu style)
    if command -v a2enmod &>/dev/null; then
      a2enmod proxy proxy_http proxy_wstunnel rewrite &>/dev/null
      a2ensite permafrost &>/dev/null
      # Disable default site if it conflicts
      a2dissite 000-default &>/dev/null || true
      ok "Enabled Apache modules and site"
    fi

    systemctl reload "$apache_svc" 2>/dev/null || true
    ok "Apache reloaded — PERMAFROST available on http://localhost"
    return 0
  fi

  # ── Neither ──
  echo ""
  warn "No web server detected (nginx or apache)"
  echo ""
  echo "  PERMAFROST is running on http://localhost:8080"
  echo ""
  echo "  To expose on port 80/443, install nginx or apache and re-run this script,"
  echo "  or use the Docker image which includes Caddy:"
  echo ""
  echo "    docker run -d -p 80:80 -v permafrost-data:/data ghcr.io/${REPO}:latest"
  echo ""
  echo "  Manual proxy config: forward to http://127.0.0.1:8080"
  echo "  WebSocket path: /ws (requires upgrade headers)"
  echo ""
}

# ── Uninstall ───────────────────────────────────────────────────────────────
do_uninstall() {
  info "Uninstalling PERMAFROST Vault..."
  echo ""

  confirm "This will stop services and remove ${INSTALL_DIR}. Continue?" || {
    info "Aborted."
    exit 0
  }

  # Stop and disable services
  if systemctl is-active --quiet permafrost 2>/dev/null; then
    systemctl stop permafrost
    ok "Stopped permafrost service"
  fi
  if systemctl is-active --quiet permafrost-relay 2>/dev/null; then
    systemctl stop permafrost-relay
    ok "Stopped permafrost-relay service"
  fi

  systemctl disable permafrost permafrost-relay 2>/dev/null || true
  rm -f /etc/systemd/system/permafrost.service
  rm -f /etc/systemd/system/permafrost-relay.service
  systemctl daemon-reload
  ok "Removed systemd services"

  # Remove install directory
  if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    ok "Removed ${INSTALL_DIR}"
  fi

  # Remove web server configs
  if [[ -f /etc/nginx/sites-available/permafrost ]]; then
    rm -f /etc/nginx/sites-enabled/permafrost
    rm -f /etc/nginx/sites-available/permafrost
    systemctl reload nginx 2>/dev/null || true
    ok "Removed nginx config"
  fi
  if [[ -f /etc/nginx/conf.d/permafrost.conf ]]; then
    rm -f /etc/nginx/conf.d/permafrost.conf
    systemctl reload nginx 2>/dev/null || true
    ok "Removed nginx config"
  fi
  if [[ -f /etc/apache2/sites-available/permafrost.conf ]]; then
    a2dissite permafrost 2>/dev/null || true
    rm -f /etc/apache2/sites-available/permafrost.conf
    systemctl reload apache2 2>/dev/null || true
    ok "Removed apache config"
  fi
  if [[ -f /etc/httpd/conf.d/permafrost.conf ]]; then
    rm -f /etc/httpd/conf.d/permafrost.conf
    systemctl reload httpd 2>/dev/null || true
    ok "Removed apache config"
  fi

  # Remove system user
  if id "$SERVICE_USER" &>/dev/null; then
    userdel "$SERVICE_USER" 2>/dev/null || true
    ok "Removed system user: ${SERVICE_USER}"
  fi

  echo ""
  ok "PERMAFROST uninstalled"
  echo ""
  warn "Data directory preserved: ${DATA_DIR}"
  echo "  To remove all data: sudo rm -rf ${DATA_DIR}"
  echo ""
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "${BOLD}PERMAFROST Vault Installer${NC}"
  echo ""

  case $MODE in
    deps)
      do_deps
      ;;
    download)
      do_download
      setup_services
      configure_webserver
      echo ""
      ok "Installation complete!"
      ;;
    build)
      do_build
      setup_services
      configure_webserver
      echo ""
      ok "Installation complete!"
      ;;
    uninstall)
      do_uninstall
      ;;
  esac
}

main
