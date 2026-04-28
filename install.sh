#!/usr/bin/env bash
# ScaptanaX - Installer
# Usage: bash install.sh
#        bash install.sh --uninstall

set -e

TOOL_NAME="ScaptanaX"
INSTALL_DIR="/usr/local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_FILE="$SCRIPT_DIR/scaptanax.py"
INSTALL_PATH="$INSTALL_DIR/$TOOL_NAME"

CYAN="\033[0;36m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; exit 1; }

print_banner() {
  echo -e "${CYAN}"
  echo "  00 "
  echo "  11 "
  echo " ==== "
  echo "  // "
  echo "  // "
  echo "  // "
  echo "  // "
  echo "  // "
  echo "  // "
  echo "  // "
  echo "  /  "
  echo -e "${RESET}"
  echo "  ScaptanaX — Installer"
  echo "  ─────────────────────────────────────────"
  echo ""
}

uninstall() {
  print_banner
  info "Uninstalling $TOOL_NAME..."

  if [ ! -f "$INSTALL_PATH" ]; then
    warn "$TOOL_NAME is not installed at $INSTALL_PATH"
    exit 0
  fi

  if [ ! -w "$INSTALL_DIR" ]; then
    sudo rm -f "$INSTALL_PATH"
  else
    rm -f "$INSTALL_PATH"
  fi

  success "$TOOL_NAME has been removed from $INSTALL_PATH"
  exit 0
}

check_python() {
  info "Checking Python 3..."
  if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Please install it first: https://www.python.org/downloads/"
  fi

  PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
  PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
  PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

  if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    error "Python 3.8+ required. Found: $PY_VERSION"
  fi

  success "Python $PY_VERSION detected"
}

check_source() {
  info "Looking for scaptanax.py..."
  if [ ! -f "$SOURCE_FILE" ]; then
    error "scaptanax.py not found in the same directory as install.sh ($SCRIPT_DIR)"
  fi
  success "Source file found"
}

install_pip_deps() {
  info "Installing required Python packages..."

  PACKAGES=("colorama" "tqdm" "tabulate")
  OPTIONAL=("jinja2" "scapy")

  for pkg in "${PACKAGES[@]}"; do
    if python3 -c "import $pkg" &>/dev/null; then
      success "  $pkg — already installed"
    else
      info "  Installing $pkg..."
      pip3 install "$pkg" --quiet --break-system-packages 2>/dev/null \
        || pip3 install "$pkg" --quiet 2>/dev/null \
        || warn "  Could not install $pkg — try: pip3 install $pkg"
    fi
  done

  echo ""
  info "Optional packages (recommended):"
  for pkg in "${OPTIONAL[@]}"; do
    if python3 -c "import $pkg" &>/dev/null; then
      success "  $pkg — already installed"
    else
      warn "  $pkg not installed (optional) — pip3 install $pkg"
    fi
  done
}

install_binary() {
  info "Installing $TOOL_NAME to $INSTALL_PATH..."

  if [ ! -w "$INSTALL_DIR" ]; then
    sudo cp "$SOURCE_FILE" "$INSTALL_PATH"
    sudo chmod +x "$INSTALL_PATH"
  else
    cp "$SOURCE_FILE" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
  fi

  success "$TOOL_NAME installed to $INSTALL_PATH"
}

verify_install() {
  info "Verifying installation..."

  if ! command -v "$TOOL_NAME" &>/dev/null; then
    warn "$TOOL_NAME not found in PATH after install."
    warn "Try running: export PATH=\"\$PATH:$INSTALL_DIR\""
    warn "Or add this line to your ~/.bashrc / ~/.zshrc"
    return
  fi

  success "Installation verified — '$TOOL_NAME' is ready"
}

print_usage() {
  echo ""
  echo -e "  ${GREEN}Usage examples:${RESET}"
  echo "    scaptanax -t 192.168.1.1"
  echo "    scaptanax -t 192.168.1.0/24 -p 22,80,443"
  echo "    scaptanax -t example.com -A --cve --headers -o report.html"
  echo "    scaptanax --help"
  echo ""
  echo -e "  ${CYAN}To uninstall:${RESET}"
  echo "    bash install.sh --uninstall"
  echo ""
}

main() {
  if [[ "$1" == "--uninstall" || "$1" == "-u" ]]; then
    uninstall
  fi

  print_banner
  check_python
  check_source
  echo ""
  install_pip_deps
  echo ""
  install_binary
  verify_install
  print_usage

  echo -e "  ${GREEN}Done.${RESET}"
  echo ""
}

main "$@"
