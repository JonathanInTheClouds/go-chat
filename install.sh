#!/bin/sh
set -e

REPO="JonathanInTheClouds/go-chat"
BINARY="chat"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    darwin) ;;
    linux)  ;;
    *) echo "Unsupported OS: $OS" && exit 1 ;;
esac

# Detect arch
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)        ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
esac

# Fetch latest version tag
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$VERSION" ]; then
    echo "error: could not determine latest version" && exit 1
fi

# GoReleaser strips the leading 'v' from the archive filename
VER="${VERSION#v}"
URL="https://github.com/$REPO/releases/download/$VERSION/${BINARY}_${VER}_${OS}_${ARCH}.tar.gz"

echo "Installing $BINARY $VERSION ($OS/$ARCH)..."
curl -fsSL "$URL" | tar -xz -C /tmp "$BINARY"

if [ -w "$INSTALL_DIR" ]; then
    mv /tmp/$BINARY "$INSTALL_DIR/$BINARY"
else
    sudo mv /tmp/$BINARY "$INSTALL_DIR/$BINARY"
fi

echo "Installed to $INSTALL_DIR/$BINARY"
echo ""
echo "Enable tab completion:"
echo "  bash:       echo 'eval \"\$(chat completion bash)\"' >> ~/.bashrc"
echo "  zsh:        echo 'eval \"\$(chat completion zsh)\"'  >> ~/.zshrc"
echo "  fish:       echo 'chat completion fish | source'     >> ~/.config/fish/config.fish"
