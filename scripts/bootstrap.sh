#!/bin/bash
set -e

if command -v apt-get >/dev/null; then
    echo "Ubuntu/Debian detected. Installing dependencies..."
    sudo apt-get update
    sudo apt-get install -y cmake gcc g++ zlib1g-dev liblzma-dev make
elif command -v pacman >/dev/null; then
    echo "Arch Linux detected. Installing dependencies..."
    sudo pacman -Syu --needed cmake gcc zlib xz make
else
    echo "Unsupported OS. Please install cmake, gcc, zlib, and liblzma manually."
    exit 1
fi

echo "Dependencies installed successfully!"
