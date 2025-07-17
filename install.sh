#!/bin/bash
set -e

# Create package directory
mkdir -p 0delay-cli-1.0.0/usr/share/0delay-cli

# Copy CLI script from src directory
cp 0delay-cli/src/0delay.py 0delay-cli-1.0.0/usr/share/0delay-cli/0delay.py

# Copy debian directory
cp -r 0delay-cli/debian 0delay-cli-1.0.0/

# Build deb package
dpkg-deb --build 0delay-cli-1.0.0

echo "Package built: 0delay-cli-1.0.0.deb"
