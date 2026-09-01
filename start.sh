#!/usr/bin/env bash
# SecureShare Cybersecurity - Single Command Startup Script

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "======================================================="
echo " 🔐 SecureShare Cybersecurity Platform"
echo "======================================================="

# Run unified launcher
node dev.js
