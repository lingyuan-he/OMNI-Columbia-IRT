#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - Main Script
# Lingyuan He - 05/2015

echo ""
echo "This script will compile odtone, hipl and middlware for Android into 'install' folder"
echo ""

# make install and work folder
mkdir -p install/hipl
mkdir -p install/sine
mkdir -p toolchain

# NDK config
./scripts/ndk_config.sh

# build common dependencies
./scripts/common_build.sh

# build odtone
./scripts/odtone_build.sh

# build hipl
./scripts/hipl_build.sh

# build middleware
./scripts/middleware_build.sh

echo ""
echo "Do not forget to change interface MAC address in 'install/odtone/802_11/link_sap.conf' and 'install/odtone/lte/link_sap.conf'"
echo ""
echo "If you will push the install forlder somewhere else than '/data/misc' on Android, do not forget to change INSTALL_PATH in 'install/odtone/mih' script"
echo ""
echo "All done, please push 'install/odtone', 'install/hipl' and 'install/sine' folder up to android device"
echo ""

