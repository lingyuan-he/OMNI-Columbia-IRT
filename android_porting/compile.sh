#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - Main Script
# Lingyuan He - 05/2015

# for cross compile
INSTALL_PATH=$(pwd)/install
TOOLCHAIN=$(pwd)/toolchain/bin/arm-linux-androideabi-

echo ""
echo "This script will compile odtone, hipl and middlware into 'install' folder"
echo ""

# make install and work folder
mkdir -p install/hipl
mkdir -p install/sined
mkdir -p toolchain

# NDK config
./ndk.sh

# common dependencies
./common.sh

# odtone
./odtone_porting.sh

# hipl
./hipl_porting.sh

# middleware
./middleware_porting.sh

echo ""
echo "Do not forget to change interface MAC address in 'install/odtone/802_11/link_sap.conf' and 'install/odtone/lte/link_sap.conf'"
echo ""
echo "If you will push the install forlder somewhere else than /data/misc, do not forget to change INSTALL_PATH in install/odtone/mih script"
echo ""
echo "All done, please push 'install' folder up to android device"
echo ""

