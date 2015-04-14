#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - Compile Odtone
# Lingyuan He / Dhruv Kuchhal - 04/2015

INSTALL_PATH=$(pwd)/install
TOOLCHAIN=arm-linux-gnueabi-
BUILD=x86_64-unknown-linux-gnu
HOST=arm-linux-gnueabi

# software version
BOOST_VER=1.55.0
BOOST_NAME=boost_1_55_0
BOOST_MINOR=55
ODTONE_VER=0.6

# work folder
cd work

# boost
if [ ! -f $BOOST_NAME.tar.gz ]; then
	wget http://sourceforge.net/projects/boost/files/boost/$BOOST_VER/$BOOST_NAME.tar.gz
fi
tar zxvf $BOOST_NAME.tar.gz
cd $BOOST_NAME
./bootstrap.sh --prefix=$INSTALL_PATH
# user config file
cd tools/build/v2
cat >> user-config.jam <<EOF
using gcc : arm : ${TOOLCHAIN}g++ :
<compileflags>-I${INSTALL_PATH}/include
<linkflags>-L${INSTALL_PATH}/lib ;
EOF
cd ../../../
# ODTONE DOES NOT NEED LIBBOOST, JUST B2, SO WE DO NOT NEED TO COMPILE
#./b2 target-os=linux toolset=gcc-arm
cd ../

# odtone
# copy archives
cp ../../protocols/mih/odtone-$ODTONE_VER.tar.gz ./
cp ../../protocols/mih/dist.tar.gz ./
# copy mih_usr source
mv ./odtone-$ODTONE_VER/app/mih_usr/mih_usr.cpp ./odtone-$ODTONE_VER/app/mih_usr/mih_usr_backup.cpp 
cp ../../protocols/mih/mih_usr.cpp ./odtone-$ODTONE_VER/app/mih_usr
# decompress
tar zxvf odtone-$ODTONE_VER.tar.gz
cd odtone-$ODTONE_VER
# settings
sed -i -e 's/boost-minor = 49/boost-minor = ${BOOST_MINOR}/g' Jamroot
echo "boost-build ../${BOOST_NAME}/tools/build/v2 ;" > boost-build.jam
# build
../${BOOST_NAME}/b2 --boost-root=../${BOOST_NAME} linkflags=-lpthread
# link_sap configs
cd ../
tar zxvf dist.tar.gz
cd dist
cp -rf * ../odtone-$ODTONE_VER/dist
cd ../
rm -rf dist
# copy all in dist to install
cd odtone-$ODTONE_VER/dist
cp -rf * ../../../install/odtone
cd ../../../

echo ""
echo "Cross compilation for odtone is done"
echo ""

