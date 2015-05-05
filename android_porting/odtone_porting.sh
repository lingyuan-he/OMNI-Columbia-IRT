#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - Compile Odtone
# Lingyuan He / Dhruv Kuchhal - 04/2015

INSTALL_PATH=$(pwd)/install
TOOLCHAIN=arm-linux-gnueabi-
BUILD=x86_64-unknown-linux-gnu
HOST=arm-linux-gnueabi

# software version
ZLIB_VER=1.2.8
BZIP2_VER=1.0.6
BOOST_VER=1.55.0
BOOST_NAME=boost_1_55_0
BOOST_MINOR=55
ODTONE_VER=0.6

# work folder
cd work

# libz2
if [ ! -f bzip2-$BZIP2_VER.tar.gz ]; then
	wget http://www.bzip.org/1.0.6/bzip2-$BZIP2_VER.tar.gz
fi
tar zxvf bzip2-$BZIP2_VER.tar.gz
cd bzip2-$BZIP2_VER
# cross compile setting
sed -i -e "s/CC=gcc/CC=${TOOLCHAIN}gcc/g" Makefile
sed -i -e "s/AR=ar/AR=${TOOLCHAIN}ar/g" Makefile
sed -i -e "s/RANLIB=ranlib/RANLIB=${TOOLCHAIN}ranlib/g" Makefile
sed -i -e "s|PREFIX=/usr/local|PREFIX=${INSTALL_PATH}|g" Makefile
sed -i -e "s|CFLAGS=-Wall -Winline -O2 -g $(BIGFILES)|CFLAGS=-Wall -Winline -O2 -g -static $(BIGFILES)|g" Makefile
make
make install
cd ../

# boost
if [ ! -f $BOOST_NAME.tar.gz ]; then
	wget http://sourceforge.net/projects/boost/files/boost/$BOOST_VER/$BOOST_NAME.tar.gz
fi
rm -f $BOOST_NAME/tools/build/v2/user-config.jam # remove config file to avoid duplicate entry
tar zxvf $BOOST_NAME.tar.gz
cd $BOOST_NAME
./bootstrap.sh --prefix=$INSTALL_PATH
# user config file
cd tools/build/v2
cat >> user-config.jam <<EOF
using gcc : arm : /usr/bin/${TOOLCHAIN}g++ :
<compileflags>"-I${INSTALL_PATH}/include -I/usr/arm-linux-gnueabi/include -fPIC"
<linkflags>"-lpthread -L${INSTALL_PATH}/lib -L/usr/arm-linux-gnueabi/lib" ;
EOF
cd ../../../
# libboost
./b2 target-os=linux toolset=gcc-arm link=static
./b2 install
cd ../
sleep 30

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
#../${BOOST_NAME}/bjam linkflags=-lpthread
../${BOOST_NAME}/b2 --boost-root=../${BOOST_NAME} link=static linkflags="-lpthread -L${INSTALL_PATH}/lib"
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
cp mih ./install/odtone

echo ""
echo "Cross compilation for odtone is done"
echo ""

