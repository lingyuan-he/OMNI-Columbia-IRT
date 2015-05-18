#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - Compile Odtone
# Lingyuan He - 05/2015

# cross compile variables
INSTALL_PATH=$(pwd)/install
TOOLCHAIN_FOLDER=$(pwd)/toolchain
TOOLCHAIN=$TOOLCHAIN_FOLDER/bin/arm-linux-androideabi-
#TOOLCHAIN=arm-linux-gnueabi-
#HOST=arm-linux-gnueabi

# ndk
NDK_VERSION=r10d
NDK_ROOT=$(pwd)/work/android-ndk-$NDK_VERSION
NDK_GCC=4.9

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

# decompress
if [ ! -f bzip2-$BZIP2_VER.tar.gz ]; then
	wget http://www.bzip.org/1.0.6/bzip2-$BZIP2_VER.tar.gz
fi
tar zxvf bzip2-$BZIP2_VER.tar.gz
cd bzip2-$BZIP2_VER

# cross compile setting
sed -i -e "s|CC=gcc|CC=${TOOLCHAIN}gcc|g" Makefile
sed -i -e "s|AR=ar|AR=${TOOLCHAIN}ar|g" Makefile
sed -i -e "s|RANLIB=ranlib|RANLIB=${TOOLCHAIN}ranlib|g" Makefile
sed -i -e "s|PREFIX=/usr/local|PREFIX=${INSTALL_PATH}|g" Makefile
sed -i -e "s|CFLAGS=-Wall -Winline -O2 -g \$(BIGFILES)|CFLAGS=-Wall -Winline -O2 -g \$(BIGFILES)|g" Makefile
make
make install
cd ../


# boost for android

# decompress
tar zxvf Boost-for-Android-master.tar.gz
cd Boost-for-Android-master

# patch to add r10 32-bit NDK support
patch -p0 < ../../patches/boost-for-android/build-android.sh.patch

# build without python (unnecessary) to avoid 32/64-bit python mix-up
./build-android.sh --boost=$BOOST_VER --prefix=$INSTALL_PATH --toolchain=arm-linux-androideabi-$NDK_GCC $NDK_ROOT --without-libraries=python
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

# boost build settings
sed -i -e 's/boost-minor = 49/boost-minor = ${BOOST_MINOR}/g' Jamroot
echo "boost-build ../Boost-for-Android-master/${BOOST_NAME}/tools/build/v2 ;" > boost-build.jam

# user config file in boost, we still need a custom build configuration
cd ../Boost-for-Android-master/${BOOST_NAME}/tools/build/v2
if grep -q "using gcc : android : " user-config.jam
then
	echo '' >> user-config.jam
else
	echo "using gcc : android : ${TOOLCHAIN}g++ :" >> user-config.jam
	echo "<compileflags>-I${INSTALL_PATH}/include" >> user-config.jam
	echo "<linkflags>-L${INSTALL_PATH}/lib ;" >> user-config.jam
fi
cd ../../../../../odtone-$ODTONE_VER

# patch debug backtrace code
patch -N ./lib/odtone/debug_linux.cpp < ../../patches/odtone/debug_linux.cpp.patch

# patch link_sap
patch -N ./app/link_sap/linux/main.cpp < ../../patches/odtone/main.cpp.patch

# librt (-lrt) is built into libc (-lc) in android, no need to link it explicitly
sed -i -e 's|<toolset>gcc-android:<linkflags>"-lrt"||g' ./app/link_sap/Jamfile
sed -i -e 's|<toolset>gcc:<linkflags>"-lrt"||g' ./app/link_sap/Jamfile

# set PATH for b2 to find toochain directly
PATH=$TOOLCHAIN_FOLDER/bin:$PATH

# compile use toolset rule set by boost for android
../Boost-for-Android-master/${BOOST_NAME}/b2 --boost-root=../Boost-for-Android-master/${BOOST_NAME} toolset=gcc-android

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

# mih_test
cd test
{$TOOLCHAIN}gcc -o mih_test mih_test.c
cp mih_test ../install/odtone

echo ""
echo "Cross compilation for ODTONE is done"
echo ""

