INSTALL_PATH=/home/dhruv/OMNI-Columbia-IRT/android_porting
TOOLCHAIN=arm-linux-gnueabi-
BUILD=x86_64-unknown-linux-gnu
HOST=arm-linux-gnueabi

# libxml2

git clone git://git.gnome.org/libxml2
cd libxml2
./autogen.sh --without-python --without-zlib --prefix=${INSTALL_PATH} --host=${HOST} --build=${BUILD} ARCH=arm CROSS_COMPILE=${TOOLCHAIN} CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LIBS="-lz" LDFLAGS="-L${INSTALL_PATH}/lib" CPPFLAGS="-I${INSTALL_PATH}/include"
make
make install
cd ../

#openssl

if [ ! -f openssl-1.0.2.tar.gz ]; then
	wget http://www.openssl.org/source/openssl-1.0.2.tar.gz
fi
tar zxvf openssl-1.0.2.tar.gz
cd openssl-1.0.2
MACHINE=armv7 CROSSCOMPILE=${TOOLCHAIN} CC=${CROSSCOMPILE}gcc AR=${CROSSCOMPILE}ar ARD=${CROSSCOMPILE}ar RANLIB=${CROSSCOMPILE}ranlib ./config --prefix=${INSTALL_PATH}
make
make install
cd ../

# sqlite

if [ ! -f sqlite-autoconf-3080803.tar.gz ]; then
	wget https://sqlite.org/2015/sqlite-autoconf-3080803.tar.gz
fi
tar zxvf sqlite-autoconf-3080803.tar.gz
cd sqlite-autoconf-3080803
./configure --prefix=${INSTALL_PATH} --host=${HOST} --build={BUILD{ CROSS_COMPILE=${TOOLCHAIN} CCC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LDFLAGS="-L${INSTALL_PATH}/lib" CPPFLAGS="-I${INSTALL_PATH}/include"
make
make install
cd ../

