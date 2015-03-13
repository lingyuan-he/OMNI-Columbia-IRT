INSTALL_PATH=/home/dhruv/OMNI-Columbia-IRT/android_porting
TOOLCHAIN=arm-linux-gnueabi-
BUILD=x86_64-unknown-linux-gnu
HOST=arm-linux-gnueabi

git clone git://git.gnome.org/libxml2
cd libxml2
./autogen.sh --without-python --without-zlib --prefix=${INSTALL_PATH} --host=${HOST} --build=${BUILD} ARCH=arm CROSS_COMPILE=${TOOLCHAIN} CC=${TOOLCHAIN}gcc AR=${TOOLCHAIN}ar ARD=${TOOLCHAIN}ar RANLIB=${TOOLCHAIN}ranlib LIBS="-lz" LDFLAGS="-L${INSTALL_PATH}/lib" CPPFLAGS="-I${INSTALL_PATH}/include"
make
make install
