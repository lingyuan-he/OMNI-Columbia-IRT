INSTALL_PATH=/home/dhruv/OMNI-Columbia-IRT/android_porting
TOOLCHAIN=arm-linux-gnueabi-
BUILD=x86_64-unknown-linux-gnu
HOST=arm-linux-gnueabi

#boost install

if [ ! -f boost_1_55_0.tar.gz ]; then
	wget http://sourceforge.net/projects/boost/files/boost/1.55.0/boost_1_55_0.tar.gz -P ./protocols/mih/
fi
tar -C ./protocols/mih -zxvf ./protocols/mih/boost_1_55_0.tar.gz
cd protocols/mih/boost_1_55_0
./bootstrap.sh
./b2
sudo ./b2 install
sudo cp b2 /usr/local/sbin/b2
sudo cp bjam /usr/local/sbin/bjam

#Compile odtone
cd ../odtone-0.6
sed -i -e 's/49/55/g' Jamroot
#The above command changes the version of boost inside the Jamroot of odtone-0.6
bjam linkflags=-lpthread
echo 'using gcc : android : /usr/bin/arm-linux-gnueabi-g++ : <linkflags>"-Wl,--whole-archive -lpthread -Wl,--no-whole-archive -lc" ;' >> /home/dhruv/OMNI-Columbia-IRT/android_porting/protocols/mih/boost_1_55_0/tools/build/v2/user-config.jam
sudo apt-get install g++-arm-linux-gnueabi
b2 toolset=gcc-android
