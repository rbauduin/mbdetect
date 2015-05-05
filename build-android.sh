#!/bin/bash -e
set -x
ANDROID_API=15
TOOLCHAIN=arm-linux-androideabi-4.9

##
## Dep. versions
##

CARES_VER=1.10.0
LIBCONFIG_VER=1.4.9
LIBSODIUM_VER=1.0.2
CURL_VER=7.42.1

##
## This shouldn't need to be changed for a while ...
##


BASE_DIR=$PWD

# Find NDK
if [ -z ${ANDROID_NDK} ]; then
    ANDROID_NDK=~/local/android-ndk-r10d
    echo "Setting ANDROID_NDK to a default value: $ANDROID_NDK"
fi
if [ -d ${ANDROID_NDK} ]; then
    echo "Found Android NDK in $ANDROID_NDK"
else
    echo "$ANDROID_NDK does not appear to contain a NDK installation...Aborting."
    exit 1
fi

# Export toolchain
if [ -d ${TOOLCHAIN} ]; then
    echo "Re-using existing Android NDK toolchain found in '$TOOLCHAIN'"
else
    echo "Creating Android NDK toolchain in '$TOOLCHAIN'"
    mkdir ${TOOLCHAIN}
    sh $ANDROID_NDK/build/tools/make-standalone-toolchain.sh \
        --platform=android-$ANDROID_API \
        --toolchain=${TOOLCHAIN} \
        --install-dir=${TOOLCHAIN}
    if [ $? -ne 0 ]; then
	    echo "Failed to create the Android NDK Toolchain...Aborting."
        rm -rf ${TOOLCHAIN}
		exit 1
    fi
fi

# Update env. var
export CC=arm-linux-androideabi-gcc
export CXX=arm-linux-androideabi-g++
export RANLIB=arm-linux-androideabi-ranlib
export AR=arm-linux-androideabi-ar
export LD=arm-linux-androideabi-ld
export STRIP=arm-linux-androideabi-strip
export PATH=$PWD/$TOOLCHAIN/bin:$PATH

export CFLAGS="-Os -fPIE $CFLAGS"
export CXXFLAGS="-Os -fPIE $CXXFLAGS"
export LDFLAGS="-fPIE -pie $LDFLAGS"
# Build dependencies

build_dep() {
    FILE=$(eval "echo \${F$1}")
    if [ ! -e ${FILE} ]; then
        echo "Downloading $FILE"
        curl -L -o $FILE $(eval "echo \${$1_URL}")
    else
        echo "Skipping download of $FILE"
    fi

    DIR=$(eval "echo \${$1}")-$(eval "echo \${$1_VER}")
    if [ ! -d ${DIR} ]; then
        echo "Expanding to $DIR"
        mkdir ${DIR}
        tar -xf ${FILE} -C ${DIR} --strip-component=1
    else
        echo "$FILE is already uncompressed in $DIR"
    fi

    cd ${DIR}
    BUILD="$1_build"
    eval ${BUILD}
    cd $BASE_DIR
}


CARES="c-ares"
FCARES=$CARES-$CARES_VER.tar.gz
CARES_URL=http://c-ares.haxx.se/download/$FCARES
CARES_build() {
	./configure  --host=arm-linux --disable-shared --prefix=$BASE_DIR
	make -j4
	make install
}

LIBCONFIG="libconfig"
FLIBCONFIG=$LIBCONFIG-$LIBCONFIG_VER.tar.gz
LIBCONFIG_URL=http://www.hyperrealm.com/libconfig/$FLIBCONFIG
LIBCONFIG_build() {
	./configure  --host=arm-linux --disable-shared --prefix=$BASE_DIR
	make -j4
	make install
}

LIBSODIUM="libsodium"
FLIBSODIUM=$LIBSODIUM-$LIBSODIUM_VER.tar.gz
LIBSODIUM_URL=https://download.libsodium.org/libsodium/releases/$FLIBSODIUM
LIBSODIUM_build() {
	./configure  --host=arm-linux --disable-shared --prefix=$BASE_DIR
	make -j4
	make install
}

CURL="curl"
FCURL=$CURL-$CURL_VER.tar.gz
CURL_URL=http://curl.haxx.se/download/$FCURL
CURL_build() {
	./configure  --host=arm-linux --disable-shared --prefix=$BASE_DIR --disable-ntlm-wb --without-zlib
	make -j4
	make install
}

mkdir -p usr/include/sys
echo "#include <sys/types.h>" > usr/include/sys/bitypes.h
#export CFLAGS="$CFLAGS -I$BASE_DIR/usr/include"
export CXXFLAGS="$CXXFLAGS -I$BASE_DIR/usr/include"

for dep in CARES LIBCONFIG LIBSODIUM CURL; do
    build_dep $dep
done

export CC=arm-linux-androideabi-gcc
# -e : environment variables override those defined in Makefile
make -e android
