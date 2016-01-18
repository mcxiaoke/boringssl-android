#!/usr/bin/env bash
# @Author: mcxiaoke
# @Date:   2016-01-18 15:40:43
# @Last Modified by:   mcxiaoke
# @Last Modified time: 2016-01-18 16:19:17
cd sample
gradle clean
cd ..
./build-static-libs.sh 
#cp -r include sample/src/main/jni/prebuilt/
cp -r obj/local/ sample/src/main/jni/libs
ndk-build NDK_DEBUG=1 -C sample/src/main
cd sample
gradle clean installDebug
cd ..
