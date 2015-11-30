#!/bin/bash

BUILD_NUM=`awk '/FBLIB_BUILD_NUM/ {print $3}' libfb/fblib_ver.h`
let BUILD_1=$BUILD_NUM+1
echo "Incrementing Build number from: "$BUILD_NUM" to "$BUILD_1

sed -i.backup -e 's/'$BUILD_NUM'/'$BUILD_1'/' libfb/fblib_ver.h
