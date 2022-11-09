#!/bin/bash

#####################################
## Script for building Tracer Tool ##
#####################################

## Constants declaration
#The current directory full path
declare -r DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
#The location of the file where to write the full rootkit package
declare -r BASEDIR="/home/h3xduck/TFM/src/bin"
#A variable to determine whether to silence output of internal commands
declare firstarg=$1
#Directory where Pin Tracer is stored
declare TRACERDIR="PinTracer"

# Echo with colors
RED='\033[0;31m'
BLU='\033[0;34m'
GRN='\033[0;32m'
NC='\033[0m' # No Color

#A simple function to silence output
quiet(){
    if [ "$firstarg" == "quiet" ]; then
        "$@" > /dev/null
    else
        "$@"
    fi
}

echo -e "${BLU}Building tracer tool${NC}"
cd $DIR/$TRACERDIR
quiet make PIN_ROOT=$DIR/external/pin-3.25-98650-g8f6168173-gcc-linux obj-intel64/PinTracer.so
mv obj-intel64/* $DIR/bin/
rm -R obj-intel64