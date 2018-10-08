#!/bin/bash

MODNAME=sqproxy_redirect
FNAME=$MODNAME.ko

make clean
make

if [ ! -e $FNAME ]; then
    echo "Can't found $FNAME after build"
    exit 1
fi


if [ -e /lib/modules/`uname -r`/$FNAME ]; then
    echo "Module already installed. Please remove manually: rm /lib/modules/`uname -r`/$FNAME"
    exit 2
fi

cp sqproxy_redirect.ko /lib/modules/`uname -r`
depmod -a

echo "Module installed. Usage: modrobe sqproxy_redirect"
