# source-query-cache-kernel-module


## Description

https://forums.alliedmods.net/showthread.php?t=297237


## Credits

uthash: https://github.com/troydhanson/uthash

## Usage

### Manual install (no auto reinstall on kernel update)

Run `install.sh` and follow instructions on the screen


### DKMS

Awesome answer about it: https://askubuntu.com/questions/408605/what-does-dkms-do-how-do-i-use-it

Offical page with details: https://github.com/dell/dkms

Prerequisites:

    sudo apt install dkms

Installation:

    cp -R ./src /usr/src/sqproxy_redirect-1.0
    sudo dkms add -m sqproxy_redirect -v 1.0
    sudo dkms build -m sqproxy_redirect -v 1.0
    sudo dkms install -m sqproxy_redirect -v 1.0

Now module will be automatically re-builded after each kernel update
