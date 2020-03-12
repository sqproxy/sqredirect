## Credits

uthash: https://github.com/troydhanson/uthash

## Requirements

* Linux, or KVM virtualization (OVZ not allowed custom modules)
* Kernel version >= 3.3 or 4.x (tested up to 4.18), check your by command: uname -r
* linux headers: sudo apt-get install linux-headers-$(uname -r); or google "install linux headers" for your system
* gcc and make

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
