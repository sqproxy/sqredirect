# sqredirect

Redirection and filtering Source Engine game traffic in a bundle with [sqproxy](https://github.com/sqproxy/sqproxy)


## How it Works?

**sqredirect** attach eBPF filter(s) to network interface and manipulate with traffic targeting to game ports

eBPF is more efficient way to check/accept/drop packets in Linux

[More in Wikipedia](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)


## Requirements

* Linux
* Kernel version >= 4.4, check your by command: uname -r
* python2 or python3


## Installation

TODO: Split into Ubuntu/Debian/Others like in bcc-tools README

### Step 1: Install bcc-tools

* bcc-tools >= 0.10.0 (depends on Kernel version, see https://github.com/iovisor/bcc/releases)
    - [Install instruction (non-Debian 10)](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
    - [Install instruction (Debian 10)](https://github.com/iovisor/bcc/issues/3081#issuecomment-766422307)
    - You can check the current version via ``python -c 'import bcc; print(bcc.__version__);'``

### Step 2: Install sqredirect

    python -m pip install sqredirect

https://pypi.org/project/sqredirect/

## Usage

### Automatically

Only by [SQProxy](https://github.com/sqproxy/sqproxy)

### Non-root running

bcc-tools can't be used w/o root, see https://github.com/iovisor/bcc/issues/1166

But you can use this snippet to restrict usage only to specified user/group:

**TL;DR:** move `python redirect.py $@` to command and add permissions in `/etc/sudoers`

---

1. Copy content of this folder to `/usr/src/sqredirect`

1. Create file in `/usr/local/bin/sqredirect` with content: 

    ```bash
    #!/bin/bash
    
    cd /usr/src/sqredirect
    exec python2 /usr/src/sqredirect/redirect.py $@
    ```

1. `chmod +x /usr/local/bin/sqredirect`

1. Create group network and add user to group

    ```bash
    addgroup network
    usermod -aG network <user-which-should-it-run>
    ```

1. Allow run `sqredirect` command w/o root privileges

    ```bash
    echo "%network ALL=(root) NOPASSWD: /usr/local/bin/sqredirect" > /etc/sudoers.d/network
    ```

More about sudoers: https://www.digitalocean.com/community/tutorials/how-to-edit-the-sudoers-file


## Troubleshooting

**Problem:** I can't reach my server through network

**Solution:** Rollback any changes at network level, run in console (if you have access): 

    tc qdisc del dev eth0 root

replace `eth0` with your interface name
