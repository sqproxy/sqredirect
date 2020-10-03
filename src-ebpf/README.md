
## Requirements

* Linux
* Kernel version >= 4.4, check your by command: uname -r
* bcc-tools >= 0.10.0 (depends on Kernel version, see https://github.com/iovisor/bcc/releases)
    - [Install instruction](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
* python2 or python3 depends on bcc-tools installation case
* pyroute2 >= 0.4
    - ``python -m pip install pyroute2``
    - You can check current version via ``python -c 'import pyroute2; print(pyroute2.__version__);'``

## Usage

### Automatically

Only by [Source Query Proxy Application](https://github.com/spumer/source-query-proxy)

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


