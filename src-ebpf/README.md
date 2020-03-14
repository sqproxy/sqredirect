
## Requirements

* Linux
* Kernel version >= 4.4, check your by command: uname -r
* bcc-tools >= 0.10.0
    - [Install instruction](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
* python2 or python3 depends on bcc-tools installation case
* pyroute2 >= 0.4
    - ``python -m pip install pyroute2``
    - You can check current version via ``python -c 'import pyroute2; print(pyroute2.__version__);'``

## Usage

### Automatically

Only by [Source Query Proxy Application](https://github.com/spumer/source-query-proxy)

