#!/usr/bin/python2

from __future__ import print_function

import argparse
import atexit
import contextlib
import logging.config
import os
import re
import sys
import time
import signal
from bcc import BPF
from ctypes import c_uint16
from ctypes import c_uint32
from ctypes import Structure
from pyroute2 import IPRoute, protocols, IPDB
from pyroute2.netlink.exceptions import NetlinkError

PY2 = sys.version_info.major == 2

try:
    import ipaddress
except ImportError:
    assert PY2
    print(
        'ipaddress module not found. Please install it: %s -m pip install py2-ipaddress' % (sys.executable,),
        file=sys.stderr,
    )
    exit(1)


def _is_ipaddress_module_compatible():
    """ipaddress module can be installed in system and have incompatible API

    The common problem is can work only with `unicode` objects
    """
    try:
        ipaddress.ip_address(str('0.0.0.0'))
    except ipaddress.AddressValueError:
        return False
    return True


if PY2 and not _is_ipaddress_module_compatible():
    print(
        'ipaddress module too old. Please update it: %s -m pip install -U py2-ipaddress' % (
            sys.executable
        ),
        file=sys.stderr,
    )
    exit(1)

ANY_IP = ipaddress.IPv4Address('0.0.0.0')


logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
        },
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'DEBUG',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
})


if sys.platform == 'darwin':
    # FIXME: skip IPRoute initialization on macOS
    ipr = object()
else:
    ipr = IPRoute()


log = logging.getLogger('main')


class AddrKey(Structure):
    _fields_ = [
        ('ip', c_uint32),
        ('port', c_uint16),
    ]


@contextlib.contextmanager
def chdir(dirname=None):
    curdir = os.getcwd()
    try:
        if dirname is not None:
            os.chdir(dirname)
        yield
    finally:
        os.chdir(curdir)


def main(all_ports, interface=None):
    if interface is None:
        log.info('Interface not provided')
        interface = get_default_interface()
        log.info('Use interface for default route: %s', interface)

    ip_addrs = list(all_ports.keys())

    ipdb = IPDB()
    ifindex = ipr.link_lookup(ifname=interface)[0]
    ifaddrs = [ipaddress.ip_address(addr) for addr, mask in ipdb.ipaddr[ifindex]]

    if ip_addrs is not None:
        unknown_ip_addresses = set(ip_addrs).difference(ifaddrs + [ANY_IP])
        if unknown_ip_addresses:
            raise RuntimeError(
                "Can not setup filtering. Given IPs not assigned to given interface: "
                "IPs={unknown_ip_addresses}, interface={interface}.\n"
                "Note: available addresses is {ifaddrs}".format(
                    unknown_ip_addresses=[str(x) for x in unknown_ip_addresses],
                    interface=interface,
                    ifaddrs=[str(x) for x in ifaddrs],
                ),
            )

    use_ipport_key = True
    if len(ip_addrs) == 1 and ip_addrs[0] == ANY_IP:
        # user not specified IP, ignore it at filtering too
        use_ipport_key = False

    cflags = ["-include", "utils.h"]

    if use_ipport_key:
        cflags.append('-DUSE_IPPORT_KEY')

    log.info('Building eBPF program ..., cflags=%s', cflags)
    with chdir(os.path.dirname(__file__)):
        bpf = BPF(src_file="redirect.c", cflags=cflags, debug=0)

    fn_incoming = bpf.load_func("incoming", BPF.SCHED_ACT)
    fn_outgoing = bpf.load_func("outgoing", BPF.SCHED_ACT)

    if use_ipport_key:
        addr_gameserver2proxy_port = bpf.get_table('addr_gameserver2proxy_port')
        addr_proxy2gameserver_port = bpf.get_table('addr_proxy2gameserver_port')

        for ip, ports in all_ports.items():
            for game_port, proxy_port in ports.items():
                addr_gameserver2proxy_port[AddrKey(ip, game_port)] = c_uint16(proxy_port)
                addr_proxy2gameserver_port[AddrKey(ip, proxy_port)] = c_uint16(game_port)

    else:
        assert len(ip_addrs) == 1
        ports = all_ports[ip_addrs[0]]

        gameserver2proxy_port = bpf.get_table('gameserver2proxy_port')
        proxy2gameserver_port = bpf.get_table('proxy2gameserver_port')

        for game_port, proxy_port in ports.items():
            gameserver2proxy_port[c_uint16(game_port)] = c_uint16(proxy_port)
            proxy2gameserver_port[c_uint16(proxy_port)] = c_uint16(game_port)

    log.info('Attach eBPF program to interface ...')
    reg_cleanup(ifindex)
    setup_incoming(fn_incoming, ifindex)
    setup_outgoing(fn_outgoing, ifindex)

    log.info('Running ...')
    while True:
        time.sleep(1)


def get_default_interface():
    ipdb = IPDB()

    try:
        interface = ipdb.interfaces[ipdb.routes['default']['oif']]
        return interface['ifname']
    finally:
        ipdb.release()


def cleanup(ifindex, safe=False):
    log.debug('Cleanup (%s)', ifindex)
    try:
        ipr.tc("del", "ingress", ifindex, "ffff:")
    except NetlinkError as exc:
        if not safe or exc.args[1] != 'Invalid argument':
            raise

    try:
        ipr.tc("del", "sfq", ifindex, "1:")
    except NetlinkError as exc:
        if not safe or exc.args[1] != 'Invalid argument':
            raise

    log.debug('Cleanup (%s) done', ifindex)


def reg_cleanup(ifindex):
    def _inner(_, __):
        cleanup(ifindex, safe=True)
        signal.default_int_handler(_, __)

    signal.signal(signal.SIGTERM, _inner)
    signal.signal(signal.SIGINT, _inner)

    atexit.register(lambda: cleanup(ifindex, safe=True))


def setup_incoming(fn, ifindex):
    log.debug('Setup incoming hook (%s) (%s)', ifindex, fn.name)
    try:
        ipr.tc("add", "ingress", ifindex, "ffff:")
    except NetlinkError as exc:
        if exc.args[1] != 'File exists':
            raise

    action = {"kind": "bpf", "fd": fn.fd, "name": fn.name, "action": "ok"}
    ipr.tc(
        "add-filter", "u32", ifindex, ":1", parent="ffff:", action=[action],
        protocol=protocols.ETH_P_ALL, classid=1, target=0x10002, keys=['0x0/0x0+0'],
    )


def setup_outgoing(fn, ifindex):
    log.debug('Setup outgoing hook (%s) (%s)', ifindex, fn.name)

    try:
        ipr.tc("add", "sfq", ifindex, "1:")
    except NetlinkError as exc:
        if exc.args[1] != 'File exists':
            raise

    action = {"kind": "bpf", "fd": fn.fd, "name": fn.name, "action": "ok"}

    ipr.tc(
        "add-filter", "u32", ifindex, ":2", parent="1:", action=[action],
        protocol=protocols.ETH_P_ALL, classid=1, target=0x10002, keys=['0x0/0x0+0'],
    )


class Ports(argparse.Action):
    _re_ip_rexp = r'\d+\.\d+\.\d+\.\d+'
    _re_format = re.compile(
        r'(?P<ip>{_re_ip_rexp})?:?'.format(_re_ip_rexp=_re_ip_rexp)
        + r'(?P<game>\d+):(?P<proxy>\d+)'
    )

    def error(self, msg, *args):
        msg %= args
        raise argparse.ArgumentError(self, msg)

    def __call__(self, parser, namespace, values, option_string=None):
        all_ports = getattr(namespace, self.dest, None)
        if all_ports is None:
            all_ports = {}
            setattr(namespace, self.dest, all_ports)

        if isinstance(values, (str, bytes)):
            values = [values]

        for value in values:
            mo = self._re_format.match(value)
            if mo is None:
                self.error("unknown format (%r), expected 'integer:integer' (e.g. '27015:27915')", value)

            match = mo.groupdict()

            ip_match = match.get('ip') or '0.0.0.0'
            try:
                ip = ipaddress.IPv4Address(ip_match)
            except ipaddress.AddressValueError:
                self.error("unknown ip format (%r), expected IPv4 format", ip_match)
                ip = None  # unreachable code, just suppress code inspection warning

            if ip not in all_ports:
                all_ports[ip] = {}

            ip_ports = all_ports[ip]

            gport = int(match['game'])
            pport = int(match['proxy'])

            if not (1 <= gport <= 65535):
                self.error("invalid game port (%s): value should be between 1 and 65535", gport)

            if not (1 <= pport <= 65535):
                self.error("invalid proxy port (%s): value should be between 1 and 65535", pport)

            if gport == pport:
                self.error("invalid port mapping (%r): ports can't be equal", value)

            old_pport = ip_ports.get(gport)
            if old_pport and old_pport != pport:
                self.error(
                    "game port (%s) already mentioned for different proxy port %s",
                    gport, old_pport,
                )

            old_gport = [k for k, v in ip_ports.items() if v == pport]
            if old_gport:
                assert len(old_gport) == 1
                self.error(
                    "proxy port (%s) already mentioned for different game port %s",
                    pport, old_gport[0],
                )

            ip_ports[gport] = pport


def sqredirect():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', '--interface', default=None, type=str,
        help='Interface name. If not provided will be used default.'
    )
    parser.add_argument(
        '-p', '--ports', metavar='27015:27915 or 192.168.0.1:27015:27915', type=str, nargs='*',
        action=Ports,
        required=True,
        help='GameServer:Proxy port to redirect queries'
    )

    args = parser.parse_args()

    try:
        main(args.ports, args.interface)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    sqredirect()
