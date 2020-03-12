#!/usr/bin/python2

from __future__ import print_function

import argparse
import atexit
import logging.config
import re
import time
import signal
from bcc import BPF
from ctypes import c_ushort
from pyroute2 import IPRoute, protocols, IPDB
from pyroute2.netlink.exceptions import NetlinkError


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

ipr = IPRoute()


log = logging.getLogger('main')


def main(ports, interface=None):
    if interface is None:
        log.info('Interface not provided')
        interface = get_default_interface()
        log.info('Use interface for default route: %s', interface)

    ifindex = ipr.link_lookup(ifname=interface)[0]

    cflags = ["-include", "utils.h"]

    log.info('Building eBPF program ...')
    bpf = BPF(src_file="redirect.c", cflags=cflags, debug=0)
    fn_incoming = bpf.load_func("incoming", BPF.SCHED_ACT)
    fn_outgoing = bpf.load_func("outgoing", BPF.SCHED_ACT)

    cache2gameserver_port = bpf.get_table('cache2gameserver_port')
    cache2gameserver_port.update((
        (c_ushort(v), c_ushort(k)) for k, v in ports.items()
    ))
    gameserver2cache_port = bpf.get_table('gameserver2cache_port')
    gameserver2cache_port.update((
        (c_ushort(k), c_ushort(v)) for k, v in ports.items()
    ))

    log.info('Attach eBPF program to interface ...')
    reg_cleanup(ifindex)
    setup_incoming(fn_incoming, ifindex)
    setup_outgoing(fn_outgoing, ifindex)

    log.info('Running ...')
    while True:
        time.sleep(1)
        bpf.trace_print()


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
        protocol=protocols.ETH_P_ALL, classid=1, target=0x10002, keys=['0x0/0x0+0']
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
        protocol=protocols.ETH_P_ALL, classid=1, target=0x10002, keys=['0x0/0x0+0']
    )


class Ports(argparse.Action):
    _re_format = re.compile(r'(\d+):(\d+)')

    def error(self, msg, *args):
        msg %= args
        raise argparse.ArgumentError(self, msg)

    def __call__(self, parser, namespace, values, option_string=None):
        ports = {}
        for value in values:
            mo = self._re_format.match(value)
            if mo is None:
                self.error("unknown format (%r), expected 'integer:integer' (e.g. '27015:27915')", value)

            gport = int(mo.group(1))
            pport = int(mo.group(2))

            if not (1 <= gport <= 65535):
                self.error("invalid game port (%s): value should be between 1 and 65535", gport)

            if not (1 <= pport <= 65535):
                self.error("invalid proxy port (%s): value should be between 1 and 65535", pport)

            if gport == pport:
                self.error("invalid port mapping (%r): ports can't be equal", value)

            old_pport = ports.get(gport)
            if old_pport and old_pport != pport:
                self.error(
                    "game port (%s) already mentioned for different proxy port %s",
                    gport, old_pport,
                )

            old_gport = [k for k, v in ports.items() if v == pport]
            if old_gport:
                assert len(old_gport) == 1
                self.error(
                    "proxy port (%s) already mentioned for different game port %s",
                    pport, old_gport[0],
                )

            ports[gport] = pport

        setattr(namespace, self.dest, ports)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', '--interface', default=None, type=str,
        help='Interface name. If not provided will be used default.'
    )
    parser.add_argument(
        '-p', '--ports', metavar='27015:27915', type=str, nargs='*',
        action=Ports,
        required=True,
        help='GameServer:Proxy port to redirect queries'
    )

    args = parser.parse_args()

    try:
        main(args.ports, args.interface)
    except KeyboardInterrupt:
        pass
