import argparse
import re
import sys
from unittest import mock

from ipaddress import IPv4Address

import pytest

from sqredirect.redirect import Ports


@pytest.fixture(scope='session', autouse=True)
def _reraise_instead_exit():
    def _reraise(message):
        if sys.exc_info() == (None, None, None):
            pytest.fail('No active exception to reraise: error message=%r' % message)
        raise

    with mock.patch.object(argparse.ArgumentParser, 'error', side_effect=_reraise):
        yield


_esc = re.escape


@pytest.fixture(params=[None, '*'], ids=['nargs_default', 'nargs_*'])
def ports_nargs(request):
    return request.param


@pytest.fixture()
def ports_parser(ports_nargs):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'ports',
        nargs=ports_nargs,
        action=Ports,
    )
    return parser


def test_ports_ok(ports_parser):
    # game:proxy
    args = ports_parser.parse_args(['27015:27915'])
    assert args.ports == {IPv4Address('0.0.0.0'): {27015: 27915}}

    # ip:game:proxy
    args = ports_parser.parse_args(['127.0.0.1:27015:27915'])
    assert args.ports == {IPv4Address('127.0.0.1'): {27015: 27915}}


@pytest.mark.parametrize('ports_nargs', '*', indirect=True)
def test_ports_multiarg_ok(ports_parser, ports_nargs):
    # grouped by equal ip
    args = ports_parser.parse_args(['127.0.0.1:27015:27915', '127.0.0.1:27016:27916'])
    assert args.ports == {IPv4Address('127.0.0.1'): {27015: 27915, 27016: 27916}}

    # splitted by different ip
    args = ports_parser.parse_args(['127.0.0.1:27015:27915', '192.168.0.1:27016:27916'])
    assert args.ports == {IPv4Address('127.0.0.1'): {27015: 27915}, IPv4Address('192.168.0.1'): {27016: 27916}}

    # ports can repeat (not collided) when ip differ
    args = ports_parser.parse_args(['127.0.0.1:27015:27915', '192.168.0.1:27015:27915'])
    assert args.ports == {IPv4Address('127.0.0.1'): {27015: 27915}, IPv4Address('192.168.0.1'): {27015: 27915}}


def test_ports_format_errors(ports_parser):
    parser = ports_parser

    with pytest.raises(argparse.ArgumentError, match=".*?ports can't be equal$"):
        parser.parse_args(['27015:27015'])

    # invalid game port range
    with pytest.raises(
        argparse.ArgumentError,
        match=_esc("invalid game port (78000): value should be between 1 and 65535"),
    ):
        parser.parse_args(['78000:27015'])

    # invalid proxy port range
    with pytest.raises(
        argparse.ArgumentError,
        match=_esc("invalid proxy port (78000): value should be between 1 and 65535"),
    ):
        parser.parse_args(['27015:78000'])

    with pytest.raises(
        argparse.ArgumentError,
        match=_esc("unknown format ('not-int:27915'), expected 'integer:integer' (e.g. '27015:27915')"),
    ):
        parser.parse_args(['not-int:27915'])


@pytest.mark.parametrize('ports_nargs', '*', indirect=True)
def test_ports_collisions(ports_parser, ports_nargs):
    parser = ports_parser
    # duplicate proxy port
    with pytest.raises(
        argparse.ArgumentError,
        match=_esc("proxy port (27916) already mentioned for different game port 27015"),
    ):
        # game-port:proxy-port
        parser.parse_args(['27015:27916', '27016:27916'])

    # duplicate game port
    with pytest.raises(
        argparse.ArgumentError,
        match=_esc("game port (27015) already mentioned for different proxy port 27915"),
    ):
        # game-port:proxy-port
        parser.parse_args(['27015:27915', '27015:27916'])
