"""Publish a finite public registry snapshot through the authenticated API."""
import argparse
import ipaddress
import json
import math
import os
import ssl
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

from hio.base import doing
from hio.core import http
from keri import Vrsn_2_0
from keri.cli.common.existing import setupHby
from keri.core import Parser, SerderACDC, SerderKERI, query
from keri.core.parsing import MsgParseDom
from keri.help import helping
from keri.peer.exchanging import serializeParsedSubstream
from keri.app.httping import CESR_CONTENT_TYPE


def positiveTimeout(value):
    """Require a finite positive operation timeout, in seconds."""
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError('timeout must be finite and positive')
    return value


parser = argparse.ArgumentParser(description=__doc__)
parser.set_defaults(handler=lambda args: [doing.doify(publish, args=args)])
parser.add_argument('--name', '-n', required=True, help='Existing publisher keystore name')
parser.add_argument('--base', '-b', default='', help='Publisher keystore base')
parser.add_argument('--alias', '-a', required=True, help='Local publisher identifier alias')
parser.add_argument('--passcode', '-p', dest='bran', default=os.getenv('KLI_KEYSTORE_PASSCODE'))
parser.add_argument('--input', required=True, help='Complete mixed CESR snapshot file')
parser.add_argument('--registry', required=True, help='Exact registry SAID to publish')
parser.add_argument('--url', required=True, help='HTTPS registrar base URL')
parser.add_argument('--ca', required=True, help='Explicit trusted CA bundle')
parser.add_argument('--certedhost', help='Explicit certificate hostname for an IP URL')
parser.add_argument('--timeout', type=positiveTimeout, default=20.0)


def publicSnapshot(raw, registry):
    """Select public top-level evidence without importing disclosure or custody.

    Parsing consumes the whole snapshot before any signing or network request.
    Only v2 CESR public authentication/source attachments survive selection.
    """
    remaining, stream, slots = bytearray(raw), bytearray(), {}
    parser = Parser(version=Vrsn_2_0)
    while remaining:
        before = len(remaining)
        parsed = parser.parseOneBare(ims=remaining, processive=False)
        if parsed is None or parsed.serder is None or len(remaining) >= before:
            raise ValueError('Input contains an incomplete CESR frame')
        event = parsed.serder
        if isinstance(event, SerderACDC):
            regid = event.said if event.ilk == 'rip' else event.sad.get('rd')
            if event.ilk not in ('rip', 'bup') or regid != registry:
                continue
            if event.sn in slots and slots[event.sn].said != event.said:
                raise ValueError('Input has conflicting registry events at one ordinal')
            slots[event.sn] = event
            public = MsgParseDom(serder=event, sscs=parsed.sscs, ssts=parsed.ssts)
        elif isinstance(event, SerderKERI) and event.ilk in ('icp', 'dip', 'rot', 'drt', 'ixn', 'rct'):
            public = MsgParseDom(serder=event, sigers=parsed.sigers, wigers=parsed.wigers,
                cigars=parsed.cigars, tsgs=parsed.tsgs, lsgs=parsed.lsgs,
                sscs=parsed.sscs, ssts=parsed.ssts, tdcs=parsed.tdcs)
        else:
            continue
        stream.extend(serializeParsedSubstream(public))
    if not slots:
        raise ValueError('Input has no RIP/BUP for the selected registry')
    ordered = sorted(slots)
    if ordered != list(range(len(ordered))) or slots[0].ilk != 'rip':
        raise ValueError('Input must contain the complete selected registry history from RIP')
    for sn in ordered[1:]:
        if slots[sn].sad['p'] != slots[sn - 1].said:
            raise ValueError('Input has a disconnected selected registry history')
    return bytes(stream), slots[ordered[-1]].said


def publicationTarget(url, ca, certedhost):
    """Bind HTTPS transport to one explicit authority and certificate identity."""
    target = urlsplit(url)
    target.port  # Reject malformed ports before opening the publisher store.
    if (target.scheme != 'https' or not target.hostname or target.username is not None
            or target.password is not None or target.query or target.fragment):
        raise ValueError('Registrar URL must be HTTPS without credentials, query or fragment')
    if not Path(ca).expanduser().is_file():
        raise ValueError('CA bundle must be an existing file')
    try:
        ipaddress.ip_address(target.hostname)
    except ValueError:
        if certedhost is not None:
            raise ValueError('Certificate hostname override requires an IP URL')
    else:
        if not certedhost or not certedhost.strip():
            raise ValueError('An IP URL requires an explicit certificate hostname')
    return target


def publish(tymth, tock=0.0, *, args, **kwa):
    """Sign with the publisher only; wait finitely for the exact accepted head."""
    yield tock
    stream, expected = publicSnapshot(Path(args.input).read_bytes(), args.registry)
    target = publicationTarget(args.url, args.ca, args.certedhost)
    hby, client, transport = None, None, None
    try:
        hby = setupHby(args.name, base=args.base, bran=args.bran,
                       noPrompt=True, version=Vrsn_2_0)
        hab = hby.habByName(args.alias)
        if hab is None:
            raise ValueError('Publisher alias does not exist')
        message = query(pre=hab.pre, route='tels/publish',
            query={'stream': stream.decode()}, stamp=helping.nowIso8601(), version=Vrsn_2_0)
        signed = hab.endorse(message, last=True, framed=False, gvrsn=Vrsn_2_0)

        ca = str(Path(args.ca).expanduser().resolve())
        # HIO also needs cafilepath to avoid reloading system roots.
        client = http.clienting.Client(scheme='https', hostname=target.hostname,
            port=target.port or 443, context=ssl.create_default_context(cafile=ca), cafilepath=ca,
            certedhost=args.certedhost, redirectable=False)
        transport = doing.DoDoer(doers=[http.clienting.ClientDoer(client)], tymth=tymth)
        transport.enter()
        client.request(method='POST', path=target.path.rstrip('/') + '/ingest',
                       headers={'Content-Type': CESR_CONTENT_TYPE}, body=bytes(signed))
        deadline = monotonic() + args.timeout
        while not client.responses:
            if monotonic() >= deadline:
                raise TimeoutError('Registrar publication timed out')
            transport.recur(tyme=tymth())
            yield tock

        response = client.responses.popleft()
        if not 200 <= response['status'] < 300:
            raise ValueError(f"Registrar refused publication (HTTP {response['status']})")
        result = json.loads(response['body'])
        if (not isinstance(result, dict) or not isinstance(result.get('pending'), dict)
                or not isinstance(result.get('rejected'), dict) or result['pending']
                or result['rejected'] or result.get('heads') != {args.registry: expected}):
            raise ValueError('Registrar did not accept the exact selected registry head')
        print(json.dumps(result))
    finally:
        if transport is not None:
            transport.exit()
        if client is not None:
            client.close()
        if hby is not None:
            hby.close()
