"""Installed publisher and registrar exchange actual authenticated TLS traffic."""
from contextlib import closing, contextmanager
from types import SimpleNamespace
import json
import os
import ssl
import subprocess
import time
from urllib.request import urlopen
from uuid import uuid4

import pytest
from keri import Vrsn_2_0
from keri.acdc import Regery, acdcmap, blindate, grant, regcept
from keri.app import Habery, openHby
from keri.core import Blinder, messagize, receipt

from kfregistrar.app.cli.commands.publish import publicSnapshot
from .test_cli import PASSCODE, port
from .test_evidence import framed


@pytest.fixture
def publication(tmp_path):
    """Keep the issuer open while the CLI opens a separate publisher Keeper."""
    base = 'publish-' + uuid4().hex
    publisher = Habery(name='publisher', base=base, bran=PASSCODE, version=Vrsn_2_0)
    try:
        ph = publisher.makeHab('publisher')
        kel = tmp_path / 'publisher.cesr'
        kel.write_bytes(ph.replay(gvrsn=Vrsn_2_0))
        publisher_aid = ph.pre
    finally:
        publisher.close()
    with (openHby(name='publication-witness', version=Vrsn_2_0) as witness,
          closing(Habery(name='issuer', base=base, bran=PASSCODE, version=Vrsn_2_0)) as issuer):
        wh = witness.makeHab('witness', transferable=False)
        issuer.psr.parse(ims=bytearray(wh.replay(gvrsn=Vrsn_2_0)))
        ih = issuer.makeHab('issuer', wits=[wh.pre], toad=1)
        inception = ih.kever.serder
        rip = regcept(israid=ih.pre)
        acdc = acdcmap(israid=ih.pre, iseaid=publisher_aid, regid=rip.said,
                       attribute={'d': '', 'i': publisher_aid, 'secret': 'private disclosure'})
        opening = Blinder.blind(acdc=acdc.said, state='issued')
        bup = blindate(rip.said, rip.said, opening.said)
        ih.interact(data=[dict(i=rip.said, s=event.sad['n'], d=event.said) for event in (rip, bup)])
        for event in (inception, ih.kever.serder):
            issuer.kvy.processReceipt(serder=receipt(ih.pre, event.sn, event.said),
                cigars=wh.sign(event.raw, indexed=False), wigers=[], tsgs=[], local=False)
        assert issuer.db.fullyWitnessed(ih.kever.serder)
        disclosure = messagize(acdc, bonds=[opening.data], gvrsn=Vrsn_2_0)
        message, atc = grant(ih, publisher_aid, 'Private credential', origin=disclosure)
        other = regcept(israid=ih.pre)
        snapshot = tmp_path / 'mixed.cesr'
        snapshot.write_bytes(wh.replay(gvrsn=Vrsn_2_0) + ih.replay(gvrsn=Vrsn_2_0)
                             + framed(rip, (bup, opening), other)
                             + disclosure + message.raw + atc)
        cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
        settings = tmp_path / 'tls.cnf'
        settings.write_text('[req]\ndistinguished_name=dn\nx509_extensions=server\nprompt=no\n'
            '[dn]\nCN=localhost\n[server]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\n')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(cert), '-days', '1', '-config', str(settings)],
            check=True, capture_output=True, timeout=15)
        yield SimpleNamespace(base=base, publisher=publisher_aid, issuer=ih.pre,
            rip=rip, bup=bup, credential=acdc, grant=message, opening=opening,
            other=other, snapshot=snapshot, kel=kel, cert=cert, key=key, folder=tmp_path)


@contextmanager
def registrar(data, publisher):
    """Own an actual separately bootstrapped service and its finite teardown."""
    internal, external = port(), port()
    while internal == external:
        external = port()
    log = data.folder / 'registrar.log'
    env = dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE)
    with log.open('wb') as output:
        process = subprocess.Popen(['kf-registrar', 'start', '--name', 'registrar',
            '--base', data.base, '--alias', 'registrar', '--bootport', str(internal),
            '--http', str(external), '--publisher', publisher, '--kel', str(data.kel),
            '--keypath', str(data.key), '--certpath', str(data.cert),
            '--cafilepath', str(data.cert), '--no-prompt'],
            env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, log.read_text()
                try:
                    with urlopen(f'https://localhost:{external}/health',
                            context=ssl.create_default_context(cafile=str(data.cert)), timeout=.3) as response:
                        assert response.status == 200
                    # TLS belongs to the public API; enrollment stays on private HTTP.
                    with urlopen(f'http://127.0.0.1:{internal}/health', timeout=.3) as response:
                        assert response.status == 200
                    break
                except OSError:
                    assert time.monotonic() < deadline, log.read_text()
                    time.sleep(.05)
            yield f'https://127.0.0.1:{external}'
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)


def publish(data, url, *, certedhost='localhost', timeout=5):
    """Invoke the installed command with explicit publisher and TLS identity."""
    return subprocess.run(['kf-registrar', 'publish', '--name', 'publisher',
        '--base', data.base, '--alias', 'publisher', '--passcode', PASSCODE,
        '--input', str(data.snapshot), '--registry', data.rip.said,
        '--url', url, '--ca', str(data.cert), '--certedhost', certedhost,
        '--timeout', str(timeout)], capture_output=True, text=True, timeout=15)


def test_installed_publish_selects_public_evidence_and_exact_accepted_head(publication):
    data = publication
    selected, expected = publicSnapshot(data.snapshot.read_bytes(), data.rip.said)
    assert expected == data.bup.said
    assert data.credential.raw not in selected and data.grant.raw not in selected
    assert data.opening.qb64b not in selected and data.other.raw not in selected
    with pytest.raises(ValueError, match='complete selected registry history'):
        publicSnapshot(framed(data.bup), data.rip.said)
    conflicting = blindate(data.rip.said, data.rip.said, Blinder.blind().said)
    with pytest.raises(ValueError, match='conflicting registry events'):
        publicSnapshot(framed(data.rip, data.bup, conflicting), data.rip.said)
    with registrar(data, data.publisher) as url:
        wrong_identity = publish(data, url, certedhost='wrong.localhost', timeout=2)
        assert wrong_identity.returncode != 0, wrong_identity.stdout + wrong_identity.stderr
        result = publish(data, url)
        assert result.returncode == 0, result.stdout + result.stderr
        accepted = json.loads(result.stdout)
        assert accepted['heads'] == {data.rip.said: data.bup.said}
        assert not accepted['pending'] and not accepted['rejected']
    # Independent persisted native evidence contains no credential or opening.
    with closing(Habery(name='registrar', base=data.base, bran=PASSCODE, version=Vrsn_2_0)) as hby:
        rgy = Regery(hby=hby, name='registrar', base=data.base, temp=False)
        try:
            assert rgy.store.headEvent(data.rip.said).said == data.bup.said
            assert rgy.store.event(data.credential.said) is None
            assert rgy.store.event(data.other.said) is None
            assert rgy.store.opening(data.bup.said) is None
            assert hby.db.exns.get((data.grant.said,)) is None
            assert hby.db.fullyWitnessed(hby.db.kevers[data.issuer].serder)
        finally:
            rgy.close()


def test_installed_publish_refuses_an_authenticated_but_unauthorized_publisher(publication):
    data = publication
    with registrar(data, data.issuer) as url:
        result = publish(data, url)
        assert result.returncode != 0
        assert 'HTTP 403' in result.stdout, result.stdout + result.stderr


def test_publish_client_uses_only_configured_ca(publication):
    from kfregistrar.app.cli.commands.publish import publish as publication_do
    data = publication
    args = SimpleNamespace(name='publisher', base=data.base, bran=PASSCODE, alias='publisher',
        input=str(data.snapshot), registry=data.rip.said, url='https://127.0.0.1:1/',
        ca=str(data.cert), certedhost='localhost', timeout=1)
    operation = publication_do(tymth=lambda: 0.0, args=args)
    try:
        next(operation)
        next(operation)
        context = operation.gi_frame.f_locals['client'].connector.context
        assert context.get_ca_certs(binary_form=True) == [ssl.PEM_cert_to_DER_cert(data.cert.read_text())]
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    finally:
        operation.close()
