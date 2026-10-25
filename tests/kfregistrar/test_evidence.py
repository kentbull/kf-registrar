"""Exercise the fork's HTTP boundary with real signatures and durable core state."""
from datetime import timedelta

from falcon import testing
from hio.base import doing
from keri import Vrsn_2_0
from keri.acdc import Regery, acdcmap, blindate, regcept
from keri.acdc.regbasing import RegBaser
from keri.app.evidencing import EvidenceContext, signedQuery
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Counter, Codens, Parser, SerderACDC
from keri.help import helping

from kfregistrar.core.serving import Context, makeContext, _corsApp, loadExternalEnds


def framed(*items):
    """Return exact event bodies with optional expanded opening attachments."""
    stream = bytearray()
    for item in items:
        event, opening = item if isinstance(item, tuple) else (item, None)
        attachments = Blinder.enclose([opening]) if opening is not None else b''
        stream.extend(event.raw)
        stream.extend(Counter.enclose(qb64=attachments,
            code=Codens.AttachmentGroup, version=Vrsn_2_0))
    return bytes(stream)


def issued(hab):
    """Return a public registry and update, both anchored by the supplied habitat."""
    rip = regcept(israid=hab.pre)
    credential = acdcmap(israid=hab.pre, regid=rip.said,
                         attribute={"d": "", "name": "public example"})
    opening = Blinder.blind(acdc=credential.said, state="issued")
    bup = blindate(rip.said, rip.said, opening.said)
    hab.interact(data=[dict(s=e.sad["n"], d=e.said) for e in (rip, bup)])
    return rip, bup, opening


def test_signed_publication_exports_independently_verifiable_public_update():
    """Authorize roles and verify full HTTP evidence in a fresh independent store."""
    with (openHby(name="publisher", version=Vrsn_2_0) as issuer,
          openHby(name="host", version=Vrsn_2_0) as host,
          openHby(name="reader", version=Vrsn_2_0) as reader):
        publisher = issuer.makeHab(name="issuer")
        observer = reader.makeHab(name="observer")
        rip, bup, opening = issued(publisher)
        ctx = makeContext(host, publishers=[publisher.pre], observers=[observer.pre],
                          fullEvidence=True)
        independent = EvidenceContext(reader)
        try:
            assert not ctx.ingest(publisher.replay(gvrsn=Vrsn_2_0))["rejected"]
            assert not ctx.ingest(observer.replay(gvrsn=Vrsn_2_0))["rejected"]
            client = testing.TestClient(ctx.externalApp)
            headers = {"Content-Type": CESR_CONTENT_TYPE}
            evidence = framed(rip, (bup, opening)).decode()
            denied = client.simulate_post("/ingest", headers=headers,
                body=signedQuery(observer, "tels/publish", {"stream": evidence}))
            assert denied.status_code == 403
            sent = client.simulate_post("/ingest", headers=headers,
                body=signedQuery(publisher, "tels/publish", {"stream": evidence}))
            assert sent.status_code == 200
            assert sent.json["accepted"][rip.said] == 2
            assert ctx.store.headEvent(rip.said).said == bup.said
            response = client.simulate_post("/", headers=headers,
                body=signedQuery(observer, "tels/bulk", {"i": rip.said}))
            assert response.status_code == 200
            result = independent.ingest(response.content)
            assert not result["pending"] and not result["rejected"]
            assert independent.store.headEvent(rip.said).said == bup.said
            remaining = bytearray(independent.clone([rip.said]))
            public = []
            parser = Parser(version=Vrsn_2_0)
            while remaining:
                dom = parser.parseOne(ims=remaining, processive=False, local=False)
                if isinstance(dom.serder, SerderACDC) and dom.serder.ilk == 'bup':
                    public.extend(dom.bsqs)
            assert len(public) == 1
            assert b''.join(item.qb64b for item in public[0]) == opening.qb64b
            # The endpoint must reject trailing signed messages, rather than
            # authenticating a valid prefix and silently ignoring the suffix.
            trailing = signedQuery(observer, "tels/bulk", {"i": rip.said})
            assert client.simulate_post("/", headers=headers,
                body=trailing + trailing).status_code == 400
        finally:
            ctx.close()
            independent.close()


def test_admin_pending_survives_new_context_without_resubmitting_tel(tmp_path):
    """Reopen persistent evidence and resolve it using only subsequently supplied KEL.

    Parameters:
        tmp_path: pytest directory for real persistent registry LMDB files.
    """
    with (openHby(name="late-issuer", version=Vrsn_2_0) as issuer,
          openHby(name="pending-host", version=Vrsn_2_0) as host):
        publisher = issuer.makeHab(name="issuer")
        hab = host.makeHab(name="registrar")
        rip, bup, opening = issued(publisher)
        baser = RegBaser(name="durable", headDirPath=str(tmp_path), temp=False)
        rgy = Regery(host, baser=baser)
        first = Context(host, hab, rgy)
        pending = first.ingest(framed(rip, (bup, opening)))
        assert pending["pending"] and not pending["accepted"]
        assert first.registries() == []
        first.close()
        baser.reopen()
        # Replace both application and verification objects. No remembered
        # batches or repeated TEL input may contribute to recovery.
        second = Context(host, hab, Regery(host, baser=baser))
        try:
            assert second.registries() == []
            result = second.ingest(publisher.replay(gvrsn=Vrsn_2_0))
            assert not result["rejected"]
            assert second.store.headEvent(rip.said).said == bup.said
            assert second.store.opening(bup.said) == opening.qb64
        finally:
            second.close()


def test_registrar_pruner_survives_restart_and_cancellation(tmp_path, monkeypatch):
    """Expire authenticated query state without deleting verified KEL evidence."""
    now = [helping.fromIso8601('2021-01-01T00:00:00.000000+00:00')]
    monkeypatch.setattr(helping, 'nowUTC', lambda: now[0])
    monkeypatch.setattr(helping, 'nowIso8601', lambda: helping.toIso8601(now[0]))

    config = {'kram': {'enabled': True, 'denials': [],
              'caches': {'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]}}}
    with openHby(name='pruner-source', version=Vrsn_2_0) as sender:
        requester = sender.makeHab(name='requester')
        raw = signedQuery(requester, 'tels/bulk')
        query = Parser(version=Vrsn_2_0).parseOne(
            ims=bytearray(raw), processive=False).serder
        key = (requester.pre, query.said)

        with openHby(name='pruner-registrar', headDirPath=str(tmp_path),
                     temp=False, version=Vrsn_2_0) as receiver:
            hab = receiver.makeHab(name='registrar')
            ctx = Context(receiver, hab, Regery(receiver),
                          observers=[requester.pre], config=config)
            ctx.externalApp = _corsApp()
            loadExternalEnds(ctx.externalApp, ctx)
            try:
                assert not ctx.ingest(requester.replay(gvrsn=Vrsn_2_0))['rejected']
                response = testing.TestClient(ctx.externalApp).simulate_post(
                    '/', body=raw, headers={'Content-Type': CESR_CONTENT_TYPE})
                assert response.status_code == 200
                cached = receiver.db.kramMSGC.get(key)
                assert cached is not None
                doist = doing.Doist(tock=1.0)
                deeds = doist.enter(doers=[ctx])
                doist.recur(deeds=deeds)
                doist.exit(deeds=deeds)
                assert receiver.db.kramMSGC.get(key) == cached
            finally:
                ctx.close()

        now[0] += timedelta(milliseconds=cached.d + cached.pml + 1)
        with openHby(name='pruner-registrar', headDirPath=str(tmp_path),
                     temp=False, version=Vrsn_2_0) as receiver:
            ctx = Context(receiver, receiver.habByName('registrar'), Regery(receiver),
                          observers=[requester.pre], config=config)
            ctx.externalApp = _corsApp()
            loadExternalEnds(ctx.externalApp, ctx)
            deeds = None
            try:
                assert ctx.pruner.kramer is ctx.kvy.kramer
                assert ctx.doers.count(ctx.pruner) == 1
                doist = doing.Doist(tock=1.0)
                deeds = doist.enter(doers=[ctx])
                doist.recur(deeds=deeds)
                assert receiver.db.kramMSGC.get(key) is None
                assert receiver.db.kels.getLast(
                    keys=requester.pre, on=0) == requester.kever.serder.said
                response = testing.TestClient(ctx.externalApp).simulate_post(
                    '/', body=raw, headers={'Content-Type': CESR_CONTENT_TYPE})
                assert response.status_code == 401
            finally:
                if deeds is not None:
                    doist.exit(deeds=deeds)
                ctx.close()
