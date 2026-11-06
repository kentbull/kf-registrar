"""Exercise the fork's HTTP boundary with real signatures and durable core state."""
from datetime import timedelta

import pytest

from falcon import testing
from hio.base import doing
from keri import Vrsn_2_0
from keri.acdc import Regery, acdcmap, blindate, regcept
from keri.acdc.regbasing import RegBaser
from keri.acdc.regeventing import vetBlind, vetBound
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Counter, Codens, Diger, Number, Parser, SerderACDC, query
from keri.help import helping
from keri.kering import ConfigurationError, Kinds

from kfregistrar.core.serving import Context, makeContext, _corsApp, loadExternalEnds, loadInternalEnds, setup


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


def signedQuery(hab, route, attributes=None):
    """Sign a fresh service query with the requester's actual habitat keys."""
    serder = query(pre=hab.pre, route=route, query=attributes or {},
                   stamp=helping.nowIso8601(), version=Vrsn_2_0)
    return bytes(hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0))


def issued(hab, kind=Kinds.json, bound=False):
    """Return a public registry and update, both anchored by the supplied habitat."""
    rip = regcept(israid=hab.pre, kind=kind)
    credential = acdcmap(israid=hab.pre, regid=rip.said,
                         attribute={"d": "", "name": "public example"},
                         **({"iseaid": hab.pre} if bound else {}))
    if bound:
        issueeEvent = hab.kever.serder
        opening = Blinder.blind(acdc=credential.said, state="issued", bound=True,
                                bsn=issueeEvent.sn, bd=issueeEvent.said)
        vetBlind(opening, blid=opening.said)
        assert vetBound(opening, acdc=credential, db=hab.db).said == issueeEvent.said
    else:
        opening = Blinder.blind(acdc=credential.said, state="issued")
    bup = blindate(rip.said, rip.said, opening.said, kind=kind)
    hab.interact(data=[dict(i=rip.said, s=e.sad["n"], d=e.said) for e in (rip, bup)])
    return rip, bup, opening


def test_account_enrollment_persists_and_revokes_without_removing_static_roles(tmp_path):
    """Actual signed publication requires durable enrollment, including after reopen."""
    with (openHby(name="enrolled-publisher", version=Vrsn_2_0) as issuer,
          openHby(name="enrollment-host", version=Vrsn_2_0) as host):
        publisher = issuer.makeHab("publisher")
        hab = host.makeHab("registrar")
        rip, bup, opening = issued(publisher)
        path = f"/accounts/{publisher.pre}"
        kel = publisher.replay(gvrsn=Vrsn_2_0).decode()
        attributes = {"stream": framed(rip, (bup, opening)).decode()}
        headers = {"Content-Type": CESR_CONTENT_TYPE}
        baser = RegBaser(name="enrollment", headDirPath=str(tmp_path), temp=False)
        first = Context(host, hab, Regery(host, baser=baser), observers=[publisher.pre])
        inner, outer = _corsApp(), _corsApp()
        loadInternalEnds(inner, first)
        loadExternalEnds(outer, first)
        admin, public = testing.TestClient(inner), testing.TestClient(outer)
        try:
            # Startup denies publication; enrollment must establish real public identity evidence.
            with pytest.raises(ConfigurationError, match="loopback"):
                setup(host, bootHost="0.0.0.0")
            assert public.simulate_post("/ingest", headers=headers,
                body=signedQuery(publisher, "tels/publish", attributes)).status_code == 403
            assert admin.simulate_put(path, json={"roles": ["publisher"],
                "kel": framed(rip).decode()}).status_code == 400
            assert first.store.event(rip.said) is None
            assert admin.simulate_get(path).status_code == 404
            assert admin.simulate_put(path, json={"roles": ["publisher"],
                "kel": framed(publisher.kever.serder).decode()}).status_code == 409
            assert admin.simulate_get(path).status_code == 404
            enrolled = admin.simulate_put(path, json={"roles": ["publisher"], "kel": kel})
            assert enrolled.status_code == 200
            assert enrolled.json == dict(aid=publisher.pre, roles=["publisher"], service=hab.pre)
            published = public.simulate_post("/ingest", headers=headers,
                body=signedQuery(publisher, "tels/publish", attributes))
            assert published.status_code == 200
            assert published.json["heads"] == {rip.said: bup.said}
            assert host.habByPre(publisher.pre) is None
        finally:
            first.close()
        # Reopen the permission-bearing registry store and restore the context's live allowlists.
        baser.reopen()
        second = Context(host, hab, Regery(host, baser=baser),
                         observers=[publisher.pre], publishers=[hab.pre])
        inner, outer = _corsApp(), _corsApp()
        loadInternalEnds(inner, second)
        loadExternalEnds(outer, second)
        admin, public = testing.TestClient(inner), testing.TestClient(outer)
        try:
            assert admin.simulate_get(path).json == enrolled.json
            assert public.simulate_post("/ingest", headers=headers,
                body=signedQuery(publisher, "tels/publish", attributes)).status_code == 200
            # Replacement and revocation remove dynamic roles while preserving operator source access.
            assert admin.simulate_put(path, json={"roles": ["observer"], "kel": kel}).status_code == 200
            assert publisher.pre not in second.publishers
            assert admin.simulate_delete(path).status_code == 204
            assert admin.simulate_delete(path).status_code == 204
            assert admin.simulate_get(path).status_code == 404
            assert public.simulate_post("/ingest", headers=headers,
                body=signedQuery(publisher, "tels/publish", attributes)).status_code == 403
            assert public.simulate_post("/", headers=headers,
                body=signedQuery(publisher, "tels/bulk", {"i": rip.said})).status_code == 200
            assert hab.pre in second.publishers
            assert second.store.headEvent(rip.said).said == bup.said
            assert second.store.opening(bup.said).qb64 == opening.qb64
        finally:
            second.close()


@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cesr])
@pytest.mark.parametrize("bound", [pytest.param(False, id="bsq"), pytest.param(True, id="bss")])
def test_signed_publication_exports_independently_verifiable_public_update(kind, bound):
    """Authorize roles and verify full HTTP evidence in a fresh independent store."""
    with (openHby(name="publisher", version=Vrsn_2_0) as issuer,
          openHby(name="host", version=Vrsn_2_0) as host,
          openHby(name="reader", version=Vrsn_2_0) as reader):
        publisher = issuer.makeHab(name="issuer")
        observer = reader.makeHab(name="observer")
        rip, bup, opening = issued(publisher, kind=kind, bound=bound)
        ctx = makeContext(host, publishers=[publisher.pre], observers=[observer.pre])
        independent = makeContext(reader, alias="observer")
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
            assert ctx.store.opening(bup.said).qb64 == opening.qb64
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
                dom = parser.parseOneBare(ims=remaining, processive=False, local=False)
                if isinstance(dom.serder, SerderACDC) and dom.serder.ilk == 'bup':
                    public.extend(dom.bsqs + dom.bsss)
            assert not public
            # Independently parsing public HTTP bytes preserves the explicitly
            # disclosed proof; unrelated intake does not publish it implicitly.
            public = []
            remaining = bytearray(response.content)
            while remaining:
                dom = parser.parseOneBare(ims=remaining, processive=False, local=False)
                if isinstance(dom.serder, SerderACDC) and dom.serder.ilk == "bup":
                    public.extend(dom.bsqs + dom.bsss)
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
        pending = first.ingest(framed(rip, (bup, opening)), publish=True)
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
            assert second.store.opening(bup.said).qb64 == opening.qb64
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


@pytest.mark.parametrize("bound", [pytest.param(False, id="bsq"), pytest.param(True, id="bss")])
def test_signed_pending_publication_retains_only_authorized_disclosure_after_reopen(tmp_path, bound):
    """An authenticated publisher's exact proof survives missing KEL and restart."""
    with (openHby(name="pending-publisher", version=Vrsn_2_0) as issuer,
          openHby(name="pending-observer", version=Vrsn_2_0) as reader,
          openHby(name="pending-http-host", version=Vrsn_2_0) as host):
        publisher = issuer.makeHab(name="publisher")
        observer = reader.makeHab(name="observer")
        rip, bup, opening = issued(publisher, bound=bound)
        hab = host.makeHab(name="registrar")
        baser = RegBaser(name="http-durable", headDirPath=str(tmp_path), temp=False)
        first = Context(host, hab, Regery(host, baser=baser),
                        observers=[observer.pre], publishers=[publisher.pre])
        first.externalApp = _corsApp()
        loadExternalEnds(first.externalApp, first)
        # Only the publisher's inception is initially available: the BUP's
        # actual anchoring interaction is deliberately withheld.
        inception = next(issuer.db.clonePreIter(pre=publisher.pre, gvrsn=Vrsn_2_0))
        assert not first.ingest(inception)["rejected"]
        assert not first.ingest(observer.replay(gvrsn=Vrsn_2_0))["rejected"]
        evidence = framed(rip, (bup, opening)).decode()
        headers = {"Content-Type": CESR_CONTENT_TYPE}
        client = testing.TestClient(first.externalApp)
        denied = client.simulate_post("/ingest", headers=headers,
            body=signedQuery(observer, "tels/publish", {"stream": evidence}))
        assert denied.status_code == 403
        assert first.pendingOpenings.get(bup.said) is None
        pending = client.simulate_post("/ingest", headers=headers,
            body=signedQuery(publisher, "tels/publish", {"stream": evidence}))
        assert pending.status_code == 202
        assert pending.json["pending"][rip.said] == 2
        assert first.pendingOpenings.get(bup.said) == opening.qb64
        assert first.store.opening(bup.said) is None
        assert first.registries() == []
        first.close()
        baser.reopen()
        second = Context(host, hab, Regery(host, baser=baser),
                         observers=[observer.pre], publishers=[publisher.pre])
        second.externalApp = _corsApp()
        loadExternalEnds(second.externalApp, second)
        try:
            # The original TEL and proof are not resubmitted.
            assert not second.ingest(publisher.replay(gvrsn=Vrsn_2_0))["rejected"]
            assert second.store.headEvent(rip.said).said == bup.said
            assert second.store.opening(bup.said).qb64 == opening.qb64
            assert second.pendingOpenings.get(bup.said) is None
            response = testing.TestClient(second.externalApp).simulate_post(
                "/", headers=headers,
                body=signedQuery(observer, "tels/bulk", {"i": rip.said}))
            assert response.status_code == 200
            assert opening.qb64b in response.content
            assert second.store.cloneTel(rip.said) == rip.raw + bup.raw
        finally:
            second.close()


def test_unpublished_intake_verifies_tel_without_retaining_public_opening():
    """Raw foreign intake cannot opt a private held proof into publication."""
    with (openHby(name="unpublished-issuer", version=Vrsn_2_0) as issuer,
          openHby(name="unpublished-host", version=Vrsn_2_0) as host):
        publisher = issuer.makeHab(name="publisher")
        rip, bup, opening = issued(publisher)
        ctx = makeContext(host)
        try:
            assert not ctx.ingest(publisher.replay(gvrsn=Vrsn_2_0))["rejected"]
            result = ctx.ingest(framed(rip, (bup, opening)))
            assert result["accepted"][rip.said] == 2
            assert ctx.store.headEvent(rip.said).said == bup.said
            assert ctx.store.opening(bup.said) is None
            assert ctx.pendingOpenings.get(bup.said) is None
            assert opening.qb64b not in ctx.clone([rip.said])
            assert ctx.ingest(framed((bup, opening)), publish=True)["accepted"][rip.said] == 1
            assert ctx.store.opening(bup.said).qb64 == opening.qb64
            assert opening.qb64b in ctx.clone([rip.said])
        finally:
            ctx.close()


def test_pending_public_opening_follows_core_sibling_arbitration():
    """A later anchored rival never exposes its proof after losing acceptance."""
    with (openHby(name="sibling-publisher", version=Vrsn_2_0) as issuer,
          openHby(name="sibling-host", version=Vrsn_2_0) as host):
        publisher = issuer.makeHab(name="publisher")
        rip, winner, opening = issued(publisher)
        rivalOpening = Blinder.blind(acdc=opening.acdc, state="revoked")
        rival = blindate(rip.said, rip.said, rivalOpening.said)
        publisher.interact(data=[dict(i=rip.said, s=rival.sad["n"], d=rival.said)])
        ctx = makeContext(host)
        try:
            # Reversed arrival order cannot overrule the ordinary earlier
            # accepted KEL anchor, once that KEL evidence becomes available.
            pending = ctx.ingest(framed(rip, (rival, rivalOpening),
                                       (winner, opening)), publish=True)
            assert pending["pending"][rip.said] == 3
            assert ctx.pendingOpenings.get(rival.said) == rivalOpening.qb64
            assert ctx.pendingOpenings.get(winner.said) == opening.qb64
            assert not ctx.ingest(publisher.replay(gvrsn=Vrsn_2_0))["rejected"]
            assert ctx.store.headEvent(rip.said).said == winner.said
            assert ctx.store.opening(winner.said).qb64 == opening.qb64
            assert ctx.pendingOpenings.get(rival.said) is None
            assert ctx.store.opening(rival.said) is None
            exported = ctx.clone([rip.said])
            assert opening.qb64b in exported
            assert rivalOpening.qb64b not in exported
        finally:
            ctx.close()


def test_bulk_query_accepts_only_its_requesters_exact_kel_seal():
    """Preserve the existing source-seal request lane, including body binding."""
    with (openHby(name="sealed-requester", version=Vrsn_2_0) as reader,
          openHby(name="sealed-host", version=Vrsn_2_0) as host):
        observer = reader.makeHab(name="observer")
        request = query(pre=observer.pre, route="tels/bulk", query={},
                        stamp=helping.nowIso8601(), version=Vrsn_2_0)
        observer.interact(data=[dict(d=request.said)])
        source = observer.kever.serder
        attachments = Counter.enclose(
            qb64=Number(num=source.sn).qb64b + Diger(qb64=source.said).qb64b,
            code=Codens.SealSourceCouples, version=Vrsn_2_0)
        attachments = Counter.enclose(qb64=attachments,
                                      code=Codens.AttachmentGroup, version=Vrsn_2_0)
        ctx = makeContext(host, observers=[observer.pre])
        try:
            assert not ctx.ingest(observer.replay(gvrsn=Vrsn_2_0))["rejected"]
            client = testing.TestClient(ctx.externalApp)
            headers = {"Content-Type": CESR_CONTENT_TYPE}
            accepted = client.simulate_post("/", headers=headers,
                                            body=request.raw + attachments)
            assert accepted.status_code == 200
            unrelated = query(pre=observer.pre, route="tels/bulk", query={"unsealed": True},
                              stamp=helping.nowIso8601(), version=Vrsn_2_0)
            rejected = client.simulate_post("/", headers=headers,
                                            body=unrelated.raw + attachments)
            assert rejected.status_code == 401
        finally:
            ctx.close()


def test_bad_disclosed_opening_does_not_stage_its_bup_or_poison_retry():
    """A valid TEL body does not excuse a mismatched explicitly published proof."""
    with (openHby(name="proof-publisher", version=Vrsn_2_0) as issuer,
          openHby(name="proof-host", version=Vrsn_2_0) as host):
        publisher = issuer.makeHab(name="publisher")
        rip, bup, opening = issued(publisher)
        wrong = Blinder.blind(acdc=opening.acdc, state="revoked")
        ctx = makeContext(host)
        try:
            assert not ctx.ingest(publisher.replay(gvrsn=Vrsn_2_0))["rejected"]
            rejected = ctx.ingest(framed(rip, (bup, wrong)), publish=True)
            assert rejected["rejected"]
            assert ctx.store.event(bup.said) is None
            assert ctx.pendingOpenings.get(bup.said) is None
            accepted = ctx.ingest(framed((bup, opening)), publish=True)
            assert accepted["accepted"][rip.said] == 1
            assert ctx.store.headEvent(rip.said).said == bup.said
            assert ctx.store.opening(bup.said).qb64 == opening.qb64
        finally:
            ctx.close()
