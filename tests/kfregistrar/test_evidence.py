"""Exercise the fork's HTTP boundary with real signatures and durable core state."""
from falcon import testing
from keri import Vrsn_2_0
from keri.acdc import Regery, acdcmap, regcept, update
from keri.acdc.regbasing import RegBaser
from keri.app.evidencing import EvidenceContext, signedQuery
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Counter, Codens

from kfregistrar.core.serving import Context, makeContext


def framed(*events):
    """Return exact event bodies with complete empty native attachment groups."""
    foot = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    return b"".join(event.raw + foot for event in events)


def issued(hab):
    """Return a public registry and update, both anchored by the supplied habitat."""
    rip = regcept(israid=hab.pre)
    credential = acdcmap(israid=hab.pre, regid=rip.said,
                         attribute={"d": "", "name": "public example"})
    upd = update(rip.said, rip.said, credential.said, "issued")
    hab.interact(data=[dict(s=e.sad["n"], d=e.said) for e in (rip, upd)])
    return rip, upd


def test_signed_publication_exports_independently_verifiable_public_update():
    """Authorize roles and verify full HTTP evidence in a fresh independent store."""
    with (openHby(name="publisher", version=Vrsn_2_0) as issuer,
          openHby(name="host", version=Vrsn_2_0) as host,
          openHby(name="reader", version=Vrsn_2_0) as reader):
        publisher = issuer.makeHab(name="issuer")
        observer = reader.makeHab(name="observer")
        rip, upd = issued(publisher)
        ctx = makeContext(host, publishers=[publisher.pre], observers=[observer.pre],
                          fullEvidence=True)
        independent = EvidenceContext(reader)
        try:
            assert not ctx.ingest(publisher.replay(gvrsn=Vrsn_2_0))["rejected"]
            assert not ctx.ingest(observer.replay(gvrsn=Vrsn_2_0))["rejected"]
            client = testing.TestClient(ctx.externalApp)
            headers = {"Content-Type": CESR_CONTENT_TYPE}
            evidence = framed(rip, upd).decode()
            denied = client.simulate_post("/ingest", headers=headers,
                body=signedQuery(observer, "tels/publish", {"stream": evidence}))
            assert denied.status_code == 403
            sent = client.simulate_post("/ingest", headers=headers,
                body=signedQuery(publisher, "tels/publish", {"stream": evidence}))
            assert sent.status_code == 200
            assert sent.json["accepted"][rip.said] == 2
            assert ctx.store.headEvent(rip.said).said == upd.said
            response = client.simulate_post("/", headers=headers,
                body=signedQuery(observer, "tels/bulk", {"i": rip.said}))
            assert response.status_code == 200
            result = independent.ingest(response.content)
            assert not result["pending"] and not result["rejected"]
            assert independent.store.headEvent(rip.said).said == upd.said
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
        rip, upd = issued(publisher)
        baser = RegBaser(name="durable", headDirPath=str(tmp_path), temp=False)
        rgy = Regery(host, baser=baser)
        first = Context(host, hab, rgy)
        pending = first.ingester.ingest(b"", rip.raw + upd.raw)
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
            assert second.store.headEvent(rip.said).said == upd.said
        finally:
            second.close()
