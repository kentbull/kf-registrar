# -*- encoding: utf-8 -*-
"""
kfregistrar.core.serving module

Dual HTTP registrar node: localhost controller API and observer-only bulk TEL API.
"""

from dataclasses import asdict, dataclass
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http
from keri import Vrsn_2_0, help
from keri.acdc import Registrar, Regery
from keri.app.indirecting import createHttpServer
from keri.core import (BlindState, Blinder, BoundState, Codens, Counter,
                       Kevery, Number, NumDex, Parser, SerderACDC, SerderKERI)
from keri.core.kraming import Pruner
from keri.db.basing import BaserDoer
from keri.db.dbing import snKey
from keri.db.koming import Komer
from keri.db.subing import Suber
from keri.kering import (ConfigurationError, KeriError, ValidationError, MissingSignatureError,
    MissingWitnessSignatureError, MissingDelegationError, OutOfOrderError,
    MissingDelegableApprovalError, UnverifiedReceiptError,
    UnverifiedWitnessReceiptError, UnverifiedTransferableReceiptError)

from kfregistrar.app import httping
from kfregistrar.core.ingesting import ControllerIngester, hostedRegistrySaids


logger = help.ogler.getLogger()

CORS_EXPOSE = [
    "cesr-attachment",
    "cesr-date",
    "content-type",
    "signature",
    "signature-input",
    "signify-resource",
    "signify-timestamp",
]

DEFAULT_KRAM_CONFIG = {
    "kram": {
        "enabled": True,
        "denials": [],
        "caches": {
            "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
        },
    }
}


class StaticConfig:
    """Minimal Configer duck-type for KRAM settings."""

    def __init__(self, data):
        self.data = data

    def get(self):
        return self.data


@dataclass
class AccountAccess:
    """Private enrollment decision; public identity evidence stays in the Habery."""
    aid: str
    roles: list[str]


class Context(doing.DoDoer):
    """Own shared evidence processors and the registrar's two HTTP surfaces."""

    def __init__(self, hby, hab, rgy, observers=None, publishers=None,
                 config=None):
        """Bind application policy to a single KEL and ACDC v2 registry verification runtime.

        Parameters:
            hby, hab: caller-owned habitat environment and local controller.
            rgy: local registry manager sharing the evidence backend.
            observers, publishers: AIDs authorized to read or publish evidence.
            config: enabled KRAM policy; disabled authentication fails closed.

        The context owns one pruner and one escrow loop. Call close only after
        cancelling its doers; the caller retains ownership of hby.
        """
        self.hab = hab
        self.rgy = rgy
        self.registrar = Registrar(rgy=rgy)
        self.staticObservers = osetOf(observers)
        self.staticPublishers = osetOf(publishers)
        self.observers = set(self.staticObservers)
        self.publishers = set(self.staticPublishers)
        self.internalApp = None
        self.externalApp = None
        self.hby = hby
        self.cf = StaticConfig(config if config is not None else DEFAULT_KRAM_CONFIG)
        policy = self.cf.get().get("kram", {})
        if policy.get("enabled") is not True or policy.get("denials"):
            raise ConfigurationError("service requests require enabled KRAM without denial exemptions")
        self.kvy = Kevery(db=hby.db, cf=self.cf, enableKram=True,
                          lax=False, local=False)
        self.store = rgy.store
        self.accounts = Komer(db=rgy.baser, subkey="registrar.accounts.", klas=AccountAccess)
        for keys, account in self.accounts.getTopItemIter():
            if (keys != (account.aid,) or account.aid not in hby.kevers
                    or not account.roles or len(set(account.roles)) != len(account.roles)
                    or not set(account.roles) <= {"publisher", "observer"}):
                raise ConfigurationError("registrar enrollment lacks valid roles or accepted account KEL")
            self._applyAccount(account.aid, account.roles)
        self.pendingOpenings = Suber(db=rgy.baser, subkey="registrar.pending-openings.")
        self.parser = Parser(kvy=self.kvy, rgy=rgy, local=False, version=Vrsn_2_0)
        self.pruner = Pruner(self.kvy.kramer, tock=1.0)
        super().__init__(doers=[self.pruner, doing.doify(self.escrowDo)])
        self.ingester = ControllerIngester(context=self)

    def _applyAccount(self, aid, roles):
        """Publish effective permissions without revoking operator-configured access."""
        for role, allowed, configured in (
                ("publisher", self.publishers, self.staticPublishers),
                ("observer", self.observers, self.staticObservers)):
            if role in roles or aid in configured:
                allowed.add(aid)
            else:
                allowed.discard(aid)

    def enroll(self, aid, roles, raw):
        """Verify KEL-only evidence, then commit and publish the private role decision."""
        ims = bytearray(raw)
        if not ims:
            raise ValidationError("public KEL evidence is required")
        while ims:
            before = len(ims)
            try:
                dom = self.parser.parseOneBare(ims=ims, processive=False, local=False)
            except KeriError as ex:
                raise ValidationError("invalid public KEL framing") from ex
            if (dom is None or len(ims) >= before or not isinstance(dom.serder, SerderKERI)
                    or dom.serder.ilk not in ("icp", "dip", "rot", "drt", "ixn", "rct")):
                raise ValidationError("enrollment accepts only public KEL evidence")
        result = self.ingest(raw)
        if result["rejected"] or result["pending"] or aid not in self.hby.kevers:
            raise falcon.HTTPConflict(description="account KEL is refused or incomplete")
        self.accounts.pin(keys=(aid,), val=AccountAccess(aid=aid, roles=list(roles)))
        self._applyAccount(aid, roles)

    def revoke(self, aid):
        """Remove dynamic access before publishing the remaining configured policy."""
        self.accounts.rem(keys=(aid,))
        self._applyAccount(aid, ())

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """Retry local issuance and remote evidence using the scheduler's clock.

        Parameters:
            tymth: injected HIO clock; tock: cooperative retry interval.
            **kwa: unused scheduler metadata.
        Yields:
            float: delay before the next bounded escrow pass.
        """
        self.wind(tymth)
        yield tock
        while True:
            self.kvy.processEscrows()
            self.rgy.processEscrows()
            self._reconcileOpenings()
            yield tock

    def ingest(self, raw, *, publish=False):
        """Process public KEL/TEL evidence using the registrar's concrete owners.

        Only an authorized publisher opts into retaining disclosed openings.
        Acceptance and dependency persistence belong to Kevery and Regery;
        this method reports their final outcomes without another pending queue.
        """
        ims = bytearray(raw)
        summary = dict(accepted={}, pending={}, rejected={}, heads={})
        events, dependencies, disclosures = [], [], []
        while ims:
            serder = None
            try:
                before = len(ims)
                dom = self.parser.parseOneBare(ims=ims, processive=False, local=False)
                if dom is None or dom.serder is None or len(ims) >= before:
                    raise ValidationError("invalid or incomplete evidence frame")
                serder = dom.serder
                if isinstance(serder, SerderACDC):
                    opening = self._disclosedOpening(serder, dom)
                    self.rgy.processEvent(serder, sscs=dom.sscs, ssts=dom.ssts)
                    events.append(serder)
                    if publish and opening is not None:
                        disclosures.append((serder, opening))
                else:
                    if serder.ilk not in ("icp", "dip", "rot", "drt", "ixn", "rct"):
                        raise ValidationError("registrar intake accepts only public KEL and native TEL")
                    self.parser.msgProcess(asdict(dom), kvy=self.kvy, tvy=None,
                                           exc=None, rvy=None, vry=None)
            except (MissingSignatureError, MissingWitnessSignatureError,
                    MissingDelegationError, OutOfOrderError,
                    MissingDelegableApprovalError, UnverifiedReceiptError,
                    UnverifiedWitnessReceiptError,
                    UnverifiedTransferableReceiptError) as ex:
                if serder is not None and not isinstance(serder, SerderACDC) and self._kelPending(serder):
                    dependencies.append(serder)
                    continue
                summary["rejected"]["stream"] = str(ex)
                break
            except Exception as ex:
                summary["rejected"]["stream"] = str(ex)
                break
        self.kvy.processEscrows()
        self.rgy.processEscrows()
        for event in dependencies:
            if self._kelPending(event):
                key = f"kel:{event.pre}"
                summary["pending"][key] = summary["pending"].get(key, 0) + 1
            elif self.hby.db.kels.getLast(keys=event.pre, on=event.sn) != event.said:
                summary["rejected"][f"kel:{event.pre}:{event.snh}"] = "dependency was not accepted or retained"
        for event in events:
            regk = event.said if event.ilk == "rip" else event.sad["rd"]
            sn = Number(numh=event.sad["n"]).num
            accepted = self.store.seqSaider(regk, sn)
            if accepted is not None and accepted.qb64 == event.said:
                bucket = "accepted"
                summary["heads"][regk] = self.store.head(regk).qb64
            else:
                pending = self._telPending(event)
                bucket = "pending" if pending else "rejected"
            summary[bucket][regk] = summary[bucket].get(regk, 0) + 1
        for event, opening in disclosures:
            accepted = self.store.seqSaider(event.sad["rd"], Number(numh=event.sad["n"]).num)
            if accepted is not None and accepted.qb64 == event.said:
                self.store.putOpening(event.said, opening)
            elif self._telPending(event):
                existing = self.pendingOpenings.get(event.said)
                if existing is not None and existing != opening.qb64:
                    raise ValidationError("pending public opening is immutable")
                self.pendingOpenings.put(event.said, opening.qb64)
        self._reconcileOpenings()
        return summary

    def _disclosedOpening(self, event, dom):
        """Validate an explicitly supplied opening before native TEL processing."""
        from keri.acdc.regeventing import vetBlind
        supplied = [(BlindState, values) for values in dom.bsqs]
        supplied.extend((BoundState, values) for values in dom.bsss)
        if not supplied:
            return None
        if event.ilk != "bup" or len(supplied) != 1:
            raise ValidationError("only a BUP may carry one disclosed opening")
        clan, values = supplied[0]
        opening = Blinder(data=clan(*values))
        vetBlind(opening, blid=event.sad["b"])
        return opening

    def _telPending(self, event):
        """Match the exact BUP/RIP in the core's ordinary dependency escrow."""
        regk = event.said if event.ilk == "rip" else event.sad["rd"]
        sn = Number(numh=event.sad["n"]).num
        return any((event.said,) in escrow.get(keys=regk, on=sn)
                   for escrow in (self.rgy.baser.maes, self.rgy.baser.ooes))

    def _reconcileOpenings(self):
        """Promote authorized disclosures only after accepted TEL membership.

        Keep exact core dependencies across restart, without a second body
        queue or retry service. Removed/rejected dependencies lose their proof.
        """
        from keri.acdc.regeventing import vetBlind
        for (said,), raw in list(self.pendingOpenings.getTopItemIter()):
            event = self.store.event(said)
            try:
                if event is None or event.ilk != "bup":
                    raise ValidationError("pending public opening has no BUP")
                vetBlind(raw, blid=event.sad["b"])
                accepted = self.store.seqSaider(event.sad["rd"], Number(numh=event.sad["n"]).num)
                if accepted is not None and accepted.qb64 == said:
                    for clan in (BlindState, BoundState):
                        try:
                            opening = Blinder(clan=clan, qb64=raw)
                        except (KeriError, ValueError, TypeError):
                            continue
                        if opening.qb64 == raw:
                            self.store.putOpening(said, opening)
                            break
                    else:
                        raise ValidationError("invalid pending public opening")
                elif self._telPending(event):
                    continue
            except (KeriError, ValueError, TypeError):
                logger.warning("Discarding invalid pending public opening %s", said)
            self.pendingOpenings.rem(said)

    def _kelPending(self, event):
        """Report only exact dependencies retained by the ordinary KEL escrows."""
        db = self.hby.db
        if event.ilk != "rct":
            if any(event.said in escrow.get(keys=event.pre, on=event.sn)
                   for escrow in (db.pses, db.pwes, db.pdes, db.ooes)):
                return True
            return event.said in db.delegables.get(keys=snKey(event.pre, event.sn))
        if any(said == event.said for said, _ in db.uwes.get(keys=event.pre, on=event.sn)):
            return True
        receipts = db.ures.get(keys=(event.pre, Number(num=event.sn, code=NumDex.Huge).qb64))
        receipts += db.vres.get(keys=snKey(event.pre, event.sn))
        return any(receipt[0].qb64 == event.said for receipt in receipts)

    def registries(self):
        """List hosted registries with an accepted head."""
        return sorted(hostedRegistrySaids(self.store))

    def clone(self, regks=None, sn=0):
        """Export accepted KEL/TEL and openings explicitly disclosed here.

        Core TEL cloning remains body-only. This service attaches held material
        from authorized publication or its own controller's issuance only.
        """
        kel, tel, issuers = bytearray(), bytearray(), set()
        for regk in self.registries() if regks is None else regks:
            rip = self.store.seqEvent(regk, 0)
            if rip is None:
                raise KeyError(regk)
            issuer = rip.sad["i"]
            if issuer not in issuers:
                kel.extend(b"".join(self.hby.db.cloneDelegation(self.hby.kevers[issuer], gvrsn=Vrsn_2_0)))
                kel.extend(b"".join(self.hby.db.clonePreIter(pre=issuer, gvrsn=Vrsn_2_0)))
                issuers.add(issuer)
            for raw in self.store.cloneTelIter(regk, sn=sn):
                event = SerderACDC(raw=raw)
                opening = self.store.opening(event.said) if event.ilk == "bup" else None
                attachments = Blinder.enclose([opening]) if opening is not None else b""
                tel.extend(event.raw)
                tel.extend(Counter.enclose(qb64=attachments, code=Codens.AttachmentGroup,
                                          version=Vrsn_2_0))
        return bytes(kel + tel)

    def close(self):
        """Close owned registry state after doer cancellation; Habery is borrowed."""
        if self.store.opened:
            self.rgy.close()


def osetOf(values):
    """Return a set of observer AIDs from a sequence or None."""
    if not values:
        return set()
    return set(values)


def _configWithKram(cf):
    """Ensure a KRAM block exists so Kramer.intake actually authenticates."""
    data = {}
    if cf is not None:
        loaded = cf.get()
        if loaded:
            data = dict(loaded)
    if "kram" not in data:
        data = {**DEFAULT_KRAM_CONFIG, **data}
        data["kram"] = dict(DEFAULT_KRAM_CONFIG["kram"])
    return StaticConfig(data)


def _observersFromConfig(cf):
    """Read observer AIDs from the kf-registrar config block."""
    if cf is None:
        return []
    data = cf.get() or {}
    block = data.get("kf-registrar") or data.get("kfregistrar") or {}
    return list(block.get("observers") or data.get("observers") or [])


def _applyCurls(cf, host, port):
    """Override advertised host/port from kf-registrar.curls when present."""
    if cf is None:
        return host, port
    data = cf.get() or {}
    block = data.get("kf-registrar") or {}
    curls = block.get("curls") or []
    if not curls:
        return host, port
    splits = urlsplit(curls[0])
    if splits.hostname:
        host = splits.hostname
    if splits.port:
        port = splits.port
    return host, port


def _corsApp():
    return falcon.App(
        middleware=falcon.CORSMiddleware(
            allow_origins="*",
            allow_credentials="*",
            expose_headers=CORS_EXPOSE,
        )
    )


def loadInternalEnds(app, ctx):
    """Register controller (issuer) routes on the internal Falcon app."""
    app.add_route("/health", httping.HealthEnd())
    app.add_route("/registries", httping.RegistriesCollectionEnd(ctx))
    app.add_route("/registries/{regk}", httping.RegistryResourceEnd(ctx))
    app.add_route("/registries/{regk}/updates", httping.RegistryUpdateEnd(ctx))
    app.add_route("/ingest", httping.IngestEnd(ctx))
    app.add_route("/accounts/{aid}", httping.AccountEnd(ctx))


def loadExternalEnds(app, ctx):
    """Register observer-only routes on the external Falcon app."""
    app.add_route("/health", httping.HealthEnd())
    app.add_route("/", httping.BulkQueryEnd(ctx))
    app.add_route("/query", httping.QueryRejectEnd())
    app.add_route("/ingest", httping.PublishEnd(ctx))


def makeContext(hby, alias="registrar", observers=None, publishers=None,
                **kwa):
    """Build the registrar Context and Falcon apps without binding sockets.

    Parameters:
        hby (Habery): habitat environment that owns the issuer identifier.
        alias (str): habitat name for the registrar/issuer controller.
        observers (list[str] | None): observer AIDs allowed on the external API.
            Combined with any ``observers`` list in Habery config.
        publishers: optional AIDs allowed to publish signed public evidence.

    Returns:
        Context: registrar node with internalApp and externalApp attached.
    """
    hab = hby.habByName(name=alias)
    if hab is None:
        hab = hby.makeHab(name=alias, transferable=True, **kwa)

    rgy = Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)

    obs = osetOf(observers) | osetOf(_observersFromConfig(hby.cf))
    ctx = Context(hby=hby, hab=hab, rgy=rgy, observers=obs,
                  publishers=publishers,
                  config=_configWithKram(hby.cf).get())

    internalApp = _corsApp()
    loadInternalEnds(internalApp, ctx)
    ctx.internalApp = internalApp

    externalApp = _corsApp()
    loadExternalEnds(externalApp, ctx)
    ctx.externalApp = externalApp
    return ctx


def setup(
    hby,
    alias="registrar",
    bootHost="127.0.0.1",
    bootPort=6631,
    host="127.0.0.1",
    port=6632,
    observers=None,
    publishers=None,
    kel=(),
    keypath=None,
    certpath=None,
    cafilepath=None,
    **kwa,
):
    """Initialize dual HTTP servers for one registrar node.

    Internal (bootHost:bootPort) is the controller API. External (host:port)
    is bulk TEL CESR for KRAM-whitelisted observers only.

    Parameters:
        hby (Habery): habitat environment that owns the issuer identifier.
        alias (str): habitat name for the registrar/issuer controller.
        bootHost (str): loopback bind address for the trusted internal controller API.
        bootPort (int): port for the internal controller API.
        host (str): bind address for the observer-facing API.
        port (int): port for the observer-facing API.
        observers (list[str] | None): observer AIDs allowed on the external API.
            Combined with any ``observers`` list in Habery config.
        publishers: optional AIDs authorized for signed external publication.
        kel: iterable of signed KEL bootstrap paths, verified before binding.
        keypath, certpath, cafilepath: optional TLS material for the public server.
            The private administration server uses HTTP on loopback only.

    Returns:
        list: HIO doers including the registrar Context and both HTTP servers.
    """
    if bootHost == "localhost":
        bootHost = "127.0.0.1"
    try:
        loopback = ip_address(bootHost).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise ConfigurationError("registrar account administration requires a loopback boot host")
    ctx = makeContext(hby=hby, alias=alias, observers=observers,
                      publishers=publishers, **kwa)
    try:
        for path in kel:
            result = ctx.ingest(Path(path).read_bytes())
            if result["rejected"] or result["pending"]:
                raise ConfigurationError("registrar bootstrap evidence is incomplete or invalid")
    except BaseException:
        ctx.close()
        raise

    advertisedHost, advertisedPort = _applyCurls(hby.cf, host, port)
    ctx.host = advertisedHost
    ctx.port = advertisedPort

    bootServer = createHttpServer(
        host=bootHost,
        port=bootPort,
        app=ctx.internalApp,
    )
    if not bootServer.reopen():
        raise RuntimeError(f"cannot create internal HTTP server on port {bootPort}")
    bootSrvrDoer = http.ServerDoer(server=bootServer)

    server = createHttpServer(
        host=host,
        port=port,
        app=ctx.externalApp,
        keypath=keypath,
        certpath=certpath,
        cafilepath=cafilepath,
    )
    if not server.reopen():
        raise RuntimeError(f"cannot create external HTTP server on port {port}")
    srvrDoer = http.ServerDoer(server=server)

    regDoer = BaserDoer(baser=ctx.rgy.baser)
    logger.info(
        "Registrar %s : %s internal http/%s:%s external http/%s:%s",
        ctx.hab.name,
        ctx.hab.pre,
        bootHost,
        bootPort,
        host,
        port,
    )
    return [ctx, regDoer, bootSrvrDoer, srvrDoer]
