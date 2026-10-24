# -*- encoding: utf-8 -*-
"""
Controller ingest of pre-built, KEL-anchored TEL events for hosting.
"""

from collections import defaultdict

from keri import Vrsn_2_0, help
from keri.acdc.regeventing import requireSupportedEvent
from keri.core import Parser, SerderACDC, Counter, Codens
from keri.kering import ValidationError


logger = help.ogler.getLogger()


def parseTelStream(stream):
    """Parse concatenated CESR TEL event bodies into SerderACDC instances.

    Parameters:
        stream (bytes | bytearray): concatenated ``rip`` / ``bup`` bodies.

    Returns:
        list[SerderACDC]: parsed events in stream order.
    """
    ims = bytearray(stream or b"")
    events = []
    while ims:
        serder = SerderACDC(raw=ims)
        events.append(serder)
        del ims[: serder.size]
    return events


def groupTelEvents(events):
    """Group parsed TEL events by registry SAID.

    Parameters:
        events (Iterable[SerderACDC]): parsed TEL events in any order.

    Returns:
        dict[str, tuple[SerderACDC | None, list[SerderACDC]]]:
            registry SAID -> (rip or None, list of bup events).
    """
    groups = defaultdict(lambda: [None, []])
    for serder in events:
        requireSupportedEvent(serder)
        if serder.ilk == "rip":
            regk = serder.said
            groups[regk][0] = serder
        elif serder.ilk == "bup":
            regk = serder.sad["rd"]
            groups[regk][1].append(serder)
        else:
            raise ValidationError(
                f"unsupported TEL event ilk {serder.ilk} in controller ingest"
            )
    return {regk: (rip, updates) for regk, (rip, updates) in groups.items()}


def _asBytes(value):
    """Coerce CESR text or bytes to bytes."""
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value.encode("utf-8")


def ingestKel(kvy, kel):
    """Parse a CESR KEL stream into the registrar Kevery / Habery Baser.

    Parameters:
        kvy (Kevery): registrar key-event processor bound to hby.db.
        kel (bytes | bytearray | str): signed KEL clone for the TEL issuer.

    Returns:
        None
    """
    ims = bytearray(_asBytes(kel))
    if not ims:
        return
    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
    kvy.processEscrows()


def hostedRegistrySaids(store):
    """Return registry SAIDs that have an accepted head in the store.

    Parameters:
        store (RegistryStore): registrar TEL store.

    Returns:
        list[str]: registry SAIDs with verified heads.
    """
    saids = []
    for (regk,), _saider in store.baser.heads.getTopItemIter():
        saids.append(regk if isinstance(regk, str) else regk.decode("utf-8"))
    return saids


def knownRegistry(store, rgy, regk):
    """True when regk is locally managed or has a hosted accepted head."""
    return regk in rgy.regs or store.head(regk) is not None


def allRegistrySaids(store, rgy):
    """Union of locally managed and hosted registry SAIDs."""
    return sorted(set(rgy.regs.keys()) | set(hostedRegistrySaids(store)))


class ControllerIngester:
    """Adapt the original admin JSON contract to shared durable verification.

    Bare TEL bodies are framed without changing their signed/self-addressed
    contents. Rever alone writes accepted ordinals and durable pending evidence.
    There is no application-owned pending batch or second acceptance path.
    """

    def __init__(self, context):
        """Retain the caller-owned EvidenceContext used by both HTTP surfaces."""
        self.context = context

    def ingest(self, kel, tel):
        """Verify admin KEL text and bare rip/bup bodies through the core.

        Parameters:
            kel: bytes or text containing signed supporting KEL evidence.
            tel: bytes or text containing concatenated ACDC v2 registry TEL bodies.
        Returns:
            dict: accepted, pending, rejected and accepted-head maps. A parse
                failure is reported before any of this batch is processed.
        """
        try:
            events = parseTelStream(_asBytes(tel))
            if not events:
                raise ValidationError("empty TEL stream")
            groupTelEvents(events)  # Reject credential bodies at this admin boundary.
            raw = bytearray(_asBytes(kel))
            for event in events:
                raw.extend(event.raw)
                raw.extend(Counter(Codens.AttachmentGroup, count=0,
                                   version=Vrsn_2_0).qb64b)
        except Exception as ex:
            return dict(accepted={}, pending={}, rejected={"*": str(ex)}, heads={})
        return self.context.ingest(bytes(raw))

    def retryPending(self):
        """Retry persisted dependencies without retaining a second pending queue.

        Returns:
            None. Callers inspect the shared store for resulting accepted heads.
        """
        self.context.kvy.processEscrows()
        self.context.rever.processEscrows()
