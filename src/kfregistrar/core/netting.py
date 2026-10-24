"""Explicit transport and query-work budgets for the registrar service."""

import falcon

from keri import Vrsn_2_0
from keri.app.indirecting import createHttpServer


HTTP_HEADER_LIMIT = 64 * 1024
HTTP_BODY_LIMIT = 8 * 1024 * 1024
HTTP_RX_BUFFER_LIMIT = 9 * 1024 * 1024
HTTP_REQUEST_TIMEOUT = 20.0
HTTP_IDLE_TIMEOUT = 30.0
MAX_CONNECTIONS = 128
ACCEPTS_PER_TURN = 16
RX_BYTES_PER_TURN = 64 * 1024
MAX_QUERY_REGISTRIES = 64
MAX_REGISTRY_EVENTS = 1024
MAX_QUERY_EVENTS = 4096
MAX_RESPONSE_BODY = 8 * 1024 * 1024
MAX_EVENT_ATTACHMENT_ALLOWANCE = 2048


def boundedHttpServer(host, port, app, *, keypath=None, certpath=None,
                      cafilepath=None):
    """Create KERIpy's HTTP/TLS server with finite HIO ingress budgets."""
    server = createHttpServer(host=host, port=port, app=app, keypath=keypath,
                              certpath=certpath, cafilepath=cafilepath)
    server.requestHeaderLimit = HTTP_HEADER_LIMIT
    server.requestBodyLimit = HTTP_BODY_LIMIT
    server.requestTimeout = HTTP_REQUEST_TIMEOUT
    server.servant.tymeout = HTTP_IDLE_TIMEOUT
    server.servant.maxConnections = MAX_CONNECTIONS
    server.servant.acceptsPerTurn = ACCEPTS_PER_TURN
    server.servant.rxbsLimit = HTTP_RX_BUFFER_LIMIT
    server.servant.rxbsPerTurn = RX_BYTES_PER_TURN
    return server


def boundedClone(ctx, regks=None, sn=0):
    """Clone only a finite registry scope while retaining whole-history checks."""
    if regks is None:
        regks = []
        for keys, _ in ctx.reger.heads.getTopItemIter():
            regks.append(keys[0])
            if len(regks) > MAX_QUERY_REGISTRIES:
                raise falcon.HTTPContentTooLarge(
                    description="registry query exceeds the scope limit")
    else:
        regks = list(dict.fromkeys(regks))
        if len(regks) > MAX_QUERY_REGISTRIES:
            raise falcon.HTTPContentTooLarge(
                description="registry query exceeds the scope limit")

    for regk in regks:
        head = ctx.store.headEvent(regk)
        if head is not None and head.sn >= MAX_REGISTRY_EVENTS:
            raise falcon.HTTPContentTooLarge(
                description="registry history exceeds the event limit")

    totalEvents = sum((ctx.store.headEvent(regk).sn + 1)
                      for regk in regks if ctx.store.headEvent(regk) is not None)
    if totalEvents > MAX_QUERY_EVENTS:
        raise falcon.HTTPContentTooLarge(
            description="registry query exceeds the aggregate event limit")

    projected = 0
    issuers = set()
    for regk in regks:
        rip = ctx.store.seqEvent(regk, 0)
        if rip is None:
            continue
        issuer = rip.sad['i']
        if issuer not in issuers:
            kever = ctx.hby.kevers[issuer]
            for message in ctx.hby.db.cloneDelegation(kever, gvrsn=Vrsn_2_0):
                projected += len(message)
                if projected > MAX_RESPONSE_BODY:
                    raise falcon.HTTPContentTooLarge(
                        description="registry response exceeds the size limit")
            for message in ctx.hby.db.clonePreIter(pre=issuer, gvrsn=Vrsn_2_0):
                projected += len(message)
                if projected > MAX_RESPONSE_BODY:
                    raise falcon.HTTPContentTooLarge(
                        description="registry response exceeds the size limit")
            issuers.add(issuer)
        for index, raw in enumerate(ctx.store.cloneTelIter(regk)):
            if index >= sn:
                projected += len(raw) + MAX_EVENT_ATTACHMENT_ALLOWANCE
                if projected > MAX_RESPONSE_BODY:
                    raise falcon.HTTPContentTooLarge(
                        description="registry response exceeds the size limit")

    raw = ctx.clone(regks, sn=sn)
    if len(raw) > MAX_RESPONSE_BODY:
        raise falcon.HTTPContentTooLarge(
            description="registry response exceeds the size limit")
    return raw
