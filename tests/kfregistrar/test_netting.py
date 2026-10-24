"""Resource-limit wiring at the registrar service boundary."""

from types import SimpleNamespace

import falcon
import pytest

from kfregistrar.core import netting


def test_http_server_has_explicit_hio_budgets():
    server = netting.boundedHttpServer("127.0.0.1", 0, falcon.App())
    try:
        assert server.requestHeaderLimit == 64 * 1024
        assert server.requestBodyLimit == 8 * 1024 * 1024
        assert server.requestTimeout == 20.0
        assert server.servant.maxConnections == 128
        assert server.servant.acceptsPerTurn == 16
        assert server.servant.rxbsLimit == 9 * 1024 * 1024
        assert server.servant.rxbsPerTurn == 64 * 1024
    finally:
        server.close()


def test_clone_rejects_aggregate_history_before_building_response():
    regks = [f"registry-{index}" for index in range(5)]
    heads = SimpleNamespace(
        getTopItemIter=lambda: iter((((regk,), object()) for regk in regks)))
    ctx = SimpleNamespace(
        reger=SimpleNamespace(heads=heads),
        store=SimpleNamespace(headEvent=lambda _regk: SimpleNamespace(sn=1023)),
    )
    with pytest.raises(falcon.HTTPContentTooLarge) as error:
        netting.boundedClone(ctx)
    assert "aggregate event limit" in error.value.description
