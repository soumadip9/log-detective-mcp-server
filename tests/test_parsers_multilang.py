"""Tests verifying that Log Detective is technology and language agnostic."""

import json
from log_detective.parsers import parse_log_text
from log_detective.tools import find_errors


def test_python_fastapi_and_traceback():
    sample = """2026-10-20 01:00:00,100 [INFO] (uvicorn.access) 127.0.0.1 - "GET /checkout HTTP/1.1" 200
2026-10-20 01:00:05,250 [ERROR] (app.routers.checkout) Order placement failed for user 1234-5678
Traceback (most recent call last):
  File "/app/routers/checkout.py", line 45, in place_order
    payment = await stripe_client.charge(cart.total)
  File "/app/services/stripe.py", line 82, in charge
    raise ConnectionError("Stripe gateway unreachable")
ConnectionError: Stripe gateway unreachable
2026-10-20 01:00:05,260 [INFO] (app.routers.checkout) Releasing inventory locks
"""
    entries = parse_log_text(sample)
    errors = [e for e in entries if e.severity == "ERROR"]
    assert len(errors) == 1
    err = errors[0]
    assert err.line_number == 2
    assert "app.routers.checkout" in (err.component or "")
    assert len(err.stack_trace) >= 5
    assert "ConnectionError: Stripe gateway unreachable" in err.stack_trace[-1]


def test_nodejs_pino_json_and_winston():
    # Pino structured logs often use numeric level: 50 (error), 40 (warn), 30 (info)
    pino_error = json.dumps({
        "level": 50,
        "time": 1729440000000,
        "pid": 9812,
        "hostname": "checkout-pod-1",
        "name": "payment-service",
        "reqId": "req_ab12cd",
        "msg": "Payment authorization rejected: Insufficient funds",
        "stack": "Error: Insufficient funds\n    at PaymentGateway.charge (/app/dist/gateway.js:42:15)\n    at processTicksAndRejections (node:internal/process/task_queues:95:5)"
    })
    entries = parse_log_text(pino_error)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.severity == "ERROR"
    assert entry.component == "payment-service"
    assert entry.request_id == "req_ab12cd"
    assert len(entry.stack_trace) == 3


def test_java_spring_boot_log4j():
    sample = """2026-10-20 01:15:20.123 [http-nio-8080-exec-1] INFO  com.store.checkout.CheckoutService - Processing order ORD-9912
2026-10-20 01:15:21.450 [http-nio-8080-exec-1] ERROR com.store.payment.StripeClient - Failed to authorize payment
org.springframework.web.client.ResourceAccessException: I/O error on POST request for "https://api.stripe.com/v1/charges": Read timed out
\tat org.springframework.web.client.RestTemplate.doExecute(RestTemplate.java:785)
\tat com.store.payment.StripeClient.executeRequest(StripeClient.java:142)
Caused by: java.net.SocketTimeoutException: Read timed out
\tat java.base/sun.nio.ch.NioSocketImpl.timedRead(NioSocketImpl.java:288)
\t... 32 more
2026-10-20 01:15:22.000 [http-nio-8080-exec-1] WARN  com.store.checkout.CheckoutService - Order rollback initiated
"""
    result = find_errors(sample, severity="ERROR")
    assert result["matching_count"] == 1
    err = result["errors"][0]
    assert err["line"] == 2
    assert "com.store.payment.StripeClient" in (err.get("component") or err.get("message"))
    assert "stack_trace" in err
    assert len(err["stack_trace"]) >= 5


def test_go_panic_and_goroutine():
    sample = """2026-10-20T01:00:00Z [INFO] HTTP server listening on :8080
2026-10-20T01:00:05Z [CRITICAL] panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x6a12b4]
goroutine 42 [running]:
main.processCheckout(0x0, 0x0)
\t/src/checkout/service.go:88 +0x34
main.handleRequest(0xc0000b4000)
\t/src/checkout/handler.go:45 +0x120
"""
    result = find_errors(sample, severity="CRITICAL")
    assert result["matching_count"] == 1
    err = result["errors"][0]
    assert err["severity"] == "CRITICAL"
    assert "stack_trace" in err
    assert len(err["stack_trace"]) >= 4
