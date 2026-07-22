from sandbox.coverage.feature_normalizer import normalize_url, value_shape


def test_normalize_url_preserves_keys_and_redacts_values() -> None:
    normalized = normalize_url(
        "HTTPS://Example.Internal/events?tenant=alpha&token=secret#fragment"
    )
    assert normalized == (
        "https://example.internal/events?tenant=%3CVALUE%3E&token=%3CVALUE%3E"
    )


def test_http_tool_url_uses_normalized_url_shape() -> None:
    assert value_shape("url", "http://mock-service.internal/health") == (
        "url(http://mock-service.internal/health)"
    )
