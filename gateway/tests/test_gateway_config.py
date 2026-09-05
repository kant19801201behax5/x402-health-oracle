"""Tests for x402_gateway.py — source validation, no runtime deps needed."""
import os
import pytest

GATEWAY_PATH = os.path.join(os.path.dirname(__file__), "..", "x402_gateway.py")


@pytest.fixture
def source():
    with open(GATEWAY_PATH) as f:
        return f.read()


def test_hedera_asset_is_native_hbar(source):
    """Asset must be 0.0.0 (native HBAR), not 0.0.456858 (mainnet USDC)."""
    assert '"0.0.0"' in source, "Hedera asset must be 0.0.0 (native HBAR)"
    assert "0.0.456858" not in source, "0.0.456858 (mainnet USDC) must not be in testnet config"


def test_hbar_decimals_is_8(source):
    """HBAR has 8 decimal places (1 HBAR = 10^8 tinybar)."""
    assert '"decimals": 8' in source, "HBAR decimals must be 8"


def test_fee_payer_present(source):
    """Hedera PaymentOption must include feePayer for Blocky402."""
    assert "feePayer" in source, "feePayer must be in PaymentOption extra"
    assert "0.0.7162784" in source, "Blocky402 feePayer account must be 0.0.7162784"


def test_dual_network_config(source):
    """Gateway must support both Base mainnet and Hedera testnet."""
    assert "eip155:8453" in source, "Base mainnet must be configured"
    assert "hedera:testnet" in source, "Hedera testnet must be configured"


def test_price_format(source):
    """Price must be $0.01."""
    assert '$0.01' in source, "Price must be $0.01"


def test_no_hardcoded_secrets(source):
    """No plaintext API keys or private keys in source."""
    lower = source.lower()
    assert "sk_live" not in lower, "No live secret keys"
    assert "private_key" not in lower or "env" in lower.split("private_key")[0][-50:], \
        "Private keys must come from env vars"


def test_feed_path(source):
    """Feed path must reference feed.jsonl."""
    assert "feed.jsonl" in source


def test_exact_evm_scheme_registered(source):
    """ExactEvmServerScheme must be registered for both networks."""
    assert "ExactEvmServerScheme" in source
    count = source.count("ExactEvmServerScheme()")
    assert count >= 2, f"ExactEvmServerScheme must be registered for both networks, found {count} instance(s)"
