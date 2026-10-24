"""Identity resolution, the worker email index, and the policy fingerprint.

Works on tmp_path copies of examples/demo (conftest); no API calls.
"""

import json
import logging

import pytest

from rbic.admin import PolicyAdmin
from rbic.gate import SQLGate, check_worker_emails, policy_fingerprint
from rbic.identity import (AttributeProvider, Identity, JsonAttributeProvider,
                           LocalProvider)

logging.disable(logging.CRITICAL)


def gate_for(cfg) -> SQLGate:
    return SQLGate.from_config(cfg)


def write_attrs(cfg, attrs: dict) -> None:
    cfg.attributes_path.write_text(json.dumps(attrs, indent=2) + "\n",
                                   encoding="utf-8")


def read_attrs(cfg) -> dict:
    return json.loads(cfg.attributes_path.read_text(encoding="utf-8"))


# ---- JsonAttributeProvider ----------------------------------------------------

@pytest.mark.parametrize("email", [
    "carol@example.test", "Carol@Example.TEST", "  carol@example.test\t",
    "CAROL@EXAMPLE.TEST\n",
])
def test_email_match_is_casefolded_and_stripped(demo_config, email):
    attrs = gate_for(demo_config).attributes
    assert JsonAttributeProvider().resolve(
        Identity("openwebui", "sub-1", email), attrs) == "carol"


@pytest.mark.parametrize("email", [
    None, "", "   ", "nobody@example.test", "carol@example.tes",
    "carol", 42, "carol@example.test, bob@example.test",
])
def test_email_no_match(demo_config, email):
    attrs = gate_for(demo_config).attributes
    assert JsonAttributeProvider().resolve(
        Identity("openwebui", "carol", email), attrs) is None


def test_json_provider_ignores_subject(demo_config):
    # The subject is the host's own id; only the email maps to a worker.
    attrs = gate_for(demo_config).attributes
    assert JsonAttributeProvider().resolve(Identity("x", "carol"), attrs) is None


def test_json_provider_ambiguous_match_resolves_to_no_one():
    attrs = {"a": {"role": "r", "email": "x@example.test"},
             "b": {"role": "r", "email": "X@example.test"}}
    assert JsonAttributeProvider().resolve(
        Identity("p", "s", "x@example.test"), attrs) is None


def test_local_provider():
    attrs = {"alice": {"role": "warehouse_worker"}}
    local = LocalProvider()
    assert local.resolve(Identity("local", "alice"), attrs) == "alice"
    assert local.resolve(Identity("local", "bob"), attrs) is None
    assert local.resolve(Identity("local", ""), attrs) is None
    assert isinstance(local, AttributeProvider)
    assert isinstance(JsonAttributeProvider(), AttributeProvider)


def test_identity_is_frozen():
    ident = Identity("p", "s", "a@example.test")
    with pytest.raises(AttributeError):
        ident.subject = "other"


# ---- email validation in the gate's loader -----------------------------------

def test_demo_emails_load(demo_config):
    gate = gate_for(demo_config)
    assert gate.broken is None
    assert gate.attributes["alice"]["email"] == "alice@example.test"
    assert "email" not in gate.attributes["master"]  # email is optional


def test_duplicate_email_breaks_snapshot_and_denies_everyone(demo_config):
    gate = gate_for(demo_config)
    attrs = read_attrs(demo_config)
    attrs["dave"]["email"] = "ALICE@example.test"  # casefold duplicate
    write_attrs(demo_config, attrs)
    gate.refresh()
    assert "share the same email" in gate.broken
    from rbic.gate import AccessDenied
    for user, sql in (("alice", "SELECT sku FROM inventory"),
                      ("dave", "SELECT vendor FROM invoices")):
        with pytest.raises(AccessDenied, match="policy reload failed"):
            gate.authorize(user, sql)


@pytest.mark.parametrize("bad", [
    "not-an-email", "a@b", "a b@example.test", "ålice@example.test",
    "alice@exa_mple.test", "alice@@example.test", "alice@example.test\n",
    "", 5, None, ["alice@example.test"], "a" * 65 + "@example.test",
])
def test_invalid_email_breaks_snapshot(demo_config, bad):
    gate = gate_for(demo_config)
    attrs = read_attrs(demo_config)
    attrs["bob"]["email"] = bad
    write_attrs(demo_config, attrs)
    gate.refresh()
    assert gate.broken and "invalid email" in gate.broken


def test_invalid_email_at_startup_refuses_to_build(demo_config):
    attrs = read_attrs(demo_config)
    attrs["bob"]["email"] = attrs["carol"]["email"]
    write_attrs(demo_config, attrs)
    with pytest.raises(ValueError, match="share the same email"):
        gate_for(demo_config)


def test_check_worker_emails_accepts_plus_and_subdomains():
    check_worker_emails({"a": {"email": "first.last+tag@mail.example.co.uk"},
                         "b": {"role": "x"}})


# ---- PolicyAdmin: email is identity-critical -----------------------------------

@pytest.fixture
def admin(demo_config):
    return PolicyAdmin.from_config(demo_config)


def test_set_attribute_refuses_email(admin):
    with pytest.raises(ValueError, match="identity-critical"):
        admin.propose_set_attribute("bob", "email", "alice2@example.test")
    with pytest.raises(ValueError, match="identity-critical"):
        admin.propose_set_attribute("dave", "email", "dave@example.test")


def test_other_admin_paths_keep_email(admin, demo_config):
    admin.apply(admin.propose_assign_role("dave", "hr_staff"), "master")
    admin.apply(admin.propose_set_attribute("dave", "dept", "engineering"),
                "master")
    assert read_attrs(demo_config)["dave"]["email"] == "dave@example.test"
    admin.apply(admin.propose_undo(), "master")
    admin.apply(admin.propose_undo(), "master")
    assert read_attrs(demo_config)["dave"]["email"] == "dave@example.test"


def test_undo_cannot_change_an_email(admin, demo_config):
    # A changelog entry from before emails were protected (or a crafted
    # one): undoing it would change an email, so the undo is refused.
    attrs = read_attrs(demo_config)
    before = json.dumps(attrs, indent=2) + "\n"
    changed = dict(attrs, bob=dict(attrs["bob"], email="carol2@example.test"))
    after = json.dumps(changed, indent=2) + "\n"
    demo_config.attributes_path.write_text(after, encoding="utf-8", newline="")
    import hashlib
    entry = {"id": "old1", "kind": "set_attribute", "actor": "master",
             "description": "old email change", "file": str(demo_config.attributes_path),
             "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
             "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
             "before_text": before, "after_text": after, "status": "applied"}
    with open(admin.changelog_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    with pytest.raises(ValueError, match="identity-critical"):
        admin.propose_undo()


# ---- policy fingerprint ---------------------------------------------------------

def test_fingerprint_is_sha256_of_built_bytes(demo_config):
    gate = gate_for(demo_config)
    expected = policy_fingerprint(demo_config.model_path.read_bytes(),
                                  demo_config.policy_path.read_bytes(),
                                  demo_config.attributes_path.read_bytes())
    assert gate.fingerprint == gate.snapshot.fingerprint == expected
    assert len(expected) == 64
    # stable across instances (restarts / other processes)
    assert gate_for(demo_config).fingerprint == expected


def test_fingerprint_changes_with_any_input(demo_config):
    gate = gate_for(demo_config)
    seen = {gate.fingerprint}
    attrs = read_attrs(demo_config)
    attrs["bob"]["dept"] = "logistics"
    write_attrs(demo_config, attrs)
    gate.refresh()
    seen.add(gate.fingerprint)
    with open(demo_config.policy_path, "a", encoding="utf-8") as f:
        f.write("\n# a comment\n")
    gate.refresh()
    seen.add(gate.fingerprint)
    with open(demo_config.model_path, "a", encoding="utf-8") as f:
        f.write("\n")
    gate.refresh()
    seen.add(gate.fingerprint)
    assert len(seen) == 4 and gate.broken is None


def test_fingerprint_parts_are_unambiguous():
    assert policy_fingerprint(b"ab", b"c", b"") != policy_fingerprint(b"a", b"bc", b"")
