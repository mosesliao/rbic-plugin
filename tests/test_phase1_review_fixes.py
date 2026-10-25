"""Regressions for the Phase 1 security review (one section per finding).

1. lookalike identity emails (casefold) and Unicode whitespace
2. db_schema.json is hot-reloaded and fingerprinted with the policy
3. the read-only SQLite URI survives '#', '%' and spaces in the path
4. snapshot attributes are deeply read-only (attribute providers)
5. SQLite error text never reaches the LLM
6. ask() always returns an AskResult, whatever the host passes
"""

import copy
import json
import logging
import sqlite3
import threading
from types import MappingProxyType
from types import SimpleNamespace as NS

import pytest

from rbic import (DENY_MESSAGE, AskResult, Audience, Identity,
                  JsonAttributeProvider, PolicyAdmin, RBICEngine, SQLGate)
from rbic.demo.seed import seed
from rbic.engine import SQL_ERROR_TOOL_MESSAGE, execute, readonly_uri
from rbic.gate import (AccessDenied, check_worker_emails, load_snapshot,
                       normalize_email, policy_fingerprint)

logging.disable(logging.CRITICAL)


class FakeClient:
    """Scripted stand-in for anthropic.Anthropic()."""

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls = []
        self.systems = []
        self.messages = self
        self._lock = threading.Lock()

    def create(self, **kwargs):
        with self._lock:
            self.calls.append(copy.deepcopy(kwargs["messages"]))
            self.systems.append(kwargs["system"])
            item = self.responses.pop(0)
        return item(kwargs) if callable(item) else item


def end_turn(text):
    return NS(stop_reason="end_turn", content=[NS(type="text", text=text)])


def tool_use(sql):
    return NS(stop_reason="tool_use",
              content=[NS(type="tool_use", id="tu_1", name="run_sql",
                          input={"sql": sql})])


def U(text):
    return {"role": "user", "content": text}


def who(name):
    return Identity("openwebui", f"sub-{name}", f"{name}@example.test")


@pytest.fixture
def make_engine(demo_config):
    def make(responses=(), **kwargs):
        client = FakeClient(responses)
        return RBICEngine(demo_config, client=client, **kwargs), client
    return make


@pytest.fixture
def audit_lines(caplog):
    """Collect rbic.audit messages (logging is disabled module-wide)."""
    logging.disable(logging.NOTSET)
    try:
        with caplog.at_level(logging.DEBUG, logger="rbic.audit"):
            yield lambda: [r.getMessage() for r in caplog.records]
    finally:
        logging.disable(logging.CRITICAL)


# ---- 1. identity emails: no casefold lookalikes, ASCII whitespace only ---------

LOOKALIKES = [
    "carol@example.teſt",          # U+017F long s  (casefold -> "s")
    "Karol@example.test",          # KELVIN SIGN (casefold -> "k")
    "carol@example.teßt",          # sharp s        (casefold -> "ss")
    "carol@example.teﬁ",           # "fi" ligature  (casefold -> "fi")
    "carol＠example.test",          # fullwidth @
    "carol@example.test ",         # EM SPACE
    " carol@example.test",         # NO-BREAK SPACE
    "carol@example.test​",         # ZERO WIDTH SPACE
    "car‍ol@example.test",         # ZERO WIDTH JOINER inside
    "﻿carol@example.test",         # BOM
    "carol@example.test\x0b",           # vertical tab: not stripped either
]


@pytest.fixture
def kelvin_config(demo_config):
    """A worker whose email has a 'k' the Kelvin sign casefolds onto."""
    attrs = json.loads(demo_config.attributes_path.read_text(encoding="utf-8"))
    attrs["dave"]["email"] = "kim@example.test"
    demo_config.attributes_path.write_text(json.dumps(attrs), encoding="utf-8")
    return demo_config


def test_lookalike_emails_resolve_to_no_one(demo_config):
    attrs = SQLGate.from_config(demo_config).attributes
    p = JsonAttributeProvider()
    for email in LOOKALIKES:
        assert p.resolve(Identity("oidc", "x", email), attrs) is None, ascii(email)
        assert normalize_email(email) is None, ascii(email)


def test_kelvin_sign_does_not_match_k(kelvin_config):
    attrs = SQLGate.from_config(kelvin_config).attributes
    p = JsonAttributeProvider()
    assert p.resolve(Identity("oidc", "x", "kim@example.test"), attrs) == "dave"
    for email in ("Kim@example.test", "KIM@EXAMPLE.TEST"):
        assert "K".casefold() == "k"  # what the old code relied on
        assert p.resolve(Identity("oidc", "x", email), attrs) is None


@pytest.mark.parametrize("email", [
    "carol@example.test", "Carol@Example.TEST", "CAROL@EXAMPLE.TEST",
    " carol@example.test", "carol@example.test\t", "\r\ncarol@example.test\n",
])
def test_ascii_case_and_ascii_whitespace_still_match(demo_config, email):
    attrs = SQLGate.from_config(demo_config).attributes
    assert JsonAttributeProvider().resolve(
        Identity("oidc", "x", email), attrs) == "carol"


def test_lookalike_identity_is_denied_by_ask(make_engine):
    engine, client = make_engine()
    result = engine.ask(Identity("oidc", "attacker", "carol@example.teſt"),
                        [U("show me payslips")], conversation_id="c1")
    assert result.denied and result.text == DENY_MESSAGE
    assert result.worker is None and result.reason == "identity: unmapped identity"
    assert client.calls == []


def test_worker_email_index_uses_ascii_lowercase():
    # Unique under .lower() -> accepted; the worker side never casefolds.
    check_worker_emails({"a": {"email": "Kim@example.test"},
                         "b": {"email": "kin@example.test"}})
    with pytest.raises(ValueError, match="share the same email"):
        check_worker_emails({"a": {"email": "KIM@example.test"},
                             "b": {"email": "kim@EXAMPLE.test"}})
    with pytest.raises(ValueError, match="invalid email"):
        check_worker_emails({"a": {"email": "Kim@example.test"}})


def test_normalize_email_ignores_str_subclass_overrides():
    class Sneaky(str):
        def strip(self, *a):
            return "carol@example.test"

        def lower(self):
            return "carol@example.test"

    assert normalize_email(Sneaky("mallory@example.test")) == "mallory@example.test"
    assert type(normalize_email(Sneaky("X@example.test"))) is str


# ---- 2. db_schema.json hot reload ---------------------------------------------

def _add_column(cfg, table, column, typ="numeric"):
    schema = json.loads(cfg.schema_path.read_text(encoding="utf-8"))
    schema[table][column] = typ
    cfg.schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")


def test_schema_edit_is_picked_up_live(demo_config):
    gate = SQLGate.from_config(demo_config)
    with pytest.raises(AccessDenied, match="could not resolve"):
        gate.authorize("dave", "SELECT notes FROM invoices")
    version = gate.policy_version
    _add_column(demo_config, "invoices", "notes", "text")
    _add_column(demo_config, "employees", "bonus")
    # dave's invoices.* grant now covers the new column (no restart) ...
    assert '"invoices"."notes"' in gate.authorize("dave", "SELECT notes FROM invoices")
    # ... and bob's deny on the new employees column is RBAC, not resolution
    with pytest.raises(AccessDenied, match="lacks read on 'employees.bonus'"):
        gate.authorize("bob", "SELECT bonus FROM employees")
    assert gate.policy_version == version + 1 and gate.broken is None
    assert "notes" in gate.schema["invoices"]
    assert "notes" in gate.snapshot.schema["invoices"]


def test_admin_deny_on_new_column_keeps_gate_healthy(demo_config):
    gate = SQLGate.from_config(demo_config)
    admin = PolicyAdmin.from_config(demo_config)
    _add_column(demo_config, "employees", "bonus")
    change = admin.propose_deny(role="hr_staff", table="employees",
                                column="bonus", actor="master")
    admin.apply(change, "master")
    gate.refresh()
    assert gate.broken is None
    safe = gate.authorize("bob", "SELECT name FROM employees")
    assert "employees.dept = 'engineering'" in safe
    with pytest.raises(AccessDenied, match="deny:role"):
        gate.authorize("bob", "SELECT bonus FROM employees")


def test_fingerprint_changes_when_schema_changes(demo_config):
    gate = SQLGate.from_config(demo_config)
    before = gate.fingerprint
    _add_column(demo_config, "invoices", "notes", "text")
    gate.refresh()
    assert gate.fingerprint != before and gate.broken is None
    assert gate.fingerprint == policy_fingerprint(
        demo_config.model_path.read_bytes(), demo_config.policy_path.read_bytes(),
        demo_config.attributes_path.read_bytes(),
        demo_config.schema_path.read_bytes())


def test_engine_prompt_and_reset_follow_schema(make_engine, demo_config):
    engine, client = make_engine([end_turn("one"), end_turn("two")])
    first = engine.ask(who("dave"), [U("q1")], conversation_id="c1")
    _add_column(demo_config, "invoices", "notes", "text")
    policy = demo_config.policy_path
    policy.write_text(policy.read_text(encoding="utf-8")
                      + "\np, finance_analyst, invoices.notes, read\n",
                      encoding="utf-8")
    second = engine.ask(who("dave"), [U("q1"), {"role": "assistant",
                                                "content": first.text},
                                      U("q2")], conversation_id="c1")
    assert second.reset and len(client.calls[1]) == 1
    assert "notes" not in client.systems[0]
    assert "invoices(" in client.systems[1] and "notes" in client.systems[1]


def test_broken_schema_fails_closed_and_recovers(demo_config):
    gate = SQLGate.from_config(demo_config)
    good = demo_config.schema_path.read_text(encoding="utf-8")
    for bad in ('{"employees": ["id", "name"]}', "[]", "not json",
                '{"employees": {"id": 5}}'):
        demo_config.schema_path.write_text(bad, encoding="utf-8")
        with pytest.raises(AccessDenied, match="policy reload failed"):
            gate.authorize("bob", "SELECT name FROM employees")
        assert gate.broken
    demo_config.schema_path.write_text(good, encoding="utf-8")
    gate.authorize("bob", "SELECT name FROM employees")
    assert gate.broken is None


def test_load_snapshot_takes_schema_bytes(demo_config):
    args = [demo_config.model_path.read_bytes(),
            demo_config.policy_path.read_bytes(),
            demo_config.attributes_path.read_bytes()]
    with pytest.raises(TypeError):
        load_snapshot(*args, {"employees": {"id": "int"}}, dialect="sqlite")
    snap = load_snapshot(*args, demo_config.schema_path.read_bytes(),
                         dialect="sqlite")
    assert isinstance(snap.schema, MappingProxyType)
    with pytest.raises(TypeError):
        snap.schema["employees"]["salary"] = "text"


# ---- 3. read-only SQLite URI ----------------------------------------------------

@pytest.mark.parametrize("dirname", ["x#y", "p%41q", "with space", "a?b=c"])
def test_db_under_awkward_directory_opens_read_only(tmp_path, dirname):
    try:
        folder = tmp_path / dirname
        folder.mkdir()
    except OSError:
        pytest.skip(f"{dirname!r} is not a valid directory name here")
    db = folder / "company.db"
    seed(db)
    before = sorted(p.name for p in tmp_path.rglob("*"))
    assert readonly_uri(db).endswith("?mode=ro")
    assert execute("SELECT COUNT(*) AS n FROM employees", db) == [{"n": 7}]
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        execute("CREATE TABLE stray (x)", db)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        execute("UPDATE employees SET salary = 0", db)
    # no stray database was created next to it (or anywhere under tmp_path)
    assert sorted(p.name for p in tmp_path.rglob("*")) == before
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT MIN(salary) FROM employees").fetchone()[0] > 0


def test_missing_db_is_not_created(tmp_path):
    db = tmp_path / "x#y" / "nope.db"
    db.parent.mkdir()
    with pytest.raises(sqlite3.OperationalError):
        execute("SELECT 1", db)
    assert not db.exists() and list(db.parent.iterdir()) == []


# ---- 4. read-only snapshot attributes ---------------------------------------

class MutatingProvider(JsonAttributeProvider):
    def __init__(self):
        self.errors = []

    def resolve(self, identity, attributes):
        worker = super().resolve(identity, attributes)
        for mutate in (lambda: attributes["bob"].__setitem__("dept", "finance"),
                       lambda: attributes.__setitem__("eve", {"role": "x"}),
                       lambda: attributes["bob"].update(dept="finance"),
                       lambda: attributes["bob"].pop("dept")):
            try:
                mutate()
            except (TypeError, AttributeError) as err:
                self.errors.append(type(err).__name__)
        return worker


def test_mutating_provider_cannot_change_rows(make_engine):
    provider = MutatingProvider()
    rows_seen = []

    def answer(kwargs):
        rows_seen.append(json.loads(kwargs["messages"][-1]["content"][0]["content"]))
        return end_turn("done")

    engine, _ = make_engine([tool_use("SELECT name, dept FROM employees"), answer],
                            attribute_provider=provider)
    fingerprint = engine.fingerprint
    result = engine.ask(who("bob"), [U("who works here?")], conversation_id="c")
    assert not result.denied and result.worker == "bob"
    assert len(provider.errors) == 4  # every mutation attempt refused
    assert {r["dept"] for r in rows_seen[0]} == {"engineering"}
    assert engine.gate.attributes["bob"]["dept"] == "engineering"
    assert "eve" not in engine.gate.attributes
    assert engine.reload() == fingerprint


def test_snapshot_attributes_are_deeply_frozen(demo_config):
    attrs = json.loads(demo_config.attributes_path.read_text(encoding="utf-8"))
    attrs["bob"]["tags"] = ["a", {"k": [1]}]
    demo_config.attributes_path.write_text(json.dumps(attrs), encoding="utf-8")
    gate = SQLGate.from_config(demo_config)
    bob = gate.attributes["bob"]
    assert isinstance(gate.attributes, MappingProxyType)
    assert isinstance(bob, MappingProxyType)
    assert bob["tags"][0] == "a" and isinstance(bob["tags"], tuple)
    with pytest.raises(TypeError):
        bob["tags"][1]["k"] = 2
    with pytest.raises(AttributeError):
        bob["tags"][1]["k"].append(2)
    # the snapshot is decoupled from the dict it was built from
    gate.authorize("bob", "SELECT name FROM employees")


# ---- 5. SQLite error text stays out of the model's context -------------------

def test_sql_error_message_never_reaches_the_model(make_engine, monkeypatch,
                                                   audit_lines):
    secret = "Carol Lim earns 112000"

    def failing_execute(sql, db_path):
        raise sqlite3.OperationalError(f"malformed value near '{secret}'")
    monkeypatch.setattr("rbic.engine.execute", failing_execute)
    engine, client = make_engine([tool_use("SELECT name FROM employees"),
                                  end_turn("sorry")])
    result = engine.ask(who("bob"), [U("q")], conversation_id="c")
    assert result.text == "sorry" and not result.denied
    tool_result = client.calls[1][-1]["content"][0]
    assert tool_result["is_error"] is True
    assert tool_result["content"] == f"{SQL_ERROR_TOOL_MESSAGE} (OperationalError)"
    sent = json.dumps(client.calls, default=str)
    assert secret not in sent and "112000" not in sent and "malformed" not in sent
    lines = audit_lines()
    assert "SQL_ERROR user=bob error=OperationalError" in lines
    assert not any(secret in line for line in lines)


def test_real_sqlite_error_is_generic(make_engine):
    engine, client = make_engine([tool_use("SELECT json(name) FROM employees"),
                                  end_turn("ok")])
    engine.ask(who("bob"), [U("q")], conversation_id="c")
    content = client.calls[1][-1]["content"][0]["content"]
    assert content == f"{SQL_ERROR_TOOL_MESSAGE} (OperationalError)"


# ---- 6. ask() never raises -------------------------------------------------------

class RaisingGetattr:
    def __getattr__(self, name):
        raise RuntimeError("boom")


class IdentityWithRaisingEmail(Identity):
    def __getattribute__(self, name):
        if name == "email":
            raise RuntimeError("boom")
        return super().__getattribute__(name)


class RaisingGetDict(dict):
    def get(self, key, default=None):
        raise KeyError(key)

    def __getitem__(self, key):
        raise KeyError(key)


class SneakyStr(str):
    calls = []

    def strip(self, *args):
        SneakyStr.calls.append("strip")
        return 5

    def __hash__(self):
        return 0

    def __eq__(self, other):
        return True


class RaisingAudience:
    @property
    def value(self):
        raise RuntimeError("boom")


def raising_messages():
    yield U("first")
    raise ValueError("generator failed")


def assert_result(result):
    assert isinstance(result, AskResult)
    assert isinstance(result.text, str) and result.text


def test_hostile_identity_objects(make_engine):
    engine, client = make_engine()
    for ident in (RaisingGetattr(), object(), None, "bob@example.test",
                  IdentityWithRaisingEmail("oidc", "x")):
        result = engine.ask(ident, [U("q")])
        assert_result(result)
        assert result.denied and result.text == DENY_MESSAGE
        assert result.reason == "identity: not an Identity"
    assert client.calls == []


def test_identity_str_subclass_fields_are_plain(make_engine):
    seen = []

    class Recording(JsonAttributeProvider):
        def resolve(self, identity, attributes):
            seen.append(identity)
            return super().resolve(identity, attributes)

    engine, client = make_engine([end_turn("ok")], attribute_provider=Recording())
    result = engine.ask(Identity(SneakyStr("oidc"), SneakyStr("s"),
                                 SneakyStr("bob@example.test")), [U("q")])
    assert_result(result)
    assert result.worker == "bob"
    assert all(type(v) is str for v in (seen[0].provider, seen[0].subject,
                                        seen[0].email))


def test_generator_raising_mid_iteration(make_engine):
    engine, client = make_engine()
    result = engine.ask(who("bob"), raising_messages())
    assert_result(result)
    assert not result.denied and result.reason == "no question"
    assert client.calls == []


def test_dict_subclass_with_raising_get(make_engine):
    engine, client = make_engine([end_turn("ok")])
    result = engine.ask(who("bob"), [RaisingGetDict(role="user", content="q")])
    assert_result(result)
    assert result.text == "ok"
    assert client.calls[0] == [{"role": "user", "content": "q"}]


def test_str_subclass_content_is_sent_as_plain_str(make_engine):
    SneakyStr.calls.clear()
    engine, client = make_engine([end_turn("ok")])
    result = engine.ask(who("bob"), [{"role": SneakyStr("user"),
                                      "content": SneakyStr("  hello  ")}])
    assert_result(result)
    assert result.text == "ok" and SneakyStr.calls == []
    turn = client.calls[0][0]
    assert turn == {"role": "user", "content": "hello"}
    assert type(turn["content"]) is str and type(turn["role"]) is str


def test_hostile_mapping_turn_is_dropped(make_engine):
    from collections.abc import Mapping

    class RaisingMapping(Mapping):
        def __getitem__(self, key):
            raise RuntimeError("boom")

        def __iter__(self):
            raise RuntimeError("boom")

        def __len__(self):
            return 2

    engine, client = make_engine([end_turn("ok")])
    result = engine.ask(who("bob"), [RaisingMapping(), U("q")])
    assert_result(result)
    assert result.text == "ok" and client.calls[0] == [U("q")]


def test_audience_whose_value_raises(make_engine, audit_lines):
    engine, client = make_engine()
    result = engine.ask(who("bob"), [U("q")], audience=RaisingAudience())
    assert_result(result)
    assert result.denied and result.reason == "audience"
    assert client.calls == []
    assert any(line.startswith("AUDIENCE_DENY") and "RaisingAudience" in line
               for line in audit_lines())


def test_conversation_id_str_subclass_cannot_alias_another(make_engine):
    engine, client = make_engine([end_turn("one"), end_turn("two")])
    first = engine.ask(who("bob"), [U("q1")], conversation_id="real-conv")
    engine.ask(who("bob"), [U("q1"), {"role": "assistant", "content": first.text},
                            U("q2")], conversation_id=SneakyStr("other"))
    assert len(client.calls[1]) == 1  # unknown conversation: last turn only


def test_unexpected_failure_is_an_engine_error_deny(make_engine, monkeypatch,
                                                    audit_lines):
    engine, client = make_engine()

    def explode(*args, **kwargs):
        raise RuntimeError("secret detail bob@example.test")
    monkeypatch.setattr("rbic.engine.sanitize_history", explode)
    result = engine.ask(who("bob"), [U("q")])
    assert_result(result)
    assert result == AskResult(DENY_MESSAGE, True, "engine error", None, None)
    lines = audit_lines()
    assert "ENGINE_ERROR stage=ask error=RuntimeError" in lines
    assert not any("secret" in line or "example.test" in line for line in lines)


def test_aask_never_raises(make_engine):
    import asyncio
    engine, _ = make_engine()
    result = asyncio.run(engine.aask(RaisingGetattr(), raising_messages(),
                                     audience=RaisingAudience()))
    assert_result(result)
    assert result.denied
