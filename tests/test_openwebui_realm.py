"""The Keycloak test realm (integrations/openwebui/keycloak/realm-rbic.json).

Open WebUI links an SSO account by the token's `sub` (the Keycloak user id)
and never by email (OAUTH_MERGE_ACCOUNTS_BY_EMAIL=false). Without a fixed
`id`, every import of the realm (a recreated Keycloak container) gives the
demo users new ids, and every sign-in then fails with "This email is already
registered". The ids are fixed on purpose: uuid5(NAMESPACE_URL,
"urn:rbic-demo:keycloak-user:<username>").
"""

import json
import re
import uuid
from pathlib import Path

OPENWEBUI = Path(__file__).resolve().parent.parent / "integrations" / "openwebui"
REALM_FILE = OPENWEBUI / "keycloak" / "realm-rbic.json"
COMPOSE_FILE = OPENWEBUI / "docker-compose.yml"

DEMO_USERS = {"owui-admin", "bob", "carol", "dave", "mallory"}


def _users():
    return json.loads(REALM_FILE.read_text(encoding="utf-8"))["users"]


def test_every_demo_user_has_a_fixed_unique_uuid_id():
    users = _users()
    assert {u["username"] for u in users} == DEMO_USERS
    ids = [u.get("id") for u in users]
    assert all(isinstance(i, str) for i in ids), ids
    assert len(set(ids)) == len(ids)
    for user in users:
        parsed = uuid.UUID(user["id"])
        assert str(parsed) == user["id"]  # canonical lowercase form


def test_ids_follow_the_documented_derivation():
    for user in _users():
        expected = uuid.uuid5(uuid.NAMESPACE_URL,
                              "urn:rbic-demo:keycloak-user:" + user["username"])
        assert user["id"] == str(expected), user["username"]


def test_accounts_are_never_merged_by_email():
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    values = re.findall(r'^\s*OAUTH_MERGE_ACCOUNTS_BY_EMAIL:\s*"?([^"\s#]*)"?',
                        text, re.MULTILINE)
    assert values == ["false"]
