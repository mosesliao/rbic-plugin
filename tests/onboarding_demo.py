"""Helpers: onboard the demo with rbic-init's library calls.

approve_catalog() approves every name-rule suggestion for the demo schema
(they match the demo's hand-written grants exactly); build_roles() merges
the starter packs and makes the few human edits that reproduce the
shipped roles; onboard_demo() replaces policy.csv with only the manual
(master chatbot) section and applies the compiled block through
PolicyAdmin, as `rbic-init compile` does after a yes.
"""

from datetime import datetime, timezone

from rbic.admin import PolicyAdmin
from rbic.config import resolve_config
from rbic.onboarding import catalog_path, roles_path
from rbic.onboarding.catalog import (apply_decisions, load_catalog,
                                     merge_suggestions, plan_approvals,
                                     save_catalog)
from rbic.onboarding.compile import compile_from_files
from rbic.onboarding.roles import (RowScope, load_pack, load_roles, merge_pack,
                                   remove_scope, save_roles, set_role)
from rbic.onboarding.suggest import suggest_categories

MANUAL_POLICY = (
    "# Demo policy: the role rules are compiled by rbic-init from "
    "onboarding/*.json.\n"
    "\n"
    "# ---- Changes via master chatbot ----\n"
    "p2, warehouse_worker, employees, id = '{employee_id}', id|name|salary\n")
PACKS = ("staff_self_service", "hr", "finance", "warehouse")
BASE_ROLES = ("warehouse_worker", "hr_staff", "finance_analyst")
# The packs scope every table that has the ownership column; the shipped
# demo leaves these three unscoped, so the reproduction removes them.
DEMO_UNSCOPED = (("hr_staff", "trainings", "dept = '{dept}'"),
                 ("finance_analyst", "budgets", "dept = '{dept}'"),
                 ("warehouse_worker", "safety_incidents",
                  "warehouse_id = '{site}'"))
NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def config(d):
    return resolve_config(d, dialect="sqlite")


def admin(d) -> PolicyAdmin:
    return PolicyAdmin.from_config(config(d))


def approve_catalog(d, actor="master"):
    a = admin(d)
    schema = a.schema()
    catalog, sha = load_catalog(catalog_path(d), schema)
    merged, _ = merge_suggestions(
        catalog, suggest_categories(schema, use_values=False,
                                    categories=catalog.categories))
    plan = plan_approvals(merged, schema, all_suggested=True)
    save_catalog(catalog_path(d), apply_decisions(merged, plan, actor, NOW), sha)


def load_state(d):
    a = admin(d)
    schema = a.schema()
    catalog, _ = load_catalog(catalog_path(d), schema)
    users = sorted(a.attributes())
    roles, sha = load_roles(roles_path(d), catalog=catalog, schema=schema,
                            usernames=users)
    return schema, catalog, users, roles, sha


def save(d, roles, sha):
    schema, catalog, users, _, _ = load_state(d)
    return save_roles(roles_path(d), roles, sha, catalog=catalog,
                      schema=schema, usernames=users)


def build_roles(d, *, demo_exact=True, packs=PACKS):
    schema, catalog, users, roles, sha = load_state(d)
    for name in packs:
        roles, _ = merge_pack(roles, load_pack(name), catalog, schema, users)
    if "staff_self_service" in packs:
        for role in BASE_ROLES:
            if role in roles.roles:
                roles, _ = set_role(roles, role, inherits=["employee"])
    if demo_exact:
        for role, table, template in DEMO_UNSCOPED:
            roles, _ = remove_scope(roles, role, RowScope(table, template))
    return save(d, roles, sha)


def compile_change(d, actor="master"):
    cfg = config(d)
    generated = compile_from_files(d, cfg.schema_path, cfg.attributes_path)
    return generated, admin(d).propose_generated_policy(generated, actor=actor)


def compile_and_apply(d, actor="master"):
    generated, change = compile_change(d, actor)
    admin(d).apply(change, actor=actor)
    return generated, change


def onboard_demo(d, *, demo_exact=True):
    approve_catalog(d)
    build_roles(d, demo_exact=demo_exact)
    (d / "casbin" / "policy.csv").write_text(MANUAL_POLICY, encoding="utf-8",
                                             newline="")
    return compile_and_apply(d)
