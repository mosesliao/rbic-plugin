"""Schema introspection: the database's tables -> db_schema.json's shape.

introspect_sqlite() reads only the catalog (sqlite_master and
pragma_table_info), never a row, over a read-only connection. Writing
db_schema.json is not done here: it goes through
PolicyAdmin.propose_schema_update() / apply() (validated with the gate's
loader in both dialects, locked, changelogged, confirmed by a human).
"""

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..engine import readonly_uri

# Names the gate can address: sqlglot lowercases unquoted identifiers, and
# policy objects are "table.column" strings split by Casbin's comma
# tokenizer, so anything but a plain lowercase identifier is skipped (a
# mixed-case table is unreachable through the gate: fail closed, noisily).
IDENTIFIER_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z", re.ASCII)

# Names the gate's loader refuses as a table (and that are reserved as a
# column too): `master` is the policy owner's role, never data. A table
# named so would break every compile/report later; it is skipped here.
RESERVED_NAMES = ("master",)

# Internal storage tables of virtual tables (FTS3/4/5, R*Tree): created by
# SQLite next to `CREATE VIRTUAL TABLE v ...` as v_<suffix>. They hold the
# index / a copy of the indexed text, not data to grant: skipped.
SHADOW_SUFFIXES = ("_content", "_data", "_idx", "_docsize", "_config",
                   "_segments", "_segdir", "_stat", "_node", "_rowid",
                   "_parent")

# Normalized types, as the shipped db_schema.json files use them. The gate
# never looks at types (they document the column for humans and the LLM).
SCHEMA_TYPES = ("int", "text", "numeric", "date", "timestamp")


def normalize_type(declared: str) -> tuple:
    """(normalized type, note or None) for an SQLite declared type.

    Follows SQLite's affinity rules (INT -> int; CHAR/CLOB/TEXT -> text;
    REAL/FLOA/DOUB and NUMERIC/DECIMAL/BOOL -> numeric), after recognizing
    DATE / DATETIME / TIMESTAMP. Anything else (including no declared type
    and BLOB) is reported as text with a note.
    """
    raw = (declared or "").strip()
    upper = raw.upper()
    if not upper:
        return "text", "no declared type; reported as text"
    if "TIMESTAMP" in upper or "DATETIME" in upper:
        return "timestamp", None
    if re.match(r"DATE\b", upper):
        return "date", None
    if "INT" in upper:
        return "int", None
    if any(k in upper for k in ("CHAR", "CLOB", "TEXT")):
        return "text", None
    if any(k in upper for k in ("REAL", "FLOA", "DOUB", "NUMERIC", "DECIMAL",
                                "BOOL")):
        return "numeric", None
    return "text", f"unknown declared type {ascii(raw[:40])}; reported as text"


def introspect_sqlite(db_path, notes: Optional[list] = None) -> dict:
    """{table: {column: type}} for every table and view of an SQLite
    database, in db_schema.json's shape.

    Tables (and views) are sorted by name, columns keep their declared
    order. sqlite_* internal tables are skipped; so are, with a note,
    tables and columns whose names are not lowercase identifiers
    (IDENTIFIER_RE), names the gate refuses (RESERVED_NAMES: `master`),
    and the shadow tables of virtual tables (FTS3/4/5 and R*Tree
    `<name>_content`, `_data`, `_idx`, `_docsize`, `_config`,
    `_segments`, `_segdir`, `_stat`, ...). Notes (unknown types, skipped
    names) are appended to `notes` if given; names in them are ascii()-
    escaped, so printing them never fails on a non-UTF-8 console. Opens
    the database read-only and reads no rows.
    """
    notes = [] if notes is None else notes
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"Database {str(path)!r} does not exist.")
    conn = sqlite3.connect(readonly_uri(path), uri=True)
    try:
        conn.execute("PRAGMA query_only = ON")
        objects = conn.execute(
            "SELECT name, type, sql FROM sqlite_master "
            "WHERE type IN ('table', 'view') "
            "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name"
        ).fetchall()
        virtual = sorted(name for name, kind, sql in objects
                         if kind == "table" and isinstance(sql, str)
                         and sql.lstrip().upper().startswith(
                             "CREATE VIRTUAL TABLE"))
        schema = {}
        for table, kind, _ in objects:
            if not IDENTIFIER_RE.match(table):
                notes.append(f"{kind} {ascii(table)} skipped: not a lowercase "
                             "identifier the gate can address (expose it "
                             "through a lowercase view)")
                continue
            if table in RESERVED_NAMES:
                notes.append(f"{kind} {ascii(table)} skipped: '{table}' is "
                             "reserved for the policy owner's role and the "
                             "SQL gate refuses it as a table name (expose it "
                             "through a view with another name)")
                continue
            owner = next((v for v in virtual for s in SHADOW_SUFFIXES
                          if kind == "table" and table == v + s), None)
            if owner is not None:
                notes.append(f"table {ascii(table)} skipped: internal shadow "
                             f"table of virtual table {ascii(owner)} (FTS / "
                             "R*Tree storage, not data to grant)")
                continue
            columns = {}
            for column, declared in conn.execute(
                    "SELECT name, type FROM pragma_table_info(?) ORDER BY cid",
                    (table,)):
                if not IDENTIFIER_RE.match(column):
                    notes.append(f"{table}.{ascii(column)} skipped: not a "
                                 "lowercase identifier the gate can address")
                    continue
                if column in RESERVED_NAMES:
                    notes.append(f"{table}.{column} skipped: '{column}' is "
                                 "reserved for the policy owner's role "
                                 "(expose it through a view with another "
                                 "name)")
                    continue
                typ, note = normalize_type(declared)
                if note:
                    notes.append(f"{table}.{column}: {note}")
                columns[column] = typ
            if not columns:
                notes.append(f"{kind} {ascii(table)} skipped: no addressable "
                             "columns")
                continue
            schema[table] = columns
        return schema
    finally:
        conn.close()


@dataclass
class SchemaDiff:
    """What changes from `old` to `new` (both {table: {column: type}})."""
    added_tables: list = field(default_factory=list)
    removed_tables: list = field(default_factory=list)
    added_columns: dict = field(default_factory=dict)    # table -> [col]
    removed_columns: dict = field(default_factory=dict)  # table -> [col]
    type_changes: dict = field(default_factory=dict)     # table -> [(col, old, new)]

    @property
    def empty(self) -> bool:
        return not (self.added_tables or self.removed_tables
                    or self.added_columns or self.removed_columns
                    or self.type_changes)

    def lines(self, new: Optional[dict] = None) -> list:
        """Plain-language lines; `new` adds the column list of new tables."""
        out = []
        for t in self.added_tables:
            cols = f" ({', '.join(new[t])})" if new and t in new else ""
            out.append(f"new table {t}{cols}")
        out += [f"table {t} removed" for t in self.removed_tables]
        for t, cols in self.added_columns.items():
            out.append(f"{t}: new column(s) {', '.join(cols)}")
        for t, cols in self.removed_columns.items():
            out.append(f"{t}: column(s) removed: {', '.join(cols)}")
        for t, changes in self.type_changes.items():
            out.append(f"{t}: type change(s) "
                       + ", ".join(f"{c} {a} -> {b}" for c, a, b in changes)
                       + " (no effect on access)")
        return out


def diff_schema(old: dict, new: dict) -> SchemaDiff:
    """Added/removed tables and columns and type changes, in `new`'s order
    (removals in `old`'s order)."""
    d = SchemaDiff()
    d.added_tables = [t for t in new if t not in old]
    d.removed_tables = [t for t in old if t not in new]
    for t in new:
        if t not in old:
            continue
        added = [c for c in new[t] if c not in old[t]]
        removed = [c for c in old[t] if c not in new[t]]
        retyped = [(c, old[t][c], new[t][c]) for c in new[t]
                   if c in old[t] and old[t][c] != new[t][c]]
        if added:
            d.added_columns[t] = added
        if removed:
            d.removed_columns[t] = removed
        if retyped:
            d.type_changes[t] = retyped
    return d


def ordered_like(old: dict, new: dict) -> dict:
    """`new`'s content in `old`'s order: tables and columns that `old`
    already lists keep their place, new ones follow in `new`'s order (so
    rewriting db_schema.json yields the smallest diff)."""
    out = {}
    for t in old:
        if t in new:
            cols = {c: new[t][c] for c in old[t] if c in new[t]}
            cols.update((c, typ) for c, typ in new[t].items() if c not in cols)
            out[t] = cols
    for t in new:
        if t not in out:
            out[t] = dict(new[t])
    return out
