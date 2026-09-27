"""Create and seed company.db with demo data matching db_schema.json.

Data spans two warehouses (SG-01, SG-02) and two departments
(engineering, logistics) so the ABAC row filters are visible:
alice (site SG-01) must never see SG-02 rows, bob/carol (engineering)
must never see logistics HR rows, dave (logistics) only logistics expenses.
"""

import os
import sqlite3

DB_PATH = "company.db"

DDL = """
CREATE TABLE inventory (
    id INTEGER PRIMARY KEY, sku TEXT, qty INTEGER, warehouse_id TEXT
);
CREATE TABLE shipments (
    id INTEGER PRIMARY KEY, warehouse_id TEXT, destination TEXT,
    eta TEXT, status TEXT
);
CREATE TABLE safety_incidents (
    id INTEGER PRIMARY KEY, warehouse_id TEXT, severity TEXT,
    reported_at TEXT, description TEXT
);
CREATE TABLE payroll (
    id INTEGER PRIMARY KEY, employee_id INTEGER, salary NUMERIC,
    effective_date TEXT
);
CREATE TABLE employees (
    id INTEGER PRIMARY KEY, name TEXT, dept TEXT, start_date TEXT,
    salary NUMERIC
);
CREATE TABLE leave_requests (
    id INTEGER PRIMARY KEY, employee_id INTEGER, dept TEXT,
    start_date TEXT, end_date TEXT, status TEXT
);
CREATE TABLE trainings (
    id INTEGER PRIMARY KEY, title TEXT, dept TEXT, date TEXT
);
CREATE TABLE budgets (
    id INTEGER PRIMARY KEY, dept TEXT, fiscal_year INTEGER, amount NUMERIC
);
CREATE TABLE expenses (
    id INTEGER PRIMARY KEY, dept TEXT, amount NUMERIC,
    submitted_by TEXT, status TEXT
);
CREATE TABLE invoices (
    id INTEGER PRIMARY KEY, vendor TEXT, amount NUMERIC,
    due_date TEXT, status TEXT
);
"""

DATA = {
    "inventory": [
        (1, "PAL-4512", 340, "SG-01"),
        (2, "BOX-2210", 80, "SG-01"),
        (3, "GLV-0031", 6, "SG-01"),
        (4, "PAL-9004", 12, "SG-02"),
        (5, "CRT-1100", 55, "SG-02"),
    ],
    "shipments": [
        (1, "SG-01", "Kuala Lumpur", "2026-07-14", "in_transit"),
        (2, "SG-01", "Jakarta", "2026-07-18", "scheduled"),
        (3, "SG-02", "Bangkok", "2026-07-12", "delayed"),
    ],
    "safety_incidents": [
        (1, "SG-01", "minor", "2026-06-02 09:14", "Forklift near-miss in aisle 4"),
        (2, "SG-02", "major", "2026-06-20 15:40", "Rack collapse, no injuries"),
    ],
    "employees": [
        (1, "Bob Tan", "engineering", "2021-03-01", 78000),
        (2, "Carol Lim", "engineering", "2019-07-15", 112000),
        (3, "Erin Ng", "engineering", "2023-01-09", 65000),
        (4, "Frank Ho", "logistics", "2020-11-20", 58000),
        (5, "Grace Koh", "logistics", "2022-05-02", 61000),
        (6, "Alice Wong", "warehouse", "2022-09-01", 42000),
        (7, "Dave Chua", "finance", "2021-06-14", 52000),
    ],
    "payroll": [
        (1, 1, 78000, "2026-01-01"),
        (2, 2, 112000, "2026-01-01"),
        (3, 3, 65000, "2026-01-01"),
        (4, 4, 58000, "2026-01-01"),
        (5, 5, 61000, "2026-01-01"),
        (6, 6, 42000, "2026-01-01"),
        (7, 7, 52000, "2026-01-01"),
    ],
    "leave_requests": [
        (1, 1, "engineering", "2026-07-20", "2026-07-24", "pending"),
        (2, 3, "engineering", "2026-08-03", "2026-08-07", "approved"),
        (3, 4, "logistics", "2026-07-15", "2026-07-16", "approved"),
    ],
    "trainings": [
        (1, "Secure Coding 101", "engineering", "2026-08-12"),
        (2, "Forklift Certification", "logistics", "2026-07-30"),
    ],
    "budgets": [
        (1, "engineering", 2026, 1200000),
        (2, "logistics", 2026, 800000),
    ],
    "expenses": [
        (1, "engineering", 450.00, "Erin Ng", "approved"),
        (2, "engineering", 1200.50, "Bob Tan", "pending"),
        (3, "logistics", 300.75, "Frank Ho", "approved"),
        (4, "logistics", 89.90, "Grace Koh", "pending"),
    ],
    "invoices": [
        (1, "Acme Pallets Pte Ltd", 15400.00, "2026-07-31", "unpaid"),
        (2, "SafetyFirst Gear", 2300.00, "2026-07-15", "paid"),
        (3, "CloudHost SG", 980.00, "2026-08-01", "unpaid"),
    ],
}


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(DDL)
    for table, rows in DATA.items():
        placeholders = ", ".join("?" * len(rows[0]))
        conn.executemany(f"INSERT INTO {table} VALUES ({placeholders})", rows)
    conn.commit()
    conn.close()
    print(f"Seeded {DB_PATH} with {sum(len(r) for r in DATA.values())} rows "
          f"across {len(DATA)} tables.")


if __name__ == "__main__":
    main()
