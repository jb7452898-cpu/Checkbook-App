# checkbook app
import os
import io
import csv
import sqlite3
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone

import psycopg
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, Response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Config ---
SQLITE_PATH = os.path.join(os.path.dirname(__file__), "checkbook.db")
DATABASE_URL = os.environ.get("DATABASE_URL")  # Render Postgres URL in prod
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.permanent_session_lifetime = 60 * 60 * 24 * 30  # ~30 days


def using_postgres() -> bool:
    return bool(DATABASE_URL)


def normalize_username(s: str) -> str:
    return (s or "").strip().lower()


def require_login(fn):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db():
    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                # users (needed for PIN login + FKs)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                pin_hash TEXT
                );
                """)
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_hash TEXT;")

                # payment types
                cur.execute("""
                CREATE TABLE IF NOT EXISTS payment_types (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                UNIQUE(user_id, name)
                );
                """)

                # vendors
                cur.execute("""
                CREATE TABLE IF NOT EXISTS vendors (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                UNIQUE(user_id, name)
                );
                """)

                # vendor items
                cur.execute("""
                CREATE TABLE IF NOT EXISTS vendor_items (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                vendor_id INTEGER NOT NULL REFERENCES vendors(id),
                name TEXT NOT NULL,
                default_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
                UNIQUE(user_id, vendor_id, name)
                );
                """)

                # transactions (B1 + receipt grouping)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                txn_date DATE NOT NULL,
                payment_type_id INTEGER NOT NULL REFERENCES payment_types(id),
                vendor_id INTEGER NOT NULL REFERENCES vendors(id),
                vendor_item_id INTEGER NULL REFERENCES vendor_items(id),
                amount NUMERIC(12,2) NOT NULL,
                memo TEXT NOT NULL DEFAULT '',
                receipt_id TEXT NOT NULL,
                is_receipt_total BOOLEAN NOT NULL DEFAULT FALSE,
                exported_at TIMESTAMPTZ NULL
                );
                """)
            conn.commit()
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    pin_hash TEXT
                );
            """)
            # sqlite: add column if missing (ignore if already exists)
            try:
                con.execute("ALTER TABLE users ADD COLUMN pin_hash TEXT;")
            except sqlite3.OperationalError:
                pass

            con.execute("""
            CREATE TABLE IF NOT EXISTS payment_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            UNIQUE(user_id, name),
            FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """)

            con.execute("""
            CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            UNIQUE(user_id, name),
            FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """)

            con.execute("""
            CREATE TABLE IF NOT EXISTS vendor_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            vendor_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            default_amount TEXT NOT NULL DEFAULT '0.00',
            UNIQUE(user_id, vendor_id, name),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(vendor_id) REFERENCES vendors(id)
            );
            """)

            con.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            txn_date TEXT NOT NULL,
            payment_type_id INTEGER NOT NULL,
            vendor_id INTEGER NOT NULL,
            vendor_item_id INTEGER NULL,
            amount TEXT NOT NULL,
            memo TEXT NOT NULL DEFAULT '',
            receipt_id TEXT NOT NULL,
            is_receipt_total INTEGER NOT NULL DEFAULT 0,
            exported_at TEXT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(payment_type_id) REFERENCES payment_types(id),
            FOREIGN KEY(vendor_id) REFERENCES vendors(id),
            FOREIGN KEY(vendor_item_id) REFERENCES vendor_items(id)
            );
            """)
            con.commit()


def get_user_by_username(username: str):
    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, pin_hash FROM users WHERE username=%s", (username,))
                return cur.fetchone()  # (id, pin_hash) or None
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute("SELECT id, pin_hash FROM users WHERE username=?", (username,))
            return cur.fetchone()


def create_user(username: str, pin_hash: str) -> int:
    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users(username, pin_hash) VALUES (%s, %s) RETURNING id",
                    (username, pin_hash),
                )
                new_id = cur.fetchone()[0]
            conn.commit()
        return int(new_id)
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute(
                "INSERT INTO users(username, pin_hash) VALUES (?, ?)",
                (username, pin_hash),
            )
            con.commit()
            return int(cur.lastrowid)


def set_user_pin(user_id: int, pin_hash: str) -> None:
    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET pin_hash=%s WHERE id=%s", (pin_hash, user_id))
            conn.commit()
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.execute("UPDATE users SET pin_hash=? WHERE id=?", (pin_hash, user_id))
            con.commit()


@app.get("/health")
def health():
    return jsonify({"ok": True, "db": "postgres" if using_postgres() else "sqlite"})


@app.get("/login")
def login():
    return render_template("login.html")


@app.post("/login")
def login_post():
    username = normalize_username(request.form.get("username", ""))
    pin = (request.form.get("pin", "") or "").strip()

    if not username:
        return render_template("login.html", error="Please enter a username.")
    if not pin or len(pin) < 4 or not pin.isdigit():
        return render_template("login.html", error="PIN must be numeric and at least 4 digits.")

    row = get_user_by_username(username)
    if row is None:
        user_id = create_user(username, generate_password_hash(pin))
    else:
        user_id, pin_hash = int(row[0]), row[1]
        if not pin_hash:
            set_user_pin(user_id, generate_password_hash(pin))
        else:
            if not check_password_hash(pin_hash, pin):
                return render_template("login.html", error="Incorrect PIN.")

    session["user_id"] = user_id
    session["username"] = username
    session.permanent = True
    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@require_login
def home():
    return render_template("index.html")


@app.get("/api/payment_types")
@require_login
def list_payment_types():
    user_id = int(session["user_id"])

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, name FROM payment_types WHERE user_id=%s ORDER BY name ASC",
                    (user_id,),
                )
                rows = cur.fetchall()
        items = [{"id": r[0], "name": r[1]} for r in rows]
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT id, name FROM payment_types WHERE user_id=? ORDER BY name ASC",
                (user_id,),
            ).fetchall()
        items = [{"id": r["id"], "name": r["name"]} for r in rows]

    return jsonify({"items": items})


@app.post("/api/payment_types")
@require_login
def create_payment_type():
    user_id = int(session["user_id"])
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()

    if not name:
        return ("Missing name", 400)

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO payment_types(user_id, name)
                    VALUES (%s, %s)
                    ON CONFLICT (user_id, name) DO UPDATE SET name=EXCLUDED.name
                    RETURNING id
                    """,
                    (user_id, name),
                )
                new_id = cur.fetchone()[0]
            conn.commit()
        return jsonify({"id": int(new_id), "name": name})
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute(
                "INSERT OR IGNORE INTO payment_types(user_id, name) VALUES (?, ?)",
                (user_id, name),
            )
            con.commit()
            # fetch id either way
            row = con.execute(
                "SELECT id FROM payment_types WHERE user_id=? AND name=?",
                (user_id, name),
            ).fetchone()
        return jsonify({"id": int(row[0]), "name": name})


@app.get("/api/vendors")
@require_login
def list_vendors():
    user_id = int(session["user_id"])

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, name FROM vendors WHERE user_id=%s ORDER BY name ASC",
                    (user_id,),
                )
                rows = cur.fetchall()
        items = [{"id": r[0], "name": r[1]} for r in rows]
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT id, name FROM vendors WHERE user_id=? ORDER BY name ASC",
                (user_id,),
            ).fetchall()
        items = [{"id": r["id"], "name": r["name"]} for r in rows]

    return jsonify({"items": items})


@app.post("/api/vendors")
@require_login
def create_vendor():
    user_id = int(session["user_id"])
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()

    if not name:
        return ("Missing name", 400)

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO vendors(user_id, name)
                    VALUES (%s, %s)
                    ON CONFLICT (user_id, name) DO UPDATE SET name=EXCLUDED.name
                    RETURNING id
                    """,
                    (user_id, name),
                )
                new_id = cur.fetchone()[0]
            conn.commit()
        return jsonify({"id": int(new_id), "name": name})
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute(
                "INSERT OR IGNORE INTO vendors(user_id, name) VALUES (?, ?)",
                (user_id, name),
            )
            con.commit()
            row = con.execute(
                "SELECT id FROM vendors WHERE user_id=? AND name=?",
                (user_id, name),
            ).fetchone()
        return jsonify({"id": int(row[0]), "name": name})

@app.get("/api/vendors/<int:vendor_id>/items")
@require_login
def list_vendor_items(vendor_id: int):
    user_id = int(session["user_id"])

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, name, default_amount
                    FROM vendor_items
                    WHERE user_id=%s AND vendor_id=%s
                    ORDER BY name ASC
                    """,
                    (user_id, vendor_id),
                )
                rows = cur.fetchall()
        items = [{"id": r[0], "name": r[1], "default_amount": str(r[2])} for r in rows]
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.row_factory = sqlite3.Row
            rows = con.execute(
                """
                SELECT id, name, default_amount
                FROM vendor_items
                WHERE user_id=? AND vendor_id=?
                ORDER BY name ASC
                """,
                (user_id, vendor_id),
            ).fetchall()
        items = [{"id": r["id"], "name": r["name"], "default_amount": r["default_amount"]} for r in rows]

    return jsonify({"items": items})


@app.post("/api/vendors/<int:vendor_id>/items")
@require_login
def create_vendor_item(vendor_id: int):
    user_id = int(session["user_id"])
    data = request.get_json(force=True)

    name = (data.get("name") or "").strip()
    amt_raw = (data.get("default_amount") or "").strip()

    if not name:
        return ("Missing name", 400)
    try:
        amt = Decimal(amt_raw).quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError):
        return ("Invalid default_amount", 400)

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO vendor_items(user_id, vendor_id, name, default_amount)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (user_id, vendor_id, name)
                    DO UPDATE SET default_amount=EXCLUDED.default_amount
                    RETURNING id, default_amount
                    """,
                    (user_id, vendor_id, name, str(amt)),
                )
                row = cur.fetchone()
            conn.commit()
        return jsonify({"id": int(row[0]), "name": name, "default_amount": str(row[1])})
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            # insert or update
            con.execute(
                "INSERT OR IGNORE INTO vendor_items(user_id, vendor_id, name, default_amount) VALUES (?, ?, ?, ?)",
                (user_id, vendor_id, name, str(amt)),
            )
            con.execute(
                "UPDATE vendor_items SET default_amount=? WHERE user_id=? AND vendor_id=? AND name=?",
                (str(amt), user_id, vendor_id, name),
            )
            con.commit()
            row = con.execute(
                "SELECT id, default_amount FROM vendor_items WHERE user_id=? AND vendor_id=? AND name=?",
                (user_id, vendor_id, name),
            ).fetchone()
        return jsonify({"id": int(row[0]), "name": name, "default_amount": row[1]})

@app.get("/api/txns")
@require_login
def list_txns():
    user_id = int(session["user_id"])

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                      t.id,
                      t.txn_date,
                      pt.name as payment_type,
                      v.name as vendor,
                      vi.name as item,
                      t.amount,
                      t.memo,
                      t.receipt_id,
                      t.is_receipt_total,
                      t.exported_at
                    FROM transactions t
                    JOIN payment_types pt ON pt.id = t.payment_type_id
                    JOIN vendors v ON v.id = t.vendor_id
                    LEFT JOIN vendor_items vi ON vi.id = t.vendor_item_id
                    WHERE t.user_id=%s
                    ORDER BY t.txn_date DESC, t.id DESC
                    """,
                    (user_id,),
                )
                rows = cur.fetchall()

        txns = []
        for r in rows:
            txns.append({
                "id": r[0],
                "date": r[1].isoformat(),
                "payment_type": r[2],
                "vendor": r[3],
                "item": (r[4] if r[4] else None),
                "amount": str(r[5]),
                "memo": r[6],
                "receipt_id": r[7],
                "is_receipt_total": bool(r[8]),
                "exported_at": (r[9].isoformat() if r[9] else None),
            })
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.row_factory = sqlite3.Row
            rows = con.execute(
                """
                SELECT
                  t.id,
                  t.txn_date as date,
                  pt.name as payment_type,
                  v.name as vendor,
                  vi.name as item,
                  t.amount,
                  t.memo,
                  t.receipt_id,
                  t.is_receipt_total,
                  t.exported_at
                FROM transactions t
                JOIN payment_types pt ON pt.id = t.payment_type_id
                JOIN vendors v ON v.id = t.vendor_id
                LEFT JOIN vendor_items vi ON vi.id = t.vendor_item_id
                WHERE t.user_id=?
                ORDER BY t.txn_date DESC, t.id DESC
                """,
                (user_id,),
            ).fetchall()

        txns = [{
            "id": r["id"],
            "date": r["date"],
            "payment_type": r["payment_type"],
            "vendor": r["vendor"],
            "item": r["item"],
            "amount": r["amount"],
            "memo": r["memo"],
            "receipt_id": r["receipt_id"],
            "is_receipt_total": bool(r["is_receipt_total"]),
            "exported_at": r["exported_at"],
        } for r in rows]

    total = str(sum(Decimal(t["amount"]) for t in txns)) if txns else "0.00"
    return jsonify({"username": session.get("username"), "txns": txns, "total": total})

@app.post("/api/txns")
@require_login
def add_txn():
    user_id = int(session["user_id"])
    data = request.get_json(force=True)

    txn_date = (data.get("date") or "").strip()
    receipt_id = (data.get("receipt_id") or "").strip()
    payment_type_id = data.get("payment_type_id")
    vendor_id = data.get("vendor_id")
    vendor_item_id = data.get("vendor_item_id")
    amount_raw = (data.get("amount") or "").strip()
    memo = (data.get("memo") or "").strip()

    if not txn_date:
        return ("Missing date", 400)
    if not receipt_id:
        return ("Missing receipt_id", 400)
    if not payment_type_id or not vendor_id or not vendor_item_id:
        return ("Missing payment_type_id/vendor_id/vendor_item_id", 400)

    try:
        amt = Decimal(amount_raw).quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError):
        return ("Invalid amount", 400)

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO transactions(
                      user_id, txn_date, payment_type_id, vendor_id, vendor_item_id,
                      amount, memo, receipt_id, is_receipt_total
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,FALSE)
                    RETURNING id
                    """,
                    (user_id, txn_date, payment_type_id, vendor_id, vendor_item_id,
                     str(amt), memo, receipt_id),
                )
                new_id = cur.fetchone()[0]
            conn.commit()
        return jsonify({"ok": True, "id": int(new_id)})
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute(
                """
                INSERT INTO transactions(
                  user_id, txn_date, payment_type_id, vendor_id, vendor_item_id,
                  amount, memo, receipt_id, is_receipt_total
                )
                VALUES (?,?,?,?,?,?,?,?,0)
                """,
                (user_id, txn_date, payment_type_id, vendor_id, vendor_item_id,
                 str(amt), memo, receipt_id),
            )
            con.commit()
            return jsonify({"ok": True, "id": int(cur.lastrowid)})


@app.delete("/api/txns/<int:txn_id>")
@require_login
def delete_txn(txn_id: int):
    user_id = int(session["user_id"])

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM transactions WHERE id=%s AND user_id=%s", (txn_id, user_id))
                deleted = cur.rowcount
            conn.commit()
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.execute("DELETE FROM transactions WHERE id=? AND user_id=?", (txn_id, user_id))
            deleted = cur.rowcount
            con.commit()

    return jsonify({"ok": True, "deleted": deleted})

@app.get("/export.csv")
@require_login
def export_csv():
    """Default: export only unexported rows (exported_at IS NULL).
       Use ?all=1 to export everything without marking exported_at.
    """
    user_id = int(session["user_id"])
    export_all = request.args.get("all", "0") == "1"
    export_time = utc_now_iso()

    header = [
        "id",
        "date",
        "payment_type",
        "vendor",
        "item",
        "amount",
        "memo",
        "receipt_id",
        "is_receipt_total",
        "exported_at",
    ]

    if using_postgres():
        # 1) fetch rows
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                if export_all:
                    cur.execute(
                        """
                        SELECT
                          t.id,
                          t.txn_date,
                          pt.name AS payment_type,
                          v.name AS vendor,
                          COALESCE(vi.name, 'TOTAL') AS item,
                          t.amount,
                          t.memo,
                          t.receipt_id,
                          t.is_receipt_total
                        FROM transactions t
                        JOIN payment_types pt ON pt.id = t.payment_type_id
                        JOIN vendors v ON v.id = t.vendor_id
                        LEFT JOIN vendor_items vi ON vi.id = t.vendor_item_id
                        WHERE t.user_id=%s
                        ORDER BY t.txn_date ASC, t.id ASC
                        """,
                        (user_id,),
                    )
                else:
                    cur.execute(
                        """
                        SELECT
                          t.id,
                          t.txn_date,
                          pt.name AS payment_type,
                          v.name AS vendor,
                          COALESCE(vi.name, 'TOTAL') AS item,
                          t.amount,
                          t.memo,
                          t.receipt_id,
                          t.is_receipt_total
                        FROM transactions t
                        JOIN payment_types pt ON pt.id = t.payment_type_id
                        JOIN vendors v ON v.id = t.vendor_id
                        LEFT JOIN vendor_items vi ON vi.id = t.vendor_item_id
                        WHERE t.user_id=%s AND t.exported_at IS NULL
                        ORDER BY t.txn_date ASC, t.id ASC
                        """,
                        (user_id,),
                    )
                rows = cur.fetchall()

        # 2) write CSV
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=header)
        writer.writeheader()

        export_ids = []
        for r in rows:
            export_ids.append(int(r[0]))
            writer.writerow({
                "id": int(r[0]),
                "date": r[1].isoformat(),
                "payment_type": r[2],
                "vendor": r[3],
                "item": r[4],
                "amount": str(r[5]),
                "memo": r[6],
                "receipt_id": r[7],
                "is_receipt_total": bool(r[8]),
                "exported_at": export_time,
            })

        csv_text = buf.getvalue()

        # 3) mark exported (unless export_all)
        if (not export_all) and export_ids:
            with psycopg.connect(DATABASE_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE transactions SET exported_at=%s WHERE user_id=%s AND id = ANY(%s)",
                        (export_time, user_id, export_ids),
                    )
                conn.commit()

    else:
        # SQLite
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.row_factory = sqlite3.Row

            if export_all:
                rows = con.execute(
                    """
                    SELECT
                      t.id,
                      t.txn_date AS date,
                      pt.name AS payment_type,
                      v.name AS vendor,
                      COALESCE(vi.name, 'TOTAL') AS item,
                      t.amount,
                      t.memo,
                      t.receipt_id,
                      t.is_receipt_total
                    FROM transactions t
                    JOIN payment_types pt ON pt.id = t.payment_type_id
                    JOIN vendors v ON v.id = t.vendor_id
                    LEFT JOIN vendor_items vi ON vi.id = t.vendor_item_id
                    WHERE t.user_id=?
                    ORDER BY t.txn_date ASC, t.id ASC
                    """,
                    (user_id,),
                ).fetchall()
            else:
                rows = con.execute(
                    """
                    SELECT
                      t.id,
                      t.txn_date AS date,
                      pt.name AS payment_type,
                      v.name AS vendor,
                      COALESCE(vi.name, 'TOTAL') AS item,
                      t.amount,
                      t.memo,
                      t.receipt_id,
                      t.is_receipt_total
                    FROM transactions t
                    JOIN payment_types pt ON pt.id = t.payment_type_id
                    JOIN vendors v ON v.id = t.vendor_id
                    LEFT JOIN vendor_items vi ON vi.id = t.vendor_item_id
                    WHERE t.user_id=? AND t.exported_at IS NULL
                    ORDER BY t.txn_date ASC, t.id ASC
                    """,
                    (user_id,),
                ).fetchall()

            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=header)
            writer.writeheader()

            export_ids = []
            for r in rows:
                export_ids.append(int(r["id"]))
                writer.writerow({
                    "id": int(r["id"]),
                    "date": r["date"],
                    "payment_type": r["payment_type"],
                    "vendor": r["vendor"],
                    "item": r["item"],
                    "amount": r["amount"],
                    "memo": r["memo"],
                    "receipt_id": r["receipt_id"],
                    "is_receipt_total": bool(r["is_receipt_total"]),
                    "exported_at": export_time,
                })

            csv_text = buf.getvalue()

            if (not export_all) and export_ids:
                placeholders = ",".join("?" for _ in export_ids)
                con.execute(
                    f"UPDATE transactions SET exported_at=? WHERE user_id=? AND id IN ({placeholders})",
                    (export_time, user_id, *export_ids),
                )
                con.commit()

    filename = f"checkbook_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.post("/api/receipt_total")
@require_login
def add_receipt_total():
    user_id = int(session["user_id"])
    data = request.get_json(force=True)

    txn_date = (data.get("date") or "").strip()
    receipt_id = (data.get("receipt_id") or "").strip()
    payment_type_id = data.get("payment_type_id")
    vendor_id = data.get("vendor_id")
    amount_raw = (data.get("amount") or "").strip()
    item_count = int(data.get("item_count") or 0)

    if not txn_date or not receipt_id or not payment_type_id or not vendor_id:
        return ("Missing required fields", 400)

    try:
        amt = Decimal(amount_raw).quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError):
        return ("Invalid amount", 400)

    memo = f"Receipt total (items: {item_count})"

    if using_postgres():
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO transactions(
                      user_id, txn_date, payment_type_id, vendor_id, vendor_item_id,
                      amount, memo, receipt_id, is_receipt_total
                    )
                    VALUES (%s,%s,%s,%s,NULL,%s,%s,%s,TRUE)
                    RETURNING id
                    """,
                    (user_id, txn_date, payment_type_id, vendor_id,
                     str(amt), memo, receipt_id),
                )
                new_id = cur.fetchone()[0]
            conn.commit()
        return jsonify({"ok": True, "id": int(new_id)})
    else:
        with sqlite3.connect(SQLITE_PATH) as con:
            con.execute("PRAGMA foreign_keys = ON;")
            cur = con.cursor()
            cur.execute(
                """
                INSERT INTO transactions(
                  user_id, txn_date, payment_type_id, vendor_id, vendor_item_id,
                  amount, memo, receipt_id, is_receipt_total
                )
                VALUES (?,?,?,?,NULL,?,?,?,1)
                """,
                (user_id, txn_date, payment_type_id, vendor_id,
                 str(amt), memo, receipt_id),
            )
            con.commit()
            return jsonify({"ok": True, "id": int(cur.lastrowid)})

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=not using_postgres())
