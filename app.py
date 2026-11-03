from __future__ import annotations

import os
import csv
import io
import struct
import zlib
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Callable, TypeVar, cast
from urllib.parse import urlparse

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup, escape
from werkzeug.security import check_password_hash, generate_password_hash

FACTIONS = ("Dominion", "Leshavult", "Shades", "Commonwealth")
MAX_UPGRADES_PER_CHARACTER = 2

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("MOONSTONE_DATABASE", BASE_DIR / "moonstone.db"))
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "dev-only-change-this-before-deploying"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_HTTPS", "0") == "1",
)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        DATABASE.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def is_valid_avatar_png(data: bytes) -> bool:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    offset = 8
    chunk_number = 0
    has_image_data = False
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        data_end = offset + 8 + length
        if data_end + 4 > len(data):
            return False
        chunk_data = data[offset + 8:data_end]
        expected_crc = struct.unpack(">I", data[data_end:data_end + 4])[0]
        if zlib.crc32(chunk_type + chunk_data) & 0xffffffff != expected_crc:
            return False
        if chunk_number == 0:
            if chunk_type != b"IHDR" or length != 13:
                return False
            width, height = struct.unpack(">II", chunk_data[:8])
            if width != 200 or height != 200:
                return False
        elif chunk_type == b"IHDR":
            return False
        if chunk_type == b"IDAT":
            has_image_data = True
        offset = data_end + 4
        chunk_number += 1
        if chunk_type == b"IEND":
            return length == 0 and has_image_data and offset == len(data)
    return False


def is_valid_https_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname:
            return False
        parsed.port  # Validate any explicitly supplied port.
        return True
    except ValueError:
        return False


@app.teardown_appcontext
def close_db(_error: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            is_active INTEGER NOT NULL DEFAULT 1,
            is_admin INTEGER NOT NULL DEFAULT 0,
            avatar_filename TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            rounds INTEGER NOT NULL CHECK(rounds BETWEEN 1 AND 20),
            allowed_players INTEGER,
            addition_mode TEXT NOT NULL DEFAULT 'either' CHECK(addition_mode IN ('either', 'both')),
            status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new', 'in_progress', 'closed')),
            current_round INTEGER NOT NULL DEFAULT 0,
            current_phase TEXT NOT NULL DEFAULT 'machinations' CHECK(current_phase IN ('machinations', 'duel', 'troupe_growth')),
            created_by INTEGER NOT NULL REFERENCES users(id),
            link_url TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS campaign_players (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            faction TEXT NOT NULL,
            joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'new',
            PRIMARY KEY (campaign_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS campaign_replacements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            replaced_user_id INTEGER REFERENCES users(id),
            new_user_id INTEGER NOT NULL REFERENCES users(id),
            effective_round INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS pairing_options (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            schedule_round INTEGER NOT NULL,
            player_one INTEGER NOT NULL REFERENCES users(id),
            player_two INTEGER REFERENCES users(id),
            PRIMARY KEY (campaign_id, schedule_round, player_one),
            CHECK (player_two IS NULL OR player_one < player_two)
        );
        CREATE TABLE IF NOT EXISTS campaign_pairings (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            round_number INTEGER NOT NULL,
            schedule_round INTEGER NOT NULL,
            PRIMARY KEY (campaign_id, round_number),
            UNIQUE (campaign_id, schedule_round)
        );
        CREATE TABLE IF NOT EXISTS machinations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            round_number INTEGER NOT NULL,
            actor_id INTEGER NOT NULL REFERENCES users(id),
            target_id INTEGER NOT NULL REFERENCES users(id),
            kind TEXT NOT NULL CHECK(kind IN ('sabotage', 'support')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (campaign_id, round_number, actor_id, target_id, kind)
        );
        CREATE TABLE IF NOT EXISTS machination_submissions (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            round_number INTEGER NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (campaign_id, round_number, user_id)
        );
        CREATE TABLE IF NOT EXISTS machination_results (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            round_number INTEGER NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id),
            campaign_cards INTEGER NOT NULL CHECK(campaign_cards BETWEEN 1 AND 3),
            machination_points INTEGER NOT NULL DEFAULT 0 CHECK(machination_points >= 0),
            PRIMARY KEY (campaign_id, round_number, user_id)
        );
        CREATE TABLE IF NOT EXISTS duel_card_uses (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            round_number INTEGER NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id),
            campaign_card_id INTEGER NOT NULL REFERENCES campaign_cards(id),
            PRIMARY KEY (campaign_id, round_number, user_id, campaign_card_id),
            UNIQUE (campaign_id, user_id, campaign_card_id)
        );
        CREATE TABLE IF NOT EXISTS duel_scores (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            round_number INTEGER NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id),
            moonstones INTEGER NOT NULL CHECK(moonstones BETWEEN 0 AND 999),
            victory_points INTEGER NOT NULL CHECK(victory_points BETWEEN 0 AND 999),
            submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (campaign_id, round_number, user_id)
        );
        CREATE TABLE IF NOT EXISTS duel_confirmations (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            round_number INTEGER NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id),
            confirmed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (campaign_id, round_number, user_id)
        );
        CREATE TABLE IF NOT EXISTS duel_match_overrides (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            round_number INTEGER NOT NULL,
            player_one INTEGER NOT NULL REFERENCES users(id),
            player_two INTEGER NOT NULL REFERENCES users(id),
            confirmed_by INTEGER NOT NULL REFERENCES users(id),
            confirmed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (campaign_id, round_number, player_one, player_two)
        );
        CREATE TABLE IF NOT EXISTS characters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            card_url TEXT NOT NULL DEFAULT '',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS character_factions (
            character_id INTEGER NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
            faction TEXT NOT NULL,
            PRIMARY KEY (character_id, faction)
        );
        CREATE TABLE IF NOT EXISTS upgrades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            image_url TEXT NOT NULL DEFAULT '',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS campaign_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            image_url TEXT NOT NULL DEFAULT '',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS campaign_card_factions (
            campaign_card_id INTEGER NOT NULL REFERENCES campaign_cards(id) ON DELETE CASCADE,
            faction TEXT NOT NULL,
            PRIMARY KEY (campaign_card_id, faction)
        );
        CREATE TABLE IF NOT EXISTS upgrade_factions (
            upgrade_id INTEGER NOT NULL REFERENCES upgrades(id) ON DELETE CASCADE,
            faction TEXT NOT NULL,
            PRIMARY KEY (upgrade_id, faction)
        );
        CREATE TABLE IF NOT EXISTS troupes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new', 'ready')),
            submitted_at TEXT,
            UNIQUE (campaign_id, user_id),
            FOREIGN KEY (campaign_id, user_id) REFERENCES campaign_players(campaign_id, user_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS troupe_characters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            troupe_id INTEGER NOT NULL REFERENCES troupes(id) ON DELETE CASCADE,
            character_id INTEGER NOT NULL REFERENCES characters(id),
            added_after_round INTEGER,
            UNIQUE (troupe_id, character_id)
        );
        CREATE TABLE IF NOT EXISTS character_upgrades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            troupe_character_id INTEGER NOT NULL REFERENCES troupe_characters(id) ON DELETE CASCADE,
            upgrade_id INTEGER NOT NULL REFERENCES upgrades(id),
            added_after_round INTEGER NOT NULL,
            UNIQUE (troupe_character_id, upgrade_id)
        );
    """)
    # Older builds limited a campaign card to one use across the whole campaign.
    # Rebuild that table so each player can use a card once independently.
    for index in db.execute("PRAGMA index_list(duel_card_uses)").fetchall():
        index_columns = [row["name"] for row in db.execute(f"PRAGMA index_info({index['name']})").fetchall()]
        if index["unique"] and index_columns == ["campaign_id", "campaign_card_id"]:
            db.execute("ALTER TABLE duel_card_uses RENAME TO duel_card_uses_old")
            db.execute("""CREATE TABLE duel_card_uses (
                campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                round_number INTEGER NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id),
                campaign_card_id INTEGER NOT NULL REFERENCES campaign_cards(id),
                PRIMARY KEY (campaign_id, round_number, user_id, campaign_card_id),
                UNIQUE (campaign_id, user_id, campaign_card_id)
            )""")
            db.execute("INSERT INTO duel_card_uses SELECT campaign_id, round_number, user_id, campaign_card_id FROM duel_card_uses_old")
            db.execute("DROP TABLE duel_card_uses_old")
            break
    # Add columns to databases created by the previous campaign-list version.
    migrations = {
        "users": {"status": "TEXT NOT NULL DEFAULT 'new'", "avatar_filename": "TEXT",
                  "is_active": "INTEGER NOT NULL DEFAULT 1", "is_admin": "INTEGER NOT NULL DEFAULT 0",
                  "is_superadmin": "INTEGER NOT NULL DEFAULT 0",
                  "can_manage_cards": "INTEGER NOT NULL DEFAULT 0"},
        "campaigns": {
            "current_round": "INTEGER NOT NULL DEFAULT 0",
            "current_phase": "TEXT NOT NULL DEFAULT 'machinations'",
            "allowed_players": "INTEGER",
            "addition_mode": "TEXT NOT NULL DEFAULT 'either'",
            "link_url": "TEXT NOT NULL DEFAULT ''",
        },
        "characters": {"is_active": "INTEGER NOT NULL DEFAULT 1"},
        "upgrades": {"image_url": "TEXT NOT NULL DEFAULT ''", "is_active": "INTEGER NOT NULL DEFAULT 1"},
        "campaign_cards": {"is_active": "INTEGER NOT NULL DEFAULT 1"},
        "campaign_players": {"status": "TEXT NOT NULL DEFAULT 'new'"},
    }
    for table, columns in migrations.items():
        present = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
        for name, declaration in columns.items():
            if name not in present:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
    player_columns = {row["name"] for row in db.execute("PRAGMA table_info(campaign_players)")}
    if "faction" not in player_columns:
        db.execute("ALTER TABLE campaign_players ADD COLUMN faction TEXT NOT NULL DEFAULT 'Dominion'")
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "faction" in user_columns:
            db.execute("UPDATE campaign_players SET faction = COALESCE((SELECT users.faction FROM users WHERE users.id = campaign_players.user_id), 'Dominion')")
    # A small starter catalogue. Players can add more entries with their card reference.
    db.execute("INSERT OR IGNORE INTO characters (name, card_url) VALUES (?, ?)",
               ("Muridae v3", "https://moonstonedb.8oni.com/character/muridae/"))
    muridae = db.execute("SELECT id FROM characters WHERE name = ?", ("Muridae v3",)).fetchone()["id"]
    db.executemany("INSERT OR IGNORE INTO character_factions (character_id, faction) VALUES (?, ?)",
                   [(muridae, "Commonwealth"), (muridae, "Dominion")])
    db.execute("INSERT OR IGNORE INTO characters (name, card_url) VALUES (?, ?)",
               ("Foxglove", "https://moonstonedb.8oni.com/character/foxglove/"))
    foxglove = db.execute("SELECT id FROM characters WHERE name = ?", ("Foxglove",)).fetchone()["id"]
    db.execute("INSERT OR IGNORE INTO character_factions (character_id, faction) VALUES (?, ?)",
               (foxglove, "Dominion"))
    db.commit()


@app.before_request
def load_user_and_initialize() -> None:
    init_db()
    user_id = session.get("user_id")
    g.user = get_db().execute("SELECT id, name, email, status, avatar_filename, is_active, is_admin, is_superadmin, can_manage_cards FROM users WHERE id = ?", (user_id,)).fetchone() if user_id else None
    if g.user and not g.user["is_active"]:
        session.pop("user_id", None)
        g.user = None
        flash("This account has been deactivated. Contact the Wizard Chamberlain.", "error")
    if request.method == "POST":
        token = session.get("csrf_token")
        submitted = request.form.get("csrf_token")
        if not token or not submitted or not secrets.compare_digest(token, submitted):
            abort(400, description="Your form expired. Please go back, refresh, and try again.")


@app.context_processor
def inject_template_values() -> dict[str, object]:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    def render_user_avatar(user):
        name = user["name"] if user else "?"
        filename = user["avatar_filename"] if user and "avatar_filename" in user.keys() else None
        if filename:
            inner = f'<img src="{escape(url_for("static", filename=filename))}" alt="">'
        else:
            inner = str(escape(name[:1].upper())) if name else "?"
        return Markup(f'<span class="user-avatar">{inner}</span>')
    return {"csrf_token": session["csrf_token"], "current_user": getattr(g, "user", None),
            "factions": FACTIONS, "user_avatar": render_user_avatar}


F = TypeVar("F", bound=Callable[..., object])
def login_required(view: F) -> F:
    @wraps(view)
    def wrapped(*args: object, **kwargs: object) -> object:
        if g.user is None:
            flash("Please sign in to continue.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return cast(F, wrapped)


@app.route("/")
def index():
    return redirect(url_for("campaigns") if g.user else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("campaigns"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or len(name) > 80:
            flash("Enter your name (up to 80 characters).", "error")
        elif not email or len(email) > 254 or "@" not in email:
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Choose a password with at least 8 characters.", "error")
        else:
            db = get_db()
            try:
                cur = db.execute("INSERT INTO users (name, email, password_hash, status) VALUES (?, ?, ?, 'new')",
                                 (name, email, generate_password_hash(password)))
                db.commit()
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")
            else:
                session.clear()
                session["user_id"] = cur.lastrowid
                session["csrf_token"] = secrets.token_urlsafe(32)
                flash("Registration complete. Your status is New until you submit a troupe.", "success")
                return redirect(url_for("campaigns"))
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("campaigns"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ? OR name = ? COLLATE NOCASE", (email, email)).fetchone()
        if user is None or not user["is_active"] or not check_password_hash(user["password_hash"], password):
            flash("Email or password is incorrect.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("campaigns"))
    return render_template("auth.html", mode="login")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


@app.route("/user-management", methods=["GET", "POST"])
@login_required
def user_management():
    db = get_db()
    account = db.execute("SELECT id, name, password_hash, avatar_filename FROM users WHERE id = ?",
                         (g.user["id"],)).fetchone()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "update_name":
            name = request.form.get("name", "").strip()
            if not name or len(name) > 80:
                flash("Enter a name up to 80 characters long.", "error")
            else:
                db.execute("UPDATE users SET name = ? WHERE id = ?", (name, g.user["id"]))
                db.commit()
                flash("Your name has been updated.", "success")
                return redirect(url_for("user_management"))
        elif action == "update_password":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if not check_password_hash(account["password_hash"], current_password):
                flash("Your current password is incorrect.", "error")
            elif len(new_password) < 8:
                flash("Choose a new password with at least 8 characters.", "error")
            elif new_password != confirm_password:
                flash("The new password and confirmation do not match.", "error")
            else:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                           (generate_password_hash(new_password), g.user["id"]))
                db.commit()
                flash("Your password has been changed.", "success")
                return redirect(url_for("user_management"))
        elif action == "update_avatar":
            upload = request.files.get("avatar")
            if not upload or not upload.filename:
                flash("Choose a 200×200 PNG image.", "error")
            else:
                data = upload.stream.read(2_000_001)
                if len(data) > 2_000_000:
                    flash("The avatar file must be 2 MB or smaller.", "error")
                elif not is_valid_avatar_png(data):
                    flash("Avatar must be a valid PNG image exactly 200×200 pixels.", "error")
                else:
                    relative_path = f"uploads/avatars/user_{g.user['id']}.png"
                    avatar_dir = BASE_DIR / "static" / "uploads" / "avatars"
                    avatar_dir.mkdir(parents=True, exist_ok=True)
                    avatar_path = BASE_DIR / "static" / relative_path
                    temporary_path = avatar_path.with_suffix(".tmp")
                    try:
                        temporary_path.write_bytes(data)
                        temporary_path.replace(avatar_path)
                        db.execute("UPDATE users SET avatar_filename = ? WHERE id = ?",
                                   (relative_path, g.user["id"]))
                        db.commit()
                        flash("Your avatar has been updated.", "success")
                        return redirect(url_for("user_management"))
                    except OSError:
                        if temporary_path.exists():
                            temporary_path.unlink()
                        flash("The avatar could not be saved. Please try again.", "error")
        else:
            abort(400)
    return render_template("user_management.html", account=account)


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def admin_users():
    if not g.user["is_superadmin"]:
        abort(403)
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action", "")
        try:
            user_id = int(request.form.get("user_id", "0"))
        except ValueError:
            user_id = 0
        target = db.execute("SELECT id, name, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            abort(404)
        if action == "save_permissions":
            is_admin = int(request.form.get("is_admin") == "1")
            can_manage_cards = int(request.form.get("can_manage_cards") == "1")
            if user_id == g.user["id"]:
                is_admin = 1
            db.execute("UPDATE users SET is_admin = ?, can_manage_cards = ? WHERE id = ?",
                       (is_admin, can_manage_cards, user_id))
            db.commit()
            flash(f"Access permissions saved for {target['name']}.", "success")
            return redirect(url_for("admin_users"))
        if action in ("deactivate", "reactivate"):
            if user_id == g.user["id"] and action == "deactivate":
                flash("You cannot deactivate your own administrator account.", "error")
            else:
                active = 0 if action == "deactivate" else 1
                db.execute("UPDATE users SET is_active = ? WHERE id = ?", (active, user_id))
                db.commit()
                flash(f"{target['name']} has been {'deactivated' if not active else 'reactivated'}.", "success")
                return redirect(url_for("admin_users"))
        elif action == "reset_password":
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if len(new_password) < 8:
                flash("A reset password must have at least 8 characters.", "error")
            elif new_password != confirm_password:
                flash("The reset password and confirmation do not match.", "error")
            else:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                           (generate_password_hash(new_password), user_id))
                db.commit()
                flash(f"Password reset for {target['name']}.", "success")
                return redirect(url_for("admin_users"))
        else:
            abort(400)

    users = db.execute("SELECT u.id, u.name, u.email, u.status, u.is_active, u.is_admin, u.is_superadmin, u.can_manage_cards, u.created_at, (SELECT COUNT(*) FROM campaign_players cp WHERE cp.user_id = u.id AND cp.status != 'replaced') AS campaign_count FROM users u ORDER BY u.is_superadmin DESC, u.is_admin DESC, u.name COLLATE NOCASE").fetchall()
    return render_template("admin_users.html", users=users)


@app.route("/campaigns")
@login_required
def campaigns():
    if "hide_closed" in request.args:
        session["hide_closed_campaigns"] = request.args.get("hide_closed") == "1"
    hide_closed = session.get("hide_closed_campaigns", False)
    my_campaigns = request.args.get("my_campaigns") == "1"
    db = get_db()
    rows = db.execute("""
        SELECT c.id, c.name, c.location, c.link_url, c.rounds, c.status, c.created_by, c.allowed_players,
               c.current_round, c.current_phase,
               chamberlain.name AS chamberlain,
               COUNT(cp.user_id) AS players,
               EXISTS(SELECT 1 FROM campaign_players mine
                      WHERE mine.campaign_id = c.id AND mine.user_id = ? AND mine.status != 'replaced') AS joined,
               (SELECT t.status FROM troupes t WHERE t.campaign_id = c.id AND t.user_id = ?) AS troupe_status
        FROM campaigns c
        JOIN users chamberlain ON chamberlain.id = c.created_by
        LEFT JOIN campaign_players cp ON cp.campaign_id = c.id AND cp.status != 'replaced'
        WHERE (? = 0 OR c.status != 'closed')
          AND (? = 0 OR EXISTS(SELECT 1 FROM campaign_players mine_filter
                               WHERE mine_filter.campaign_id = c.id
                                 AND mine_filter.user_id = ? AND mine_filter.status != 'replaced'))
        GROUP BY c.id
        ORDER BY CASE c.status WHEN 'new' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
                 c.created_at DESC, c.id DESC
    """, (g.user["id"], g.user["id"], int(not hide_closed), int(my_campaigns), g.user["id"])).fetchall()
    running_campaigns = db.execute(
        "SELECT COUNT(*) FROM campaigns WHERE status = 'in_progress'"
    ).fetchone()[0]
    faction_rows = db.execute("""
        SELECT cp.faction, COUNT(*) AS players
        FROM campaign_players cp JOIN campaigns c ON c.id = cp.campaign_id
        WHERE cp.status != 'replaced' AND c.status != 'closed'
        GROUP BY cp.faction
    """).fetchall()
    faction_counts = {faction: 0 for faction in FACTIONS}
    faction_counts.update({row["faction"]: row["players"] for row in faction_rows
                           if row["faction"] in faction_counts})
    faction_total = sum(faction_counts.values())
    top_characters = db.execute("""
        SELECT ch.name, COUNT(*) AS selections
        FROM troupe_characters tc
        JOIN characters ch ON ch.id = tc.character_id
        JOIN troupes t ON t.id = tc.troupe_id AND t.status = 'ready'
        JOIN campaign_players cp ON cp.campaign_id = t.campaign_id AND cp.user_id = t.user_id AND cp.status != 'replaced'
        JOIN campaigns c ON c.id = t.campaign_id AND c.status != 'closed'
        GROUP BY ch.id, ch.name
        ORDER BY selections DESC, ch.name COLLATE NOCASE
        LIMIT 5
    """).fetchall()
    return render_template("campaigns.html", campaigns=rows, hide_closed=hide_closed,
                           my_campaigns=my_campaigns, running_campaigns=running_campaigns,
                           faction_counts=faction_counts, faction_total=faction_total,
                           top_characters=top_characters)


def draw_round_robin(players: list[sqlite3.Row]) -> list[list[tuple[int, int | None]]]:
    """Return one complete round-robin schedule; a missing opponent is a BYE."""
    entrants = [player["id"] for player in players]
    secrets.SystemRandom().shuffle(entrants)
    if len(entrants) % 2:
        entrants.append(None)
    if len(entrants) < 2:
        return []
    schedule: list[list[tuple[int, int | None]]] = []
    for _ in range(len(entrants) - 1):
        matches = []
        for index in range(len(entrants) // 2):
            left, right = entrants[index], entrants[-1 - index]
            if left is None:
                matches.append((right, None))
            elif right is None:
                matches.append((left, None))
            else:
                matches.append((min(left, right), max(left, right)))
        schedule.append(matches)
        entrants = [entrants[0], entrants[-1], *entrants[1:-1]]
    return schedule


def record_campaign_card_counts(db: sqlite3.Connection, campaign_id: int, round_number: int) -> None:
    db.execute("DELETE FROM machination_results WHERE campaign_id = ? AND round_number = ?",
               (campaign_id, round_number))
    players = db.execute("SELECT user_id FROM campaign_players WHERE campaign_id = ? AND status != 'replaced'", (campaign_id,)).fetchall()
    for player in players:
        if round_number == 1:
            sabotage_count = support_count = 0
        else:
            counts = db.execute("SELECT SUM(CASE WHEN kind = 'sabotage' THEN 1 ELSE 0 END), SUM(CASE WHEN kind = 'support' THEN 1 ELSE 0 END) FROM machinations WHERE campaign_id = ? AND round_number = ? AND target_id = ?",
                                (campaign_id, round_number, player["user_id"])).fetchone()
            sabotage_count, support_count = counts[0] or 0, counts[1] or 0
        unbounded_count = 2 - sabotage_count + support_count
        campaign_cards = min(3, max(1, unbounded_count))
        machination_points = max(0, unbounded_count - 3)
        db.execute("INSERT INTO machination_results (campaign_id, round_number, user_id, campaign_cards, machination_points) VALUES (?, ?, ?, ?, ?)",
                   (campaign_id, round_number, player["user_id"], campaign_cards, machination_points))


def machination_points_for(kind: str, tier: str, outcome: str) -> int:
    if outcome not in ("won", "lost"):
        return 0
    if kind == "support":
        return 1 if outcome == "won" else {"top": -2, "middle": -1, "bottom": 0}[tier]
    if outcome == "won":
        return {"top": 0, "middle": -1, "bottom": -1}[tier]
    return {"top": 1, "middle": 1, "bottom": 0}[tier]


def campaign_active_player_ids(db: sqlite3.Connection, campaign_id: int, round_number: int) -> set[int]:
    active = {row["user_id"] for row in db.execute(
        "SELECT user_id FROM campaign_players WHERE campaign_id = ?", (campaign_id,))}
    events = db.execute("SELECT replaced_user_id, new_user_id, effective_round FROM campaign_replacements WHERE campaign_id = ? ORDER BY effective_round, id",
                        (campaign_id,)).fetchall()
    for event in events:
        if round_number < event["effective_round"]:
            active.discard(event["new_user_id"])
        else:
            if event["replaced_user_id"] is not None:
                active.discard(event["replaced_user_id"])
            active.add(event["new_user_id"])
    return active


def campaign_leaderboard(db: sqlite3.Connection, campaign_id: int, through_round: int,
                         tier_round: int | None = None) -> list[dict]:
    players = db.execute("SELECT u.id, u.name, cp.faction FROM campaign_players cp JOIN users u ON u.id = cp.user_id WHERE cp.campaign_id = ? ORDER BY u.name COLLATE NOCASE",
                         (campaign_id,)).fetchall()
    standings = {player["id"]: {"user_id": player["id"], "name": player["name"], "stones": 0,
                                 "faction": player["faction"],
                                 "campaign_points": 0, "machination_points": 0,
                                 "wins": 0, "draws": 0, "losses": 0}
                 for player in players}

    def tier_map(at_round: int) -> dict[int, str]:
        active_ids = campaign_active_player_ids(db, campaign_id, at_round)
        ordered = sorted((row for row in standings.values() if row["user_id"] in active_ids), key=lambda row: (-(row["stones"] + row["campaign_points"] + row["machination_points"]), row["name"].casefold()))
        count = len(ordered)
        top_count = (count + 2) // 3
        middle_count = (count - top_count + 1) // 2
        tiers = {}
        for index, row in enumerate(ordered):
            tiers[row["user_id"]] = "top" if index < top_count else "middle" if index < top_count + middle_count else "bottom"
        return tiers

    for round_number in range(1, through_round + 1):
        tiers_at_start = tier_map(round_number)
        active_ids = campaign_active_player_ids(db, campaign_id, round_number)
        round_scores: dict[int, tuple[int, int]] = {}
        match_outcomes: dict[int, str] = {}
        bye_players = []
        matches = db.execute("SELECT po.player_one, po.player_two FROM campaign_pairings cp JOIN pairing_options po ON po.campaign_id = cp.campaign_id AND po.schedule_round = cp.schedule_round WHERE cp.campaign_id = ? AND cp.round_number = ?",
                             (campaign_id, round_number)).fetchall()
        for match in matches:
            player_one, player_two = match["player_one"], match["player_two"]
            if player_two is None:
                bye_players.append(player_one)
                continue
            scores = db.execute("SELECT user_id, moonstones, victory_points FROM duel_scores WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                                (campaign_id, round_number, player_one, player_two)).fetchall()
            by_user = {score["user_id"]: score for score in scores}
            if len(by_user) != 2 or not duel_result_confirmed(db, campaign_id, round_number, match):
                continue
            first, second = by_user[player_one], by_user[player_two]
            first_vp = first["moonstones"] + first["victory_points"]
            second_vp = second["moonstones"] + second["victory_points"]
            for score in (first, second):
                user_id = score["user_id"]
                stones, campaign_points = score["moonstones"], score["victory_points"]
                standings[user_id]["stones"] += stones
                standings[user_id]["campaign_points"] += campaign_points
                round_scores[user_id] = (stones, campaign_points)
            if first_vp > second_vp:
                match_outcomes[player_one], match_outcomes[player_two] = "won", "lost"
                standings[player_one]["wins"] += 1
                standings[player_two]["losses"] += 1
            elif second_vp > first_vp:
                match_outcomes[player_two], match_outcomes[player_one] = "won", "lost"
                standings[player_two]["wins"] += 1
                standings[player_one]["losses"] += 1
            else:
                standings[player_one]["draws"] += 1
                standings[player_two]["draws"] += 1

        # A BYE awards the rounded-up average VP of all other players for this round.
        for user_id in bye_players:
            denominator = len(active_ids) - 1
            if denominator > 0:
                virtual_points = sum(stones + points for other_id, (stones, points) in round_scores.items()
                                     if other_id != user_id and other_id in active_ids)
                bye_stones = (virtual_points + denominator - 1) // denominator
            else:
                bye_stones = 0
            standings[user_id]["stones"] += bye_stones

        # Excess support is awarded to the player who received it, as before.
        for result in db.execute("SELECT user_id, machination_points FROM machination_results WHERE campaign_id = ? AND round_number = ?",
                                 (campaign_id, round_number)):
            standings[result["user_id"]]["machination_points"] += result["machination_points"]

        for action in db.execute("SELECT actor_id, target_id, kind FROM machinations WHERE campaign_id = ? AND round_number = ?",
                                 (campaign_id, round_number)):
            outcome = match_outcomes.get(action["target_id"])
            if outcome is None:
                continue
            tier = tiers_at_start.get(action["target_id"], "bottom")
            standings[action["actor_id"]]["machination_points"] += machination_points_for(action["kind"], tier, outcome)

    tier_at = tier_round if tier_round is not None else max(1, through_round)
    final_tiers = tier_map(tier_at)
    ordered = sorted(standings.values(), key=lambda row: (0 if row["user_id"] in final_tiers else 1,
                                                           {"top": 0, "middle": 1, "bottom": 2}.get(final_tiers.get(row["user_id"]), 3),
                                                           -(row["stones"] + row["campaign_points"] + row["machination_points"]),
                                                           row["name"].casefold()))
    active_rows = [row for row in ordered if row["user_id"] in final_tiers]
    count = len(active_rows)
    top_count = (count + 2) // 3
    middle_count = (count - top_count + 1) // 2
    index_by_id = {row["user_id"]: index for index, row in enumerate(active_rows)}
    for row in ordered:
        row["victory_points"] = row["stones"] + row["campaign_points"]
        row["power"] = row["victory_points"] + row["machination_points"]
        if row["user_id"] in final_tiers:
            index = index_by_id[row["user_id"]]
            row["tier"] = "Top" if index < top_count else "Middle" if index < top_count + middle_count else "Bottom"
        else:
            row["tier"] = "Former" if db.execute("SELECT 1 FROM campaign_replacements WHERE campaign_id = ? AND replaced_user_id = ? AND effective_round <= ? LIMIT 1",
                                                  (campaign_id, row["user_id"], tier_at)).fetchone() else "Joining"
    return ordered


def current_match(db: sqlite3.Connection, campaign_id: int, round_number: int, user_id: int):
    return db.execute("SELECT po.player_one, po.player_two FROM campaign_pairings cp JOIN pairing_options po ON po.campaign_id = cp.campaign_id AND po.schedule_round = cp.schedule_round WHERE cp.campaign_id = ? AND cp.round_number = ? AND (po.player_one = ? OR po.player_two = ?)",
                      (campaign_id, round_number, user_id, user_id)).fetchone()


def duel_phase_complete(db: sqlite3.Connection, campaign_id: int, round_number: int) -> bool:
    matches = db.execute("SELECT po.player_one, po.player_two FROM campaign_pairings cp JOIN pairing_options po ON po.campaign_id = cp.campaign_id AND po.schedule_round = cp.schedule_round WHERE cp.campaign_id = ? AND cp.round_number = ?",
                         (campaign_id, round_number)).fetchall()
    for match in matches:
        if match["player_two"] is None:
            continue
        users = (match["player_one"], match["player_two"])
        for user_id in users:
            allowance = db.execute("SELECT campaign_cards FROM machination_results WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                                   (campaign_id, round_number, user_id)).fetchone()
            selected = db.execute("SELECT COUNT(*) FROM duel_card_uses WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                                  (campaign_id, round_number, user_id)).fetchone()[0]
            score = db.execute("SELECT 1 FROM duel_scores WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                               (campaign_id, round_number, user_id)).fetchone()
            if not allowance or selected != allowance["campaign_cards"] or not score:
                return False
        confirmed = db.execute("SELECT COUNT(*) FROM duel_confirmations WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                               (campaign_id, round_number, *users)).fetchone()[0]
        admin_confirmed = db.execute("SELECT 1 FROM duel_match_overrides WHERE campaign_id = ? AND round_number = ? AND player_one = ? AND player_two = ?",
                                     (campaign_id, round_number, *users)).fetchone()
        if confirmed < 2 and not admin_confirmed:
            return False
    return bool(matches)


def match_cards_complete(db: sqlite3.Connection, campaign_id: int, round_number: int,
                         players: tuple[int, int]) -> bool:
    for user_id in players:
        allowance = db.execute("SELECT campaign_cards FROM machination_results WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                               (campaign_id, round_number, user_id)).fetchone()
        selected = db.execute("SELECT COUNT(*) FROM duel_card_uses WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                              (campaign_id, round_number, user_id)).fetchone()[0]
        if not allowance or selected != allowance["campaign_cards"]:
            return False
    return True


def duel_result_confirmed(db: sqlite3.Connection, campaign_id: int, round_number: int,
                          match: sqlite3.Row | None) -> bool:
    if not match or match["player_two"] is None:
        return False
    if db.execute("SELECT 1 FROM duel_match_overrides WHERE campaign_id = ? AND round_number = ? AND player_one = ? AND player_two = ?",
                  (campaign_id, round_number, match["player_one"], match["player_two"])).fetchone():
        return True
    return db.execute("SELECT COUNT(*) FROM duel_confirmations WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                      (campaign_id, round_number, match["player_one"], match["player_two"])).fetchone()[0] >= 2


def round_has_confirmed_duel(db: sqlite3.Connection, campaign_id: int, round_number: int) -> bool:
    matches = db.execute("SELECT po.player_one, po.player_two FROM campaign_pairings cp JOIN pairing_options po ON po.campaign_id = cp.campaign_id AND po.schedule_round = cp.schedule_round WHERE cp.campaign_id = ? AND cp.round_number = ?",
                         (campaign_id, round_number)).fetchall()
    return any(duel_result_confirmed(db, campaign_id, round_number, match) for match in matches)


@app.route("/campaigns/<int:campaign_id>/pairings", methods=["GET", "POST"])
@login_required
def configure_pairings(campaign_id: int):
    db = get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if campaign is None:
        abort(404)
    if campaign["created_by"] != g.user["id"]:
        abort(403)
    if campaign["status"] != "new":
        flash("Pairings can only be configured before the campaign starts.", "error")
        return redirect(url_for("troupe", campaign_id=campaign_id))

    players = db.execute("SELECT u.id, u.name FROM campaign_players cp JOIN users u ON u.id = cp.user_id WHERE cp.campaign_id = ? ORDER BY u.name COLLATE NOCASE",
                         (campaign_id,)).fetchall()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "draw":
            schedule = draw_round_robin(players)
            db.execute("DELETE FROM campaign_pairings WHERE campaign_id = ?", (campaign_id,))
            db.execute("DELETE FROM pairing_options WHERE campaign_id = ?", (campaign_id,))
            for round_index, matches in enumerate(schedule, start=1):
                db.executemany("INSERT INTO pairing_options (campaign_id, schedule_round, player_one, player_two) VALUES (?, ?, ?, ?)",
                               [(campaign_id, round_index, one, two) for one, two in matches])
            db.commit()
            if not schedule:
                flash("At least one player must join before pairings can be drawn.", "error")
            elif campaign["rounds"] > len(schedule):
                flash(f"This player count supports at most {len(schedule)} round-robin rounds without repeat opponents; this campaign has {campaign['rounds']} rounds.", "error")
            else:
                flash(f"Drew a round-robin schedule with {len(schedule)} possible rounds. Choose one distinct pairing set for each campaign round.", "success")
            return redirect(url_for("configure_pairings", campaign_id=campaign_id))
        elif action == "save":
            option_rounds = [request.form.get(f"round_{round_number}", "") for round_number in range(1, campaign["rounds"] + 1)]
            try:
                selected = [int(value) for value in option_rounds]
            except ValueError:
                selected = []
            available = {row[0] for row in db.execute("SELECT DISTINCT schedule_round FROM pairing_options WHERE campaign_id = ?", (campaign_id,))}
            if len(selected) != campaign["rounds"] or len(set(selected)) != len(selected) or any(value not in available for value in selected):
                flash("Choose a different valid pairing set for every campaign round.", "error")
            elif not players:
                flash("At least one player must join before pairings can be saved.", "error")
            else:
                db.execute("DELETE FROM campaign_pairings WHERE campaign_id = ?", (campaign_id,))
                db.executemany("INSERT INTO campaign_pairings (campaign_id, round_number, schedule_round) VALUES (?, ?, ?)",
                               [(campaign_id, round_number, schedule_round) for round_number, schedule_round in enumerate(selected, start=1)])
                db.commit()
                flash("Round pairings saved. The campaign is ready to start once all players submit their troupes.", "success")
                return redirect(url_for("configure_pairings", campaign_id=campaign_id))
        else:
            abort(400)

    options = db.execute("SELECT po.schedule_round, po.player_one, po.player_two, u1.name AS player_one_name, u2.name AS player_two_name FROM pairing_options po JOIN users u1 ON u1.id = po.player_one LEFT JOIN users u2 ON u2.id = po.player_two WHERE po.campaign_id = ? ORDER BY po.schedule_round, u1.name COLLATE NOCASE",
                         (campaign_id,)).fetchall()
    by_round: dict[int, list[sqlite3.Row]] = {}
    for option in options:
        by_round.setdefault(option["schedule_round"], []).append(option)
    selected_rounds = {row["round_number"]: row["schedule_round"] for row in db.execute("SELECT round_number, schedule_round FROM campaign_pairings WHERE campaign_id = ?", (campaign_id,))}
    max_rounds = max(by_round, default=0)
    return render_template("pairings.html", campaign=campaign, players=players, by_round=by_round,
                           max_rounds=max_rounds, selected_rounds=selected_rounds)


@app.route("/campaigns/<int:campaign_id>/players")
@login_required
def campaign_players(campaign_id: int):
    db = get_db()
    campaign = db.execute("SELECT id, name, location, created_by, status FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if campaign is None:
        abort(404)
    players = db.execute("""
        SELECT u.id, u.name, cp.faction, cp.status AS membership_status,
               t.status AS troupe_status, COUNT(tc.id) AS character_count
        FROM campaign_players cp
        JOIN users u ON u.id = cp.user_id
        LEFT JOIN troupes t ON t.campaign_id = cp.campaign_id AND t.user_id = cp.user_id
        LEFT JOIN troupe_characters tc ON tc.troupe_id = t.id
        WHERE cp.campaign_id = ? AND cp.status != 'replaced'
        GROUP BY u.id, u.name, cp.faction, cp.status, t.status
        ORDER BY u.name COLLATE NOCASE
    """, (campaign_id,)).fetchall()
    return render_template("campaign_players.html", campaign=campaign, players=players,
                           is_creator=campaign["created_by"] == g.user["id"])


@app.post("/campaigns/<int:campaign_id>/players/<int:player_id>/withdraw")
@login_required
def withdraw_campaign_player(campaign_id: int, player_id: int):
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    campaign = db.execute("SELECT status, created_by FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if campaign is None:
        db.rollback()
        abort(404)
    if player_id != g.user["id"] and campaign["created_by"] != g.user["id"]:
        db.rollback()
        abort(403)
    if campaign["status"] != "new":
        db.rollback()
        flash("Players can only be withdrawn before the campaign starts.", "error")
    else:
        membership = db.execute("SELECT 1 FROM campaign_players WHERE campaign_id = ? AND user_id = ?",
                                (campaign_id, player_id)).fetchone()
        if not membership:
            db.rollback()
            abort(404)
        db.execute("DELETE FROM campaign_players WHERE campaign_id = ? AND user_id = ?",
                   (campaign_id, player_id))
        db.execute("DELETE FROM campaign_pairings WHERE campaign_id = ?", (campaign_id,))
        db.execute("DELETE FROM pairing_options WHERE campaign_id = ?", (campaign_id,))
        db.commit()
        if player_id == g.user["id"]:
            flash("You withdrew from the campaign.", "success")
            return redirect(url_for("campaigns"))
        flash("Player withdrawn from the campaign.", "success")
    return redirect(url_for("campaign_players", campaign_id=campaign_id))


@app.route("/campaigns/<int:campaign_id>/players/<int:player_id>")
@login_required
def player_details(campaign_id: int, player_id: int):
    db = get_db()
    campaign = db.execute("SELECT id, name, location FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if campaign is None:
        abort(404)
    player = db.execute("""
        SELECT u.id, u.name, cp.faction, cp.status AS membership_status, t.id AS troupe_id,
               t.status AS troupe_status
        FROM campaign_players cp
        JOIN users u ON u.id = cp.user_id
        LEFT JOIN troupes t ON t.campaign_id = cp.campaign_id AND t.user_id = cp.user_id
        WHERE cp.campaign_id = ? AND cp.user_id = ?
    """, (campaign_id, player_id)).fetchone()
    if player is None:
        abort(404)
    roster = []
    if player["troupe_id"]:
        roster = db.execute("""
            SELECT tc.id AS troupe_character_id, tc.added_after_round, c.name, c.card_url,
                   (SELECT group_concat(cf.faction, ', ') FROM character_factions cf WHERE cf.character_id = c.id) AS factions
            FROM troupe_characters tc
            JOIN characters c ON c.id = tc.character_id
            WHERE tc.troupe_id = ?
            ORDER BY tc.added_after_round IS NOT NULL, tc.id
        """, (player["troupe_id"],)).fetchall()
        upgrades = db.execute("""
            SELECT cu.troupe_character_id, u.name, u.image_url
            FROM character_upgrades cu
            JOIN upgrades u ON u.id = cu.upgrade_id
            JOIN troupe_characters tc ON tc.id = cu.troupe_character_id
            WHERE tc.troupe_id = ?
            ORDER BY cu.id
        """, (player["troupe_id"],)).fetchall()
        upgrade_map: dict[int, list[sqlite3.Row]] = {}
        for upgrade in upgrades:
            upgrade_map.setdefault(upgrade["troupe_character_id"], []).append(upgrade)
        roster = [dict(character) for character in roster]
        for character in roster:
            character["upgrades"] = upgrade_map.get(character["troupe_character_id"], [])
    card_history = db.execute("SELECT cc.name AS card_name, dcu.round_number FROM duel_card_uses dcu JOIN campaign_cards cc ON cc.id = dcu.campaign_card_id WHERE dcu.campaign_id = ? AND dcu.user_id = ? ORDER BY dcu.round_number, cc.name COLLATE NOCASE",
                              (campaign_id, player_id)).fetchall()
    return render_template("player_details.html", campaign=campaign, player=player, roster=roster,
                           card_history=card_history)


@app.route("/campaigns/new", methods=["GET", "POST"])
@login_required
def new_campaign():
    db = get_db()
    created_campaigns = db.execute(
        "SELECT COUNT(*) FROM campaigns WHERE created_by = ? AND status != 'closed'",
        (g.user["id"],)
    ).fetchone()[0]
    if created_campaigns >= 3:
        flash("You cannot create a new campaign because you already have three active campaigns.", "error")
        return redirect(url_for("campaigns"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        location = request.form.get("location", "").strip()
        link_url = request.form.get("link_url", "").strip()
        rounds_raw = request.form.get("rounds", "").strip()
        try:
            rounds = int(rounds_raw)
        except ValueError:
            rounds = 0
        allowed_raw = request.form.get("allowed_players", "").strip()
        try:
            allowed_players = int(allowed_raw) if allowed_raw else None
        except ValueError:
            allowed_players = 0
        if not name or len(name) > 100:
            flash("Enter a campaign name (up to 100 characters).", "error")
        elif not location or len(location) > 120:
            flash("Enter a location (up to 120 characters).", "error")
        elif link_url and (len(link_url) > 500 or not is_valid_https_url(link_url)):
            flash("Enter a valid HTTPS campaign link, or leave the field blank.", "error")
        elif not 1 <= rounds <= 20:
            flash("Rounds must be between 1 and 20.", "error")
        elif allowed_players is not None and not 1 <= allowed_players <= 100:
            flash("Player limit must be between 1 and 100, or left blank for no limit.", "error")
        else:
            cur = db.execute("INSERT INTO campaigns (name, location, link_url, rounds, allowed_players, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                             (name, location, link_url, rounds, allowed_players, g.user["id"]))
            db.commit()
            flash("Campaign created. Join it and choose your faction to sign up.", "success")
            return redirect(url_for("campaigns"))
    return render_template("new_campaign.html")


@app.route("/campaigns/<int:campaign_id>/join", methods=["GET", "POST"])
@login_required
def join_campaign(campaign_id: int):
    db = get_db()
    campaign = db.execute("SELECT id, status, allowed_players FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if campaign is None:
        abort(404)
    if db.execute("SELECT 1 FROM campaign_players WHERE campaign_id = ? AND user_id = ?",
                  (campaign_id, g.user["id"])).fetchone():
        return redirect(url_for("troupe", campaign_id=campaign_id))
    if campaign["status"] != "new":
        flash("This campaign is no longer accepting players.", "error")
        return redirect(url_for("campaigns"))
    signed_up = db.execute("SELECT COUNT(*) FROM campaign_players WHERE campaign_id = ?", (campaign_id,)).fetchone()[0]
    if campaign["allowed_players"] is not None and signed_up >= campaign["allowed_players"]:
        flash("This campaign has reached its player limit.", "error")
        return redirect(url_for("campaigns"))
    if request.method == "POST":
        faction = request.form.get("faction", "")
        if faction not in FACTIONS:
            flash("Choose a faction to join this campaign.", "error")
        else:
            db.execute("BEGIN IMMEDIATE")
            campaign = db.execute("SELECT status, allowed_players FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
            players = db.execute("SELECT COUNT(*) FROM campaign_players WHERE campaign_id = ?", (campaign_id,)).fetchone()[0]
            if campaign["status"] != "new":
                db.rollback()
                flash("This campaign is no longer accepting players.", "error")
                return redirect(url_for("campaigns"))
            if campaign["allowed_players"] is not None and players >= campaign["allowed_players"]:
                db.rollback()
                flash("This campaign has reached its player limit.", "error")
                return redirect(url_for("campaigns"))
            if db.execute("SELECT 1 FROM campaign_players WHERE campaign_id = ? AND user_id = ?",
                          (campaign_id, g.user["id"])).fetchone():
                db.rollback()
                return redirect(url_for("troupe", campaign_id=campaign_id))
            db.execute("INSERT INTO campaign_players (campaign_id, user_id, faction) VALUES (?, ?, ?)",
                       (campaign_id, g.user["id"], faction))
            db.execute("DELETE FROM campaign_pairings WHERE campaign_id = ?", (campaign_id,))
            db.execute("DELETE FROM pairing_options WHERE campaign_id = ?", (campaign_id,))
            db.commit()
            flash(f"You joined the campaign as {faction}.", "success")
            return redirect(url_for("troupe", campaign_id=campaign_id))
    return render_template("join_campaign.html", campaign=campaign)


@app.route("/cards", methods=["GET", "POST"])
@login_required
def manage_cards():
    db = get_db()
    if request.method == "POST":
        if not g.user["can_manage_cards"]:
            abort(403)
        action = request.form.get("action", "")
        card_type = request.form.get("card_type", "")
        try:
            card_id = int(request.form.get("card_id", "0"))
        except ValueError:
            card_id = 0

        if action == "import_csv":
            upload = request.files.get("csv_file")
            if not upload or not upload.filename:
                flash("Choose a CSV file to import.", "error")
                return redirect(url_for("manage_cards"))
            raw_csv = upload.stream.read(1_000_001)
            if len(raw_csv) > 1_000_000:
                flash("The CSV file must be smaller than 1 MB.", "error")
                return redirect(url_for("manage_cards"))
            try:
                text = raw_csv.decode("utf-8-sig")
                reader = csv.DictReader(io.StringIO(text, newline=""))
                headers = {str(header or "").strip().lower() for header in (reader.fieldnames or [])}
                required_headers = {"type", "name", "faction", "card_url", "image_url"}
                if not required_headers.issubset(headers):
                    raise ValueError("CSV headers must include type, name, faction, card_url, and image_url.")
                type_aliases = {"character": "character", "upgrade": "upgrade",
                                "campaign": "campaign", "campaign_card": "campaign",
                                "campaign card": "campaign"}
                grouped: dict[tuple[str, str], dict] = {}
                errors = []
                row_count = 0
                for line_number, row in enumerate(reader, start=2):
                    if not any(str(value or "").strip() for value in row.values()):
                        continue
                    row_count += 1
                    if row_count > 1000:
                        errors.append("A CSV import can contain no more than 1,000 non-empty rows.")
                        break
                    values = {str(key or "").strip().lower(): str(value or "").strip()
                              for key, value in row.items() if key is not None}
                    card_type = type_aliases.get(values.get("type", "").lower())
                    name = values.get("name", "")
                    faction = values.get("faction", "")
                    card_url = values.get("card_url", "")
                    image_url = values.get("image_url", "")
                    if card_type == "character":
                        image_url = card_url or image_url
                    else:
                        image_url = image_url or card_url
                    if not card_type:
                        errors.append(f"Row {line_number}: type must be character, upgrade, or campaign_card.")
                    if not name or len(name) > 100:
                        errors.append(f"Row {line_number}: card name is required and must be 100 characters or fewer.")
                    if faction not in FACTIONS:
                        errors.append(f"Row {line_number}: choose one of the supported factions.")
                    if (card_url and not card_url.startswith("https://")) or (values.get("image_url", "") and not values["image_url"].startswith("https://")):
                        errors.append(f"Row {line_number}: card_url and image_url must be blank or start with https://.")
                    if card_url and values.get("image_url", "") and card_url != values["image_url"]:
                        errors.append(f"Row {line_number}: use only the URL column for that card type, or keep both URL values identical.")
                    if (not card_type or not name or len(name) > 100 or faction not in FACTIONS
                            or (card_url and not card_url.startswith("https://"))
                            or (values.get("image_url", "") and not values["image_url"].startswith("https://"))
                            or (card_url and values.get("image_url", "") and card_url != values["image_url"])):
                        continue
                    key = (card_type, name.casefold())
                    item = grouped.setdefault(key, {"type": card_type, "name": name,
                                                    "image_url": "", "factions": set()})
                    if item["image_url"] and image_url and item["image_url"] != image_url:
                        errors.append(f"Row {line_number}: repeated rows for {name} must use the same image_url.")
                    elif image_url:
                        item["image_url"] = image_url
                    item["factions"].add(faction)
                if not row_count:
                    errors.append("The CSV has a header but no card rows.")
                if errors:
                    for error in dict.fromkeys(errors[:8]):
                        flash(error, "error")
                    if len(errors) > 8:
                        flash(f"There are {len(errors) - 8} more CSV errors.", "error")
                    return redirect(url_for("manage_cards"))
            except (UnicodeDecodeError, csv.Error, ValueError) as error:
                flash(str(error) or "The CSV file could not be read. Save it as UTF-8 CSV and try again.", "error")
                return redirect(url_for("manage_cards"))

            created = updated = added_factions = 0
            try:
                db.execute("BEGIN IMMEDIATE")
                for item in grouped.values():
                    card_type = item["type"]
                    table = {"character": "characters", "upgrade": "upgrades",
                             "campaign": "campaign_cards"}[card_type]
                    url_column = "card_url" if card_type == "character" else "image_url"
                    existing = db.execute(f"SELECT id, {url_column} FROM {table} WHERE name = ? COLLATE NOCASE",
                                          (item["name"],)).fetchone()
                    if existing:
                        card_id = existing["id"]
                        if item["image_url"] and existing[url_column] != item["image_url"]:
                            db.execute(f"UPDATE {table} SET {url_column} = ? WHERE id = ?",
                                       (item["image_url"], card_id))
                            updated += 1
                    else:
                        cur = db.execute(f"INSERT INTO {table} (name, {url_column}, created_by) VALUES (?, ?, ?)",
                                         (item["name"], item["image_url"], g.user["id"]))
                        card_id = cur.lastrowid
                        created += 1
                    relation_table, relation_id = {
                        "character": ("character_factions", "character_id"),
                        "upgrade": ("upgrade_factions", "upgrade_id"),
                        "campaign": ("campaign_card_factions", "campaign_card_id"),
                    }[card_type]
                    for faction in item["factions"]:
                        cur = db.execute(f"INSERT OR IGNORE INTO {relation_table} ({relation_id}, faction) VALUES (?, ?)",
                                         (card_id, faction))
                        added_factions += cur.rowcount
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                flash("The CSV import could not be applied because a card conflicts with the catalogue.", "error")
                return redirect(url_for("manage_cards"))
            flash(f"CSV import complete: {created} new cards, {added_factions} faction assignments added, {updated} image URLs updated.", "success")
            return redirect(url_for("manage_cards"))

        if action == "delete":
            if card_id < 1:
                abort(404)
            if card_type == "character":
                used = db.execute("SELECT 1 FROM troupe_characters WHERE character_id = ? LIMIT 1", (card_id,)).fetchone()
                table, related = "characters", ("character_factions", "character_id")
            elif card_type == "upgrade":
                used = db.execute("SELECT 1 FROM character_upgrades WHERE upgrade_id = ? LIMIT 1", (card_id,)).fetchone()
                table, related = "upgrades", ("upgrade_factions", "upgrade_id")
            elif card_type == "campaign":
                used = db.execute("SELECT 1 FROM duel_card_uses WHERE campaign_card_id = ? LIMIT 1", (card_id,)).fetchone()
                table, related = "campaign_cards", None
            else:
                abort(400)
            if used:
                flash("This card is already used in a campaign or troupe and cannot be deleted. Mark it inactive instead.", "error")
            else:
                if related:
                    db.execute(f"DELETE FROM {related[0]} WHERE {related[1]} = ?", (card_id,))
                cur = db.execute(f"DELETE FROM {table} WHERE id = ?", (card_id,))
                if cur.rowcount == 0:
                    abort(404)
                db.commit()
                flash("Card deleted.", "success")
            return redirect(url_for("manage_cards"))

        if card_type == "character":
            name = request.form.get("name", "").strip()
            card_url = request.form.get("card_url", "").strip()
            selected_factions = list(dict.fromkeys(f for f in request.form.getlist("factions") if f in FACTIONS))
            if not name or len(name) > 100 or not selected_factions:
                flash("Character cards need a name and at least one faction.", "error")
            elif card_url and not card_url.startswith("https://"):
                flash("Character card links must use HTTPS.", "error")
            else:
                try:
                    if action == "add":
                        cur = db.execute("INSERT INTO characters (name, card_url, created_by) VALUES (?, ?, ?)",
                                         (name, card_url, g.user["id"]))
                        card_id = cur.lastrowid
                    elif action == "save":
                        db.execute("UPDATE characters SET name = ?, card_url = ?, is_active = ? WHERE id = ?",
                                   (name, card_url, int(request.form.get("is_active") == "1"), card_id))
                        if not db.execute("SELECT changes()").fetchone()[0]:
                            abort(404)
                    else:
                        abort(400)
                    db.execute("DELETE FROM character_factions WHERE character_id = ?", (card_id,))
                    db.executemany("INSERT INTO character_factions (character_id, faction) VALUES (?, ?)",
                                   [(card_id, faction) for faction in selected_factions])
                    db.commit()
                    flash("Character card saved.", "success")
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash("A character with that name already exists.", "error")
        elif card_type == "upgrade":
            name = request.form.get("name", "").strip()
            image_url = request.form.get("image_url", "").strip()
            selected_factions = list(dict.fromkeys(f for f in request.form.getlist("factions") if f in FACTIONS))
            if not name or len(name) > 100 or not selected_factions:
                flash("Upgrade cards need a name and at least one faction.", "error")
            elif image_url and not image_url.startswith("https://"):
                flash("Upgrade card images must use HTTPS.", "error")
            else:
                try:
                    if action == "add":
                        cur = db.execute("INSERT INTO upgrades (name, image_url, created_by) VALUES (?, ?, ?)",
                                         (name, image_url, g.user["id"]))
                        card_id = cur.lastrowid
                    elif action == "save":
                        db.execute("UPDATE upgrades SET name = ?, image_url = ?, is_active = ? WHERE id = ?",
                                   (name, image_url, int(request.form.get("is_active") == "1"), card_id))
                        if not db.execute("SELECT changes()").fetchone()[0]:
                            abort(404)
                    else:
                        abort(400)
                    db.execute("DELETE FROM upgrade_factions WHERE upgrade_id = ?", (card_id,))
                    db.executemany("INSERT INTO upgrade_factions (upgrade_id, faction) VALUES (?, ?)",
                                   [(card_id, faction) for faction in selected_factions])
                    db.commit()
                    flash("Upgrade card saved.", "success")
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash("An upgrade with that name already exists.", "error")
        elif card_type == "campaign":
            name = request.form.get("name", "").strip()
            image_url = request.form.get("image_url", "").strip()
            selected_factions = list(dict.fromkeys(f for f in request.form.getlist("factions") if f in FACTIONS))
            if not name or len(name) > 100 or not selected_factions:
                flash("Campaign cards need a name and at least one faction.", "error")
            elif image_url and not image_url.startswith("https://"):
                flash("Campaign card images must use HTTPS.", "error")
            else:
                try:
                    if action == "add":
                        cur = db.execute("INSERT INTO campaign_cards (name, image_url, created_by) VALUES (?, ?, ?)",
                                         (name, image_url, g.user["id"]))
                        card_id = cur.lastrowid
                    elif action == "save":
                        db.execute("UPDATE campaign_cards SET name = ?, image_url = ?, is_active = ? WHERE id = ?",
                                   (name, image_url, int(request.form.get("is_active") == "1"), card_id))
                        if not db.execute("SELECT changes()").fetchone()[0]:
                            abort(404)
                    else:
                        abort(400)
                    db.execute("DELETE FROM campaign_card_factions WHERE campaign_card_id = ?", (card_id,))
                    db.executemany("INSERT INTO campaign_card_factions (campaign_card_id, faction) VALUES (?, ?)",
                                   [(card_id, faction) for faction in selected_factions])
                    db.commit()
                    flash("Campaign card saved.", "success")
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash("A campaign card with that name already exists.", "error")
        else:
            abort(400)
        return redirect(url_for("manage_cards"))

    characters = db.execute("SELECT * FROM characters ORDER BY name COLLATE NOCASE").fetchall()
    character_factions = {row["id"]: [item[0] for item in db.execute("SELECT faction FROM character_factions WHERE character_id = ? ORDER BY faction", (row["id"],))] for row in characters}
    upgrades = db.execute("SELECT * FROM upgrades ORDER BY name COLLATE NOCASE").fetchall()
    upgrade_factions = {row["id"]: [item[0] for item in db.execute("SELECT faction FROM upgrade_factions WHERE upgrade_id = ? ORDER BY faction", (row["id"],))] for row in upgrades}
    campaign_cards = db.execute("SELECT * FROM campaign_cards ORDER BY name COLLATE NOCASE").fetchall()
    campaign_card_factions = {row["id"]: [item[0] for item in db.execute("SELECT faction FROM campaign_card_factions WHERE campaign_card_id = ? ORDER BY faction", (row["id"],))] for row in campaign_cards}
    template = "manage_cards.html" if g.user["can_manage_cards"] else "manage_cards_readonly.html"
    return render_template(template, characters=characters,
                           character_factions=character_factions, upgrades=upgrades,
                           upgrade_factions=upgrade_factions, campaign_cards=campaign_cards,
                           campaign_card_factions=campaign_card_factions)


@app.route("/campaigns/<int:campaign_id>/settings", methods=["GET", "POST"])
@login_required
def campaign_settings(campaign_id: int):
    db = get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if campaign is None:
        abort(404)
    if campaign["created_by"] != g.user["id"]:
        abort(403)
    if request.method == "POST":
        if request.form.get("action") == "close_campaign_early":
            if campaign["status"] != "in_progress":
                flash("Only an in-progress campaign can be closed early.", "error")
                return redirect(url_for("campaign_settings", campaign_id=campaign_id))
            db.execute("UPDATE campaigns SET status = 'closed' WHERE id = ?", (campaign_id,))
            db.commit()
            flash(f"Campaign closed early during round {campaign['current_round']}.", "success")
            return redirect(url_for("troupe", campaign_id=campaign_id))
        name = request.form.get("name", "").strip()
        location = request.form.get("location", "").strip()
        link_url = request.form.get("link_url", "").strip()
        addition_mode = request.form.get("addition_mode", "")
        if not name or len(name) > 100:
            flash("Enter a campaign name (up to 100 characters).", "error")
        elif not location or len(location) > 120:
            flash("Enter a location (up to 120 characters).", "error")
        elif link_url and (len(link_url) > 500 or not is_valid_https_url(link_url)):
            flash("Enter a valid HTTPS campaign link, or leave the field blank.", "error")
        elif addition_mode not in ("either", "both"):
            flash("Choose a valid roster addition rule.", "error")
        else:
            db.execute("UPDATE campaigns SET name = ?, location = ?, link_url = ?, addition_mode = ? WHERE id = ?",
                       (name, location, link_url, addition_mode, campaign_id))
            valid = True
            if campaign["status"] == "new":
                try:
                    rounds = int(request.form.get("rounds", "0"))
                except ValueError:
                    rounds = 0
                allowed_raw = request.form.get("allowed_players", "").strip()
                try:
                    allowed_players = int(allowed_raw) if allowed_raw else None
                except ValueError:
                    allowed_players = 0
                member_count = db.execute("SELECT COUNT(*) FROM campaign_players WHERE campaign_id = ?",
                                          (campaign_id,)).fetchone()[0]
                if not 1 <= rounds <= 20:
                    valid = False
                    flash("Rounds must be between 1 and 20.", "error")
                elif allowed_players is not None and not 1 <= allowed_players <= 100:
                    valid = False
                    flash("Player limit must be between 1 and 100, or left blank for no limit.", "error")
                elif allowed_players is not None and allowed_players < member_count:
                    valid = False
                    flash(f"Player limit cannot be lower than the {member_count} players already signed up.", "error")
                if valid:
                    db.execute("UPDATE campaigns SET rounds = ?, allowed_players = ? WHERE id = ?",
                               (rounds, allowed_players, campaign_id))
            if valid:
                db.commit()
                flash("Campaign parameters saved.", "success")
                return redirect(url_for("troupe", campaign_id=campaign_id))
            db.rollback()
    return render_template("campaign_settings.html", campaign=campaign)


def get_campaign_troupe(campaign_id: int):
    db = get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if campaign is None:
        abort(404)
    member = db.execute("SELECT faction, status FROM campaign_players WHERE campaign_id = ? AND user_id = ?",
                        (campaign_id, g.user["id"])).fetchone()
    if not member or member["status"] == "replaced":
        abort(403)
    db.execute("INSERT OR IGNORE INTO troupes (campaign_id, user_id) VALUES (?, ?)",
               (campaign_id, g.user["id"]))
    db.commit()
    troupe = db.execute("SELECT * FROM troupes WHERE campaign_id = ? AND user_id = ?",
                        (campaign_id, g.user["id"])).fetchone()
    return campaign, troupe, member["faction"]


@app.route("/campaigns/<int:campaign_id>/troupe", methods=["GET", "POST"])
@login_required
def troupe(campaign_id: int):
    db = get_db()
    campaign, troupe_row, player_faction = get_campaign_troupe(campaign_id)
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save_machinations":
            if (campaign["status"] != "in_progress" or campaign["current_phase"] != "machinations"
                    or campaign["current_round"] <= 1):
                flash("Machinations can only be submitted during the Machinations phase from round 2 onward.", "error")
            else:
                opponent = db.execute("SELECT CASE WHEN po.player_one = ? THEN po.player_two ELSE po.player_one END AS opponent_id FROM campaign_pairings cp JOIN pairing_options po ON po.campaign_id = cp.campaign_id AND po.schedule_round = cp.schedule_round WHERE cp.campaign_id = ? AND cp.round_number = ? AND (po.player_one = ? OR po.player_two = ?)",
                                      (g.user["id"], campaign_id, campaign["current_round"], g.user["id"], g.user["id"])).fetchone()
                blocked_ids = {g.user["id"]}
                if opponent and opponent["opponent_id"] is not None:
                    blocked_ids.add(opponent["opponent_id"])
                allowed_targets = {row["user_id"] for row in db.execute("SELECT user_id FROM campaign_players WHERE campaign_id = ? AND status != 'replaced'", (campaign_id,)) if row["user_id"] not in blocked_ids}
                choices: list[tuple[int, str]] = []
                invalid = False
                for slot in (1, 2):
                    target_raw = request.form.get(f"target_{slot}", "")
                    kind = request.form.get(f"kind_{slot}", "")
                    if not target_raw and not kind:
                        continue
                    try:
                        target_id = int(target_raw)
                    except ValueError:
                        invalid = True
                        break
                    if target_id not in allowed_targets or kind not in ("sabotage", "support"):
                        invalid = True
                        break
                    choices.append((target_id, kind))
                if len(choices) != len(set(choices)):
                    invalid = True
                if invalid:
                    flash("Choose up to two valid machinations. You may not target the same player twice with the same type.", "error")
                else:
                    db.execute("DELETE FROM machinations WHERE campaign_id = ? AND round_number = ? AND actor_id = ?",
                               (campaign_id, campaign["current_round"], g.user["id"]))
                    db.executemany("INSERT INTO machinations (campaign_id, round_number, actor_id, target_id, kind) VALUES (?, ?, ?, ?, ?)",
                                   [(campaign_id, campaign["current_round"], g.user["id"], target, kind) for target, kind in choices])
                    db.execute("INSERT INTO machination_submissions (campaign_id, round_number, user_id) VALUES (?, ?, ?) ON CONFLICT(campaign_id, round_number, user_id) DO UPDATE SET submitted_at = CURRENT_TIMESTAMP",
                               (campaign_id, campaign["current_round"], g.user["id"]))
                    db.commit()
                    flash("Your machinations are saved secretly. You can edit them until Encounter begins.", "success")
                    return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "save_duel_cards":
            if campaign["status"] != "in_progress" or campaign["current_phase"] != "duel":
                flash("Campaign cards can only be submitted during the Encounter phase.", "error")
            else:
                db.execute("BEGIN IMMEDIATE")
                match = current_match(db, campaign_id, campaign["current_round"], g.user["id"])
                allowance = db.execute("SELECT campaign_cards FROM machination_results WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                                       (campaign_id, campaign["current_round"], g.user["id"])).fetchone()
                opponent_id = None
                if match and match["player_two"] is not None:
                    opponent_id = match["player_two"] if match["player_one"] == g.user["id"] else match["player_one"]
                opponent_confirmed = db.execute("SELECT 1 FROM duel_confirmations WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                                                (campaign_id, campaign["current_round"], opponent_id)).fetchone() if opponent_id else None
                admin_confirmed = (db.execute("SELECT 1 FROM duel_match_overrides WHERE campaign_id = ? AND round_number = ? AND player_one = ? AND player_two = ?",
                                              (campaign_id, campaign["current_round"], match["player_one"], match["player_two"])).fetchone()
                                   if match and match["player_two"] is not None else None)
                selection_locked = bool(opponent_confirmed or admin_confirmed)
                chosen = request.form.getlist("campaign_card_ids", type=int)
                valid = bool(not selection_locked and match and match["player_two"] is not None and allowance
                             and len(chosen) == allowance["campaign_cards"] and len(chosen) == len(set(chosen)))
                if valid:
                    for card_id in chosen:
                        card = db.execute("SELECT cc.is_active, EXISTS(SELECT 1 FROM campaign_card_factions cf WHERE cf.campaign_card_id = cc.id AND cf.faction = ?) AS faction_ok, EXISTS(SELECT 1 FROM duel_card_uses old WHERE old.campaign_id = ? AND old.round_number = ? AND old.user_id = ? AND old.campaign_card_id = cc.id) AS own_current FROM campaign_cards cc WHERE cc.id = ?",
                                          (player_faction, campaign_id, campaign["current_round"], g.user["id"], card_id)).fetchone()
                        used_elsewhere = db.execute("SELECT 1 FROM duel_card_uses WHERE campaign_id = ? AND user_id = ? AND campaign_card_id = ? AND round_number != ? LIMIT 1",
                                                    (campaign_id, g.user["id"], card_id, campaign["current_round"])).fetchone()
                        if not card or not card["faction_ok"] or (not card["is_active"] and not card["own_current"]) or used_elsewhere:
                            valid = False
                            break
                if selection_locked:
                    db.rollback()
                    flash("Campaign card selections are locked because the opponent or Wizard Chamberlain has confirmed the result.", "error")
                elif not valid:
                    db.rollback()
                    flash(f"Choose exactly {allowance['campaign_cards'] if allowance else 0} unused active campaign card(s) from your faction.", "error")
                else:
                    db.execute("DELETE FROM duel_card_uses WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                               (campaign_id, campaign["current_round"], g.user["id"]))
                    db.executemany("INSERT INTO duel_card_uses (campaign_id, round_number, user_id, campaign_card_id) VALUES (?, ?, ?, ?)",
                                   [(campaign_id, campaign["current_round"], g.user["id"], card_id) for card_id in chosen])
                    if match and match["player_two"] is not None:
                        db.execute("DELETE FROM duel_confirmations WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                                   (campaign_id, campaign["current_round"], match["player_one"], match["player_two"]))
                        db.execute("DELETE FROM duel_match_overrides WHERE campaign_id = ? AND round_number = ? AND player_one = ? AND player_two = ?",
                                   (campaign_id, campaign["current_round"], match["player_one"], match["player_two"]))
                    db.commit()
                    flash("Campaign cards recorded for this Encounter.", "success")
                    return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "save_duel_score":
            if campaign["status"] != "in_progress" or campaign["current_phase"] != "duel":
                flash("Encounter results can only be entered during the Encounter phase.", "error")
            else:
                match = current_match(db, campaign_id, campaign["current_round"], g.user["id"])
                try:
                    moonstones = int(request.form.get("moonstones", "-1"))
                    victory_points = int(request.form.get("victory_points", "-1"))
                except ValueError:
                    moonstones = victory_points = -1
                if not match or match["player_two"] is None:
                    flash("There is no Encounter result to record for this round.", "error")
                elif duel_result_confirmed(db, campaign_id, campaign["current_round"], match):
                    flash("This Encounter result is confirmed and can no longer be changed.", "error")
                elif not 0 <= moonstones <= 999 or not 0 <= victory_points <= 999:
                    flash("Moonstones and campaign points must each be between 0 and 999.", "error")
                else:
                    db.execute("INSERT INTO duel_scores (campaign_id, round_number, user_id, moonstones, victory_points) VALUES (?, ?, ?, ?, ?) ON CONFLICT(campaign_id, round_number, user_id) DO UPDATE SET moonstones = excluded.moonstones, victory_points = excluded.victory_points, submitted_at = CURRENT_TIMESTAMP",
                               (campaign_id, campaign["current_round"], g.user["id"], moonstones, victory_points))
                    db.execute("DELETE FROM duel_confirmations WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                               (campaign_id, campaign["current_round"], match["player_one"], match["player_two"]))
                    db.execute("DELETE FROM duel_match_overrides WHERE campaign_id = ? AND round_number = ? AND player_one = ? AND player_two = ?",
                               (campaign_id, campaign["current_round"], match["player_one"], match["player_two"]))
                    db.commit()
                    flash("Your Encounter result is saved. Both players will need to confirm the results again if they change.", "success")
                    return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "confirm_duel_result":
            match = current_match(db, campaign_id, campaign["current_round"], g.user["id"])
            if campaign["status"] != "in_progress" or campaign["current_phase"] != "duel" or not match or match["player_two"] is None:
                flash("There is no Encounter result to confirm right now.", "error")
            else:
                score_count = db.execute("SELECT COUNT(*) FROM duel_scores WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                                         (campaign_id, campaign["current_round"], match["player_one"], match["player_two"])).fetchone()[0]
                if score_count != 2:
                    flash("Both players must submit their scores before confirming the result.", "error")
                elif not match_cards_complete(db, campaign_id, campaign["current_round"],
                                              (match["player_one"], match["player_two"])):
                    flash("Both players must select their campaign cards before confirming the result.", "error")
                else:
                    db.execute("INSERT OR IGNORE INTO duel_confirmations (campaign_id, round_number, user_id) VALUES (?, ?, ?)",
                               (campaign_id, campaign["current_round"], g.user["id"]))
                    db.commit()
                    flash("Your confirmation has been recorded.", "success")
                    return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "admin_revoke_duel_confirmation":
            if campaign["created_by"] != g.user["id"]:
                abort(403)
            try:
                result_round = int(request.form.get("round_number", "0"))
                player_id = int(request.form.get("player_id", "0"))
            except ValueError:
                result_round = player_id = 0
            match = current_match(db, campaign_id, result_round, player_id) if result_round == campaign["current_round"] else None
            if (campaign["status"] not in ("in_progress", "closed")
                    or campaign["current_phase"] not in ("duel", "troupe_growth")
                    or not match or match["player_two"] is None):
                flash("That Encounter confirmation cannot be revoked now.", "error")
            elif not duel_result_confirmed(db, campaign_id, result_round, match):
                flash("That Encounter result is not confirmed.", "info")
            else:
                db.execute("DELETE FROM duel_confirmations WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                           (campaign_id, result_round, match["player_one"], match["player_two"]))
                db.execute("DELETE FROM duel_match_overrides WHERE campaign_id = ? AND round_number = ? AND player_one = ? AND player_two = ?",
                           (campaign_id, result_round, match["player_one"], match["player_two"]))
                if campaign["current_phase"] != "duel" or campaign["status"] == "closed":
                    db.execute("UPDATE campaigns SET status = 'in_progress', current_phase = 'duel' WHERE id = ?",
                               (campaign_id,))
                db.commit()
                flash("Encounter confirmation revoked. The result is unlocked for correction and reconfirmation.", "success")
                return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "admin_confirm_duel":
            if campaign["created_by"] != g.user["id"]:
                abort(403)
            try:
                result_round = int(request.form.get("round_number", "0"))
            except ValueError:
                result_round = 0
            match = current_match(db, campaign_id, result_round, int(request.form.get("player_id", "0"))) if result_round == campaign["current_round"] else None
            if campaign["status"] != "in_progress" or campaign["current_phase"] != "duel" or not match or match["player_two"] is None:
                flash("That Encounter cannot be confirmed now.", "error")
            else:
                score_count = db.execute("SELECT COUNT(*) FROM duel_scores WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                                         (campaign_id, result_round, match["player_one"], match["player_two"])).fetchone()[0]
                if score_count != 2:
                    flash("Both players must submit their scores before the organizer can confirm the result.", "error")
                elif not match_cards_complete(db, campaign_id, result_round,
                                              (match["player_one"], match["player_two"])):
                    flash("Both players must select their campaign cards before the organizer can confirm the result.", "error")
                else:
                    db.execute("INSERT OR REPLACE INTO duel_match_overrides (campaign_id, round_number, player_one, player_two, confirmed_by) VALUES (?, ?, ?, ?, ?)",
                               (campaign_id, result_round, match["player_one"], match["player_two"], g.user["id"]))
                    db.commit()
                    flash("Encounter result confirmed by the organizer.", "success")
                    return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "submit_troupe":
            chosen = request.form.getlist("character_ids", type=int)
            if campaign["status"] != "new" or troupe_row["status"] == "ready":
                flash("The starting troupe cannot be replaced. Use the Troupe Growth phase for roster additions.", "error")
            elif len(chosen) != 5 or len(set(chosen)) != 5:
                flash("Choose exactly five different characters for your starting troupe.", "error")
            else:
                placeholders = ",".join("?" for _ in chosen)
                eligible = db.execute(f"SELECT COUNT(DISTINCT c.id) FROM characters c JOIN character_factions cf ON cf.character_id = c.id WHERE c.is_active = 1 AND cf.faction = ? AND c.id IN ({placeholders})",
                                      [player_faction, *chosen]).fetchone()[0]
                if eligible != 5:
                    flash("Every character must be available to your chosen faction.", "error")
                else:
                    db.execute("DELETE FROM troupe_characters WHERE troupe_id = ?", (troupe_row["id"],))
                    db.executemany("INSERT INTO troupe_characters (troupe_id, character_id) VALUES (?, ?)",
                                   [(troupe_row["id"], char_id) for char_id in chosen])
                    db.execute("UPDATE troupes SET status = 'ready', submitted_at = CURRENT_TIMESTAMP WHERE id = ?",
                               (troupe_row["id"],))
                    db.execute("UPDATE campaign_players SET status = 'ready' WHERE campaign_id = ? AND user_id = ?",
                               (campaign_id, g.user["id"]))
                    db.execute("UPDATE users SET status = 'ready' WHERE id = ?", (g.user["id"],))
                    db.commit()
                    flash("Troupe submitted and marked ready.", "success")
                    return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "add_character_card":
            card_name = request.form.get("card_name", "").strip()
            card_url = request.form.get("card_url", "").strip()
            card_factions = [f for f in request.form.getlist("card_factions") if f in FACTIONS]
            if not card_name or len(card_name) > 100 or not card_factions:
                flash("Enter a character name and select at least one faction.", "error")
            elif card_url and not card_url.startswith("https://"):
                flash("Card links must use HTTPS.", "error")
            else:
                cur = db.execute("INSERT OR IGNORE INTO characters (name, card_url, created_by) VALUES (?, ?, ?)",
                                 (card_name, card_url, g.user["id"]))
                char = db.execute("SELECT id FROM characters WHERE name = ?", (card_name,)).fetchone()
                db.executemany("INSERT OR IGNORE INTO character_factions (character_id, faction) VALUES (?, ?)",
                               [(char["id"], faction) for faction in card_factions])
                if cur.rowcount:
                    flash("Character card added to the catalogue.", "success")
                else:
                    flash("That character is already in the catalogue. Its existing faction entries were kept.", "info")
                db.commit()
                return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action in ("remove_character_selection", "remove_upgrade_selection"):
            if troupe_row["status"] != "ready":
                flash("Submit your starting troupe before managing campaign selections.", "error")
            elif campaign["status"] != "in_progress" or campaign["current_phase"] != "troupe_growth":
                flash("Selections can only be removed during the Troupe Growth phase.", "error")
            else:
                round_number = campaign["current_round"]
                if action == "remove_character_selection":
                    current_character = db.execute("SELECT id FROM troupe_characters WHERE troupe_id = ? AND added_after_round = ?",
                                                   (troupe_row["id"], round_number)).fetchone()
                    if not current_character:
                        flash("There is no character selection for this round to remove.", "info")
                    else:
                        linked_upgrade = db.execute("SELECT 1 FROM character_upgrades WHERE troupe_character_id = ? AND added_after_round = ?",
                                                    (current_character["id"], round_number)).fetchone()
                        if linked_upgrade:
                            flash("Remove the current-round upgrade from this character first.", "error")
                        else:
                            db.execute("DELETE FROM troupe_characters WHERE id = ?", (current_character["id"],))
                            db.commit()
                            flash(f"Round {round_number} character selection removed.", "success")
                            return redirect(url_for("troupe", campaign_id=campaign_id))
                else:
                    current_upgrade = db.execute("SELECT cu.id FROM character_upgrades cu JOIN troupe_characters tc ON tc.id = cu.troupe_character_id WHERE tc.troupe_id = ? AND cu.added_after_round = ? ORDER BY cu.id LIMIT 1",
                                                 (troupe_row["id"], round_number)).fetchone()
                    if not current_upgrade:
                        flash("There is no upgrade selection for this round to remove.", "info")
                    else:
                        db.execute("DELETE FROM character_upgrades WHERE id = ?", (current_upgrade["id"],))
                        db.commit()
                        flash(f"Round {round_number} upgrade selection removed.", "success")
                        return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action in ("add_character", "add_upgrade"):
            if troupe_row["status"] != "ready":
                flash("Submit your starting troupe before adding campaign changes.", "error")
            elif campaign["status"] != "in_progress" or campaign["current_phase"] != "troupe_growth":
                flash("Troupes can only be modified during the Troupe Growth phase.", "error")
            else:
                try:
                    after_round = int(request.form.get("after_round", "0"))
                except ValueError:
                    after_round = 0
                if after_round != campaign["current_round"]:
                    flash("Choose the current round during its Troupe Growth phase.", "error")
                elif action == "add_character":
                    try:
                        character_id = int(request.form.get("character_id", "0"))
                    except ValueError:
                        character_id = 0
                    current_character = db.execute("SELECT id, character_id FROM troupe_characters WHERE troupe_id = ? AND added_after_round = ?",
                                                   (troupe_row["id"], after_round)).fetchone()
                    available = db.execute("SELECT 1 FROM characters c JOIN character_factions cf ON cf.character_id = c.id WHERE c.id = ? AND c.is_active = 1 AND cf.faction = ?",
                                           (character_id, player_faction)).fetchone()
                    duplicate_params = [troupe_row["id"], character_id]
                    duplicate_sql = "SELECT 1 FROM troupe_characters WHERE troupe_id = ? AND character_id = ?"
                    if current_character:
                        duplicate_sql += " AND id != ?"
                        duplicate_params.append(current_character["id"])
                    duplicate = db.execute(duplicate_sql, duplicate_params).fetchone()
                    if not available or duplicate:
                        flash("Choose an unused character card available to your campaign faction.", "error")
                    else:
                        current_upgrade = db.execute("SELECT cu.id FROM character_upgrades cu JOIN troupe_characters tc ON tc.id = cu.troupe_character_id WHERE tc.troupe_id = ? AND cu.added_after_round = ? ORDER BY cu.id LIMIT 1",
                                                     (troupe_row["id"], after_round)).fetchone()
                        if campaign["addition_mode"] == "either" and current_upgrade:
                            db.execute("DELETE FROM character_upgrades WHERE id = ?", (current_upgrade["id"],))
                        if current_character:
                            db.execute("UPDATE troupe_characters SET character_id = ? WHERE id = ?",
                                       (character_id, current_character["id"]))
                            message = f"Round {after_round} character selection updated."
                        else:
                            db.execute("INSERT INTO troupe_characters (troupe_id, character_id, added_after_round) VALUES (?, ?, ?)",
                                       (troupe_row["id"], character_id, after_round))
                            message = f"Character selected for round {after_round}."
                        db.commit()
                        flash(message, "success")
                        return redirect(url_for("troupe", campaign_id=campaign_id))
                else:
                    try:
                        upgrade_id = int(request.form.get("upgrade_id", "0"))
                        troupe_character_id = int(request.form.get("troupe_character_id", "0"))
                    except ValueError:
                        upgrade_id, troupe_character_id = 0, 0
                    current_character = db.execute("SELECT id FROM troupe_characters WHERE troupe_id = ? AND added_after_round = ?",
                                                   (troupe_row["id"], after_round)).fetchone()
                    current_upgrade = db.execute("SELECT cu.id, cu.upgrade_id, cu.troupe_character_id FROM character_upgrades cu JOIN troupe_characters tc ON tc.id = cu.troupe_character_id WHERE tc.troupe_id = ? AND cu.added_after_round = ? ORDER BY cu.id LIMIT 1",
                                                 (troupe_row["id"], after_round)).fetchone()
                    upgrade_ok = db.execute("SELECT 1 FROM upgrades u JOIN upgrade_factions uf ON uf.upgrade_id = u.id WHERE u.id = ? AND u.is_active = 1 AND uf.faction = ?",
                                            (upgrade_id, player_faction)).fetchone()
                    target = db.execute("SELECT id, added_after_round FROM troupe_characters WHERE id = ? AND troupe_id = ?",
                                        (troupe_character_id, troupe_row["id"])).fetchone()
                    switching_from_character = campaign["addition_mode"] == "either" and current_character
                    invalid_switch_target = switching_from_character and target and target["id"] == current_character["id"]
                    count = db.execute("SELECT COUNT(*) FROM character_upgrades WHERE troupe_character_id = ?",
                                       (troupe_character_id,)).fetchone()[0]
                    if current_upgrade and current_upgrade["troupe_character_id"] == troupe_character_id:
                        count -= 1
                    duplicate_sql = "SELECT 1 FROM character_upgrades WHERE troupe_character_id = ? AND upgrade_id = ?"
                    duplicate_params = [troupe_character_id, upgrade_id]
                    if current_upgrade:
                        duplicate_sql += " AND id != ?"
                        duplicate_params.append(current_upgrade["id"])
                    duplicate = db.execute(duplicate_sql, duplicate_params).fetchone()
                    if not upgrade_ok or not target or invalid_switch_target or count >= MAX_UPGRADES_PER_CHARACTER or duplicate:
                        flash(f"Choose a faction-eligible upgrade and a character with fewer than {MAX_UPGRADES_PER_CHARACTER} upgrades.", "error")
                    else:
                        switching_upgrade_on_removed_character = (campaign["addition_mode"] == "either" and current_character
                                                                  and current_upgrade
                                                                  and current_upgrade["troupe_character_id"] == current_character["id"])
                        if campaign["addition_mode"] == "either" and current_character:
                            db.execute("DELETE FROM troupe_characters WHERE id = ?", (current_character["id"],))
                        if current_upgrade and not switching_upgrade_on_removed_character:
                            db.execute("UPDATE character_upgrades SET troupe_character_id = ?, upgrade_id = ? WHERE id = ?",
                                       (troupe_character_id, upgrade_id, current_upgrade["id"]))
                            message = f"Round {after_round} upgrade selection updated."
                        else:
                            db.execute("INSERT INTO character_upgrades (troupe_character_id, upgrade_id, added_after_round) VALUES (?, ?, ?)",
                                       (troupe_character_id, upgrade_id, after_round))
                            message = f"Upgrade selected for round {after_round}."
                        db.commit()
                        flash(message, "success")
                        return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "add_upgrade_card":
            upgrade_name = request.form.get("upgrade_name", "").strip()
            upgrade_image_url = request.form.get("upgrade_image_url", "").strip()
            upgrade_factions = [f for f in request.form.getlist("upgrade_factions") if f in FACTIONS]
            if not upgrade_name or len(upgrade_name) > 100 or not upgrade_factions:
                flash("Enter an upgrade name and select at least one faction.", "error")
            elif upgrade_image_url and not upgrade_image_url.startswith("https://"):
                flash("Card image links must use HTTPS.", "error")
            else:
                cur = db.execute("INSERT OR IGNORE INTO upgrades (name, image_url, created_by) VALUES (?, ?, ?)",
                                 (upgrade_name, upgrade_image_url, g.user["id"]))
                upgrade = db.execute("SELECT id FROM upgrades WHERE name = ?", (upgrade_name,)).fetchone()
                db.executemany("INSERT OR IGNORE INTO upgrade_factions (upgrade_id, faction) VALUES (?, ?)",
                               [(upgrade["id"], faction) for faction in upgrade_factions])
                if cur.rowcount:
                    flash("Upgrade card added to the catalogue.", "success")
                else:
                    if upgrade_image_url:
                        db.execute("UPDATE upgrades SET image_url = ? WHERE id = ?",
                                   (upgrade_image_url, upgrade["id"]))
                        flash("Upgrade card image updated.", "success")
                    else:
                        flash("That upgrade is already in the catalogue.", "info")
                db.commit()
                return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "start_campaign":
            if campaign["created_by"] != g.user["id"]:
                abort(403)
            creator_joined = db.execute("SELECT 1 FROM campaign_players WHERE campaign_id = ? AND user_id = ?",
                                        (campaign_id, g.user["id"])).fetchone()
            signed_players = db.execute(
                "SELECT COUNT(*) FROM campaign_players WHERE campaign_id = ? AND status != 'replaced'",
                (campaign_id,)
            ).fetchone()[0]
            not_ready = db.execute("SELECT COUNT(*) FROM campaign_players WHERE campaign_id = ? AND status != 'ready'",
                                   (campaign_id,)).fetchone()[0]
            pairing_rounds = db.execute("SELECT COUNT(*) FROM campaign_pairings WHERE campaign_id = ?",
                                        (campaign_id,)).fetchone()[0]
            if not creator_joined:
                flash("Join the campaign and choose your faction before starting it.", "error")
            elif signed_players < 4:
                flash("A campaign needs at least four signed-up players before it can start.", "error")
            elif pairing_rounds != campaign["rounds"]:
                flash("Configure one round-robin pairing set for every campaign round before starting.", "error")
            elif not_ready:
                flash("Every signed-up player must submit a ready troupe first.", "error")
            else:
                db.execute("UPDATE campaigns SET status = 'in_progress', current_round = 1, current_phase = 'machinations' WHERE id = ?", (campaign_id,))
                record_campaign_card_counts(db, campaign_id, 1)
                db.commit()
                flash("Campaign started in the Machinations phase of round 1.", "success")
                return redirect(url_for("troupe", campaign_id=campaign_id))
        elif action == "advance_phase":
            if campaign["created_by"] != g.user["id"]:
                abort(403)
            if campaign["status"] != "in_progress":
                flash("Only an active campaign can advance phases.", "error")
            elif campaign["current_phase"] == "machinations":
                record_campaign_card_counts(db, campaign_id, campaign["current_round"])
                db.execute("UPDATE campaigns SET current_phase = 'duel' WHERE id = ?", (campaign_id,))
                db.commit()
                flash(f"Round {campaign['current_round']} moved to Encounter.", "success")
                return redirect(url_for("troupe", campaign_id=campaign_id))
            elif campaign["current_phase"] == "duel":
                if not duel_phase_complete(db, campaign_id, campaign["current_round"]):
                    flash("Every Encounter needs campaign card selections, both submitted scores, and both confirmations (or an organizer confirmation) before Troupe Growth.", "error")
                else:
                    db.execute("UPDATE campaigns SET current_phase = 'troupe_growth' WHERE id = ?", (campaign_id,))
                    db.commit()
                    flash(f"Round {campaign['current_round']} moved to Troupe Growth.", "success")
                    return redirect(url_for("troupe", campaign_id=campaign_id))
            elif campaign["current_phase"] == "troupe_growth" and campaign["current_round"] < campaign["rounds"]:
                next_round = campaign["current_round"] + 1
                db.execute("UPDATE campaigns SET current_round = ?, current_phase = 'machinations' WHERE id = ?",
                           (next_round, campaign_id))
                db.commit()
                flash(f"Round {next_round} started in the Machinations phase.", "success")
                return redirect(url_for("troupe", campaign_id=campaign_id))
            elif campaign["current_phase"] == "troupe_growth":
                db.execute("UPDATE campaigns SET status = 'closed' WHERE id = ?", (campaign_id,))
                db.commit()
                flash("All rounds are complete. The campaign is closed.", "success")
                return redirect(url_for("troupe", campaign_id=campaign_id))
            else:
                abort(400)
        elif action == "reverse_phase":
            if campaign["created_by"] != g.user["id"]:
                abort(403)
            if campaign["status"] not in ("in_progress", "closed"):
                flash("Only an active or just-closed campaign can reverse a phase.", "error")
            elif campaign["current_phase"] == "troupe_growth":
                db.execute("UPDATE campaigns SET status = 'in_progress', current_phase = 'duel' WHERE id = ?", (campaign_id,))
                db.commit()
                flash(f"Round {campaign['current_round']} returned to Encounter.", "success")
                return redirect(url_for("troupe", campaign_id=campaign_id))
            elif campaign["current_phase"] == "duel":
                if round_has_confirmed_duel(db, campaign_id, campaign["current_round"]):
                    flash("This round has a confirmed Encounter result and cannot be reopened for edits.", "error")
                else:
                    db.execute("DELETE FROM machination_results WHERE campaign_id = ? AND round_number = ?",
                               (campaign_id, campaign["current_round"]))
                    for table in ("duel_card_uses", "duel_scores", "duel_confirmations", "duel_match_overrides"):
                        db.execute(f"DELETE FROM {table} WHERE campaign_id = ? AND round_number = ?",
                                   (campaign_id, campaign["current_round"]))
                    db.execute("UPDATE campaigns SET status = 'in_progress', current_phase = 'machinations' WHERE id = ?", (campaign_id,))
                    db.commit()
                    flash(f"Round {campaign['current_round']} returned to Machinations.", "success")
                    return redirect(url_for("troupe", campaign_id=campaign_id))
            elif campaign["current_phase"] == "machinations" and campaign["current_round"] > 1:
                previous_round = campaign["current_round"] - 1
                db.execute("DELETE FROM machinations WHERE campaign_id = ? AND round_number = ?",
                           (campaign_id, campaign["current_round"]))
                db.execute("DELETE FROM machination_submissions WHERE campaign_id = ? AND round_number = ?",
                           (campaign_id, campaign["current_round"]))
                db.execute("UPDATE campaigns SET status = 'in_progress', current_round = ?, current_phase = 'troupe_growth' WHERE id = ?",
                           (previous_round, campaign_id))
                db.commit()
                flash(f"Campaign returned to Troupe Growth for round {previous_round}.", "success")
                return redirect(url_for("troupe", campaign_id=campaign_id))
            else:
                flash("This is the first phase of the campaign; there is no earlier phase to return to.", "error")
    roster = db.execute("""
        SELECT tc.id AS troupe_character_id, tc.added_after_round, c.id AS character_id, c.name, c.card_url,
               (SELECT group_concat(faction, ', ') FROM character_factions cf WHERE cf.character_id = c.id) AS factions,
               (SELECT group_concat(u.name, ', ') FROM character_upgrades cu JOIN upgrades u ON u.id = cu.upgrade_id WHERE cu.troupe_character_id = tc.id) AS upgrade_names,
               (SELECT COUNT(*) FROM character_upgrades cu WHERE cu.troupe_character_id = tc.id) AS upgrade_count
        FROM troupe_characters tc JOIN characters c ON c.id = tc.character_id
        WHERE tc.troupe_id = ? ORDER BY tc.added_after_round IS NOT NULL, tc.id
    """, (troupe_row["id"],)).fetchall()
    current_growth_character = next((item for item in roster
                                     if campaign["status"] == "in_progress"
                                     and campaign["current_phase"] == "troupe_growth"
                                     and item["added_after_round"] == campaign["current_round"]), None)
    current_growth_upgrade = db.execute("SELECT cu.id, cu.upgrade_id, cu.troupe_character_id FROM character_upgrades cu JOIN troupe_characters tc ON tc.id = cu.troupe_character_id WHERE tc.troupe_id = ? AND cu.added_after_round = ? ORDER BY cu.id LIMIT 1",
                                       (troupe_row["id"], campaign["current_round"])).fetchone()
    characters = db.execute("SELECT c.id, c.name, c.card_url, (SELECT group_concat(cf2.faction, ', ') FROM character_factions cf2 WHERE cf2.character_id = c.id) AS factions FROM characters c JOIN character_factions cf ON cf.character_id = c.id WHERE c.is_active = 1 AND cf.faction = ? ORDER BY c.name",
                            (player_faction,)).fetchall()
    already_selected = {item["character_id"] for item in roster}
    available_characters = [item for item in characters
                            if item["id"] not in already_selected
                            or (current_growth_character and item["id"] == current_growth_character["character_id"])]
    upgrades = db.execute("SELECT u.id, u.name, u.image_url FROM upgrades u JOIN upgrade_factions uf ON uf.upgrade_id = u.id WHERE u.is_active = 1 AND uf.faction = ? ORDER BY u.name",
                          (player_faction,)).fetchall()
    players = db.execute("SELECT u.id, u.name, u.avatar_filename, cp.faction, cp.status, t.status AS troupe_status FROM campaign_players cp JOIN users u ON u.id = cp.user_id LEFT JOIN troupes t ON t.campaign_id = cp.campaign_id AND t.user_id = cp.user_id WHERE cp.campaign_id = ? AND cp.status != 'replaced' ORDER BY u.name",
                         (campaign_id,)).fetchall()
    growth_rounds = [campaign["current_round"]] if campaign["status"] == "in_progress" and campaign["current_phase"] == "troupe_growth" else []
    attached_upgrades = db.execute("SELECT cu.troupe_character_id, u.name, u.image_url FROM character_upgrades cu JOIN upgrades u ON u.id = cu.upgrade_id JOIN troupe_characters tc ON tc.id = cu.troupe_character_id WHERE tc.troupe_id = ? ORDER BY cu.id", (troupe_row["id"],)).fetchall()
    upgrades_by_character: dict[int, list[sqlite3.Row]] = {}
    for upgrade in attached_upgrades:
        upgrades_by_character.setdefault(upgrade["troupe_character_id"], []).append(upgrade)
    roster = [dict(item) for item in roster]
    for item in roster:
        item["upgrades"] = upgrades_by_character.get(item["troupe_character_id"], [])
    round_pairings = []
    if campaign["status"] in ("in_progress", "closed"):
        round_pairings = db.execute("SELECT cp.round_number, po.player_one, po.player_two, u1.name AS player_one_name, u2.name AS player_two_name, (SELECT group_concat(cc.name, ', ') FROM duel_card_uses dcu JOIN campaign_cards cc ON cc.id = dcu.campaign_card_id WHERE dcu.campaign_id = cp.campaign_id AND dcu.round_number = cp.round_number AND dcu.user_id = po.player_one) AS player_one_campaign_cards, (SELECT group_concat(cc.name, ', ') FROM duel_card_uses dcu JOIN campaign_cards cc ON cc.id = dcu.campaign_card_id WHERE dcu.campaign_id = cp.campaign_id AND dcu.round_number = cp.round_number AND dcu.user_id = po.player_two) AS player_two_campaign_cards, (EXISTS(SELECT 1 FROM machination_submissions ms WHERE ms.campaign_id = cp.campaign_id AND ms.round_number = cp.round_number AND ms.user_id = po.player_one) OR EXISTS(SELECT 1 FROM machinations m WHERE m.campaign_id = cp.campaign_id AND m.round_number = cp.round_number AND m.actor_id = po.player_one)) AS player_one_machinations_submitted, (po.player_two IS NOT NULL AND (EXISTS(SELECT 1 FROM machination_submissions ms WHERE ms.campaign_id = cp.campaign_id AND ms.round_number = cp.round_number AND ms.user_id = po.player_two) OR EXISTS(SELECT 1 FROM machinations m WHERE m.campaign_id = cp.campaign_id AND m.round_number = cp.round_number AND m.actor_id = po.player_two))) AS player_two_machinations_submitted, s1.moonstones AS player_one_moonstones, s1.victory_points AS player_one_victory_points, s2.moonstones AS player_two_moonstones, s2.victory_points AS player_two_victory_points, (SELECT COUNT(*) FROM duel_confirmations dc WHERE dc.campaign_id = cp.campaign_id AND dc.round_number = cp.round_number AND dc.user_id IN (po.player_one, po.player_two)) AS confirmations, EXISTS(SELECT 1 FROM duel_match_overrides dro WHERE dro.campaign_id = cp.campaign_id AND dro.round_number = cp.round_number AND dro.player_one = po.player_one AND dro.player_two = po.player_two) AS admin_confirmed FROM campaign_pairings cp JOIN pairing_options po ON po.campaign_id = cp.campaign_id AND po.schedule_round = cp.schedule_round JOIN users u1 ON u1.id = po.player_one LEFT JOIN users u2 ON u2.id = po.player_two LEFT JOIN duel_scores s1 ON s1.campaign_id = cp.campaign_id AND s1.round_number = cp.round_number AND s1.user_id = po.player_one LEFT JOIN duel_scores s2 ON s2.campaign_id = cp.campaign_id AND s2.round_number = cp.round_number AND s2.user_id = po.player_two WHERE cp.campaign_id = ? AND cp.round_number = ? ORDER BY u1.name COLLATE NOCASE",
                                    (campaign_id, campaign["current_round"])).fetchall()
    pairings_by_player = {}
    for pairing in round_pairings:
        pairings_by_player[pairing["player_one"]] = pairing
        if pairing["player_two"] is not None:
            pairings_by_player[pairing["player_two"]] = pairing
    roster_statuses = {}
    for player in players:
        if campaign["status"] == "new":
            ready = player["troupe_status"] == "ready"
            roster_statuses[player["id"]] = {
                "label": "Ready" if ready else "Troupe needed",
                "class": "ready" if ready else "troupe-needed",
            }
        elif campaign["current_phase"] == "machinations":
            submitted = campaign["current_round"] == 1 or bool(db.execute(
                "SELECT EXISTS(SELECT 1 FROM machination_submissions WHERE campaign_id = ? AND round_number = ? AND user_id = ?) OR EXISTS(SELECT 1 FROM machinations WHERE campaign_id = ? AND round_number = ? AND actor_id = ?)",
                (campaign_id, campaign["current_round"], player["id"], campaign_id,
                 campaign["current_round"], player["id"])
            ).fetchone()[0])
            roster_statuses[player["id"]] = {
                "label": "Machinations submitted" if submitted else "Machinations pending",
                "class": "submitted" if submitted else "pending",
            }
        elif campaign["current_phase"] == "duel":
            pairing = pairings_by_player.get(player["id"])
            if pairing and pairing["player_two"] is None:
                roster_statuses[player["id"]] = {"label": "Validated", "class": "validated"}
            else:
                allowance = db.execute(
                    "SELECT campaign_cards FROM machination_results WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                    (campaign_id, campaign["current_round"], player["id"])
                ).fetchone()
                selected_cards = db.execute(
                    "SELECT COUNT(*) FROM duel_card_uses WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                    (campaign_id, campaign["current_round"], player["id"])
                ).fetchone()[0]
                score_exists = db.execute(
                    "SELECT 1 FROM duel_scores WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                    (campaign_id, campaign["current_round"], player["id"])
                ).fetchone()
                if not pairing or not allowance or selected_cards != allowance["campaign_cards"] or not score_exists:
                    roster_statuses[player["id"]] = {"label": "Results missing", "class": "missing"}
                elif duel_result_confirmed(db, campaign_id, campaign["current_round"], pairing):
                    roster_statuses[player["id"]] = {"label": "Validated", "class": "validated"}
                else:
                    roster_statuses[player["id"]] = {"label": "Waiting for validation", "class": "waiting"}
        else:  # troupe_growth
            has_character = db.execute(
                "SELECT 1 FROM troupe_characters tc JOIN troupes t ON t.id = tc.troupe_id WHERE t.campaign_id = ? AND t.user_id = ? AND tc.added_after_round = ? LIMIT 1",
                (campaign_id, player["id"], campaign["current_round"])
            ).fetchone() is not None
            has_upgrade = db.execute(
                "SELECT 1 FROM character_upgrades cu JOIN troupe_characters tc ON tc.id = cu.troupe_character_id JOIN troupes t ON t.id = tc.troupe_id WHERE t.campaign_id = ? AND t.user_id = ? AND cu.added_after_round = ? LIMIT 1",
                (campaign_id, player["id"], campaign["current_round"])
            ).fetchone() is not None
            completed = ((has_character and has_upgrade) if campaign["addition_mode"] == "both"
                         else (has_character or has_upgrade))
            roster_statuses[player["id"]] = {
                "label": "Completed" if completed else "Recruitment",
                "class": "completed" if completed else "recruitment",
            }
    my_match = next((item for item in round_pairings
                     if item["round_number"] == campaign["current_round"]
                     and (item["player_one"] == g.user["id"] or item["player_two"] == g.user["id"])), None)
    my_opponent = None
    if campaign["status"] == "in_progress" and campaign["current_round"] > 1:
        matchup = db.execute("SELECT CASE WHEN po.player_one = ? THEN po.player_two ELSE po.player_one END AS opponent_id FROM campaign_pairings cp JOIN pairing_options po ON po.campaign_id = cp.campaign_id AND po.schedule_round = cp.schedule_round WHERE cp.campaign_id = ? AND cp.round_number = ? AND (po.player_one = ? OR po.player_two = ?)",
                             (g.user["id"], campaign_id, campaign["current_round"], g.user["id"], g.user["id"])).fetchone()
        my_opponent = matchup["opponent_id"] if matchup else None
    machination_targets = [player for player in players
                           if player["id"] != g.user["id"] and player["id"] != my_opponent]
    my_machinations = db.execute("SELECT target_id, kind FROM machinations WHERE campaign_id = ? AND round_number = ? AND actor_id = ? ORDER BY id",
                                 (campaign_id, campaign["current_round"], g.user["id"])).fetchall()
    card_result = db.execute("SELECT campaign_cards, machination_points FROM machination_results WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                              (campaign_id, campaign["current_round"], g.user["id"])).fetchone()
    my_duel_cards = [row["campaign_card_id"] for row in db.execute("SELECT campaign_card_id FROM duel_card_uses WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                                                                    (campaign_id, campaign["current_round"], g.user["id"]))]
    card_selection = db.execute("SELECT cc.id, cc.name, cc.image_url, cc.is_active, EXISTS(SELECT 1 FROM duel_card_uses used WHERE used.campaign_id = ? AND used.user_id = ? AND used.campaign_card_id = cc.id) AS used_by_me, EXISTS(SELECT 1 FROM duel_card_uses own WHERE own.campaign_id = ? AND own.round_number = ? AND own.user_id = ? AND own.campaign_card_id = cc.id) AS selected_by_me FROM campaign_cards cc JOIN campaign_card_factions ccf ON ccf.campaign_card_id = cc.id WHERE ccf.faction = ? ORDER BY cc.name COLLATE NOCASE",
                                 (campaign_id, g.user["id"], campaign_id, campaign["current_round"], g.user["id"], player_faction)).fetchall()
    campaign_card_history = db.execute("SELECT cc.name AS card_name, dcu.round_number FROM duel_card_uses dcu JOIN campaign_cards cc ON cc.id = dcu.campaign_card_id WHERE dcu.campaign_id = ? AND dcu.user_id = ? ORDER BY dcu.round_number, cc.name COLLATE NOCASE",
                                       (campaign_id, g.user["id"])).fetchall()
    own_score = db.execute("SELECT moonstones, victory_points FROM duel_scores WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                           (campaign_id, campaign["current_round"], g.user["id"])).fetchone()
    my_confirmation = db.execute("SELECT 1 FROM duel_confirmations WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                                 (campaign_id, campaign["current_round"], g.user["id"])).fetchone()
    admin_confirmed_round = None
    if my_match and my_match["player_two"] is not None:
        admin_confirmed_round = db.execute("SELECT 1 FROM duel_match_overrides WHERE campaign_id = ? AND round_number = ? AND player_one = ? AND player_two = ?",
                                           (campaign_id, campaign["current_round"], my_match["player_one"], my_match["player_two"])).fetchone()
    result_confirmed = duel_result_confirmed(db, campaign_id, campaign["current_round"], my_match)
    opponent_id = None
    if my_match and my_match["player_two"] is not None:
        opponent_id = my_match["player_two"] if my_match["player_one"] == g.user["id"] else my_match["player_one"]
    opponent_confirmation = db.execute("SELECT 1 FROM duel_confirmations WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                                       (campaign_id, campaign["current_round"], opponent_id)).fetchone() if opponent_id else None
    card_selection_locked = bool(opponent_confirmation or admin_confirmed_round)
    character_add_rounds = upgrade_add_rounds = growth_rounds
    return render_template("troupe.html", campaign=campaign, troupe=troupe_row, roster=roster,
                           characters=characters, available_characters=available_characters,
                           upgrades=upgrades, players=players, player_faction=player_faction,
                           current_growth_character=current_growth_character,
                           current_growth_upgrade=current_growth_upgrade,
                           round_pairings=round_pairings,
                           roster_statuses=roster_statuses,
                           my_match=my_match,
                           current_user_id=g.user["id"],
                           leaderboard=campaign_leaderboard(db, campaign_id, campaign["current_round"]),
                           card_selection=card_selection,
                           my_duel_cards=my_duel_cards,
                           campaign_card_history=campaign_card_history,
                           own_score=own_score,
                           my_confirmation=bool(my_confirmation),
                           admin_confirmed_round=bool(admin_confirmed_round),
                           result_confirmed=result_confirmed,
                           card_selection_locked=card_selection_locked,
                           machination_targets=machination_targets,
                           my_machinations=my_machinations,
                           card_result=card_result,
                           max_upgrades_per_character=MAX_UPGRADES_PER_CHARACTER,
                           character_add_rounds=character_add_rounds,
                           upgrade_add_rounds=upgrade_add_rounds)


@app.route("/campaigns/<int:campaign_id>/matches/<int:round_number>/<int:player_id>/admin", methods=["GET", "POST"])
@login_required
def admin_match_editor(campaign_id: int, round_number: int, player_id: int):
    db = get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if not campaign:
        abort(404)
    if campaign["created_by"] != g.user["id"]:
        abort(403)
    match = current_match(db, campaign_id, round_number, player_id)
    if (campaign["status"] != "in_progress" or campaign["current_phase"] != "duel"
            or round_number != campaign["current_round"] or not match or match["player_two"] is None):
        abort(404)
    if duel_result_confirmed(db, campaign_id, round_number, match):
        flash("This Encounter is already confirmed. Revoke its confirmation before editing.", "info")
        return redirect(url_for("troupe", campaign_id=campaign_id))

    match_players = db.execute("SELECT u.id, u.name, cp.faction FROM campaign_players cp JOIN users u ON u.id = cp.user_id WHERE cp.campaign_id = ? AND u.id IN (?, ?) ORDER BY CASE WHEN u.id = ? THEN 0 ELSE 1 END",
                               (campaign_id, match["player_one"], match["player_two"], match["player_one"])).fetchall()
    editor_players = []
    for player in match_players:
        allowance = db.execute("SELECT campaign_cards FROM machination_results WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                               (campaign_id, round_number, player["id"])).fetchone()
        selected = [row["campaign_card_id"] for row in db.execute("SELECT campaign_card_id FROM duel_card_uses WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                                                                    (campaign_id, round_number, player["id"]))]
        score = db.execute("SELECT moonstones, victory_points FROM duel_scores WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                           (campaign_id, round_number, player["id"])).fetchone()
        cards = db.execute("SELECT cc.id, cc.name, cc.is_active, EXISTS(SELECT 1 FROM duel_card_uses old WHERE old.campaign_id = ? AND old.user_id = ? AND old.campaign_card_id = cc.id AND old.round_number != ?) AS used_before FROM campaign_cards cc JOIN campaign_card_factions cf ON cf.campaign_card_id = cc.id WHERE cf.faction = ? ORDER BY cc.name COLLATE NOCASE",
                           (campaign_id, player["id"], round_number, player["faction"])).fetchall()
        editor_players.append({"id": player["id"], "name": player["name"], "faction": player["faction"],
                               "allowance": allowance["campaign_cards"] if allowance else 2,
                               "selected": selected, "score": score, "cards": cards})

    if request.method == "POST":
        submitted = {}
        errors = []
        for player in editor_players:
            try:
                stones = int(request.form.get(f"moonstones_{player['id']}", "-1"))
                campaign_points = int(request.form.get(f"campaign_points_{player['id']}", "-1"))
                chosen = request.form.getlist(f"cards_{player['id']}", type=int)
            except (TypeError, ValueError):
                stones = campaign_points = -1
                chosen = []
            if not 0 <= stones <= 999 or not 0 <= campaign_points <= 999:
                errors.append(f"Enter valid Stones and Campaign Points for {player['name']} (0–999).")
            if len(chosen) != player["allowance"] or len(set(chosen)) != len(chosen):
                errors.append(f"Select exactly {player['allowance']} campaign card(s) for {player['name']}.")
            cards_by_id = {card["id"]: card for card in player["cards"]}
            for card_id in chosen:
                card = cards_by_id.get(card_id)
                if (not card or card["used_before"]
                        or (not card["is_active"] and card_id not in player["selected"])):
                    errors.append(f"A selected campaign card for {player['name']} is unavailable or was already used.")
                    break
            submitted[player["id"]] = (stones, campaign_points, chosen)

        if errors:
            for error in errors:
                flash(error, "error")
        else:
            for user_id, (stones, campaign_points, chosen) in submitted.items():
                db.execute("DELETE FROM duel_card_uses WHERE campaign_id = ? AND round_number = ? AND user_id = ?",
                           (campaign_id, round_number, user_id))
                db.executemany("INSERT INTO duel_card_uses (campaign_id, round_number, user_id, campaign_card_id) VALUES (?, ?, ?, ?)",
                               [(campaign_id, round_number, user_id, card_id) for card_id in chosen])
                db.execute("INSERT INTO duel_scores (campaign_id, round_number, user_id, moonstones, victory_points) VALUES (?, ?, ?, ?, ?) ON CONFLICT(campaign_id, round_number, user_id) DO UPDATE SET moonstones = excluded.moonstones, victory_points = excluded.victory_points, submitted_at = CURRENT_TIMESTAMP",
                           (campaign_id, round_number, user_id, stones, campaign_points))
            db.execute("DELETE FROM duel_confirmations WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                       (campaign_id, round_number, match["player_one"], match["player_two"]))
            db.execute("INSERT OR REPLACE INTO duel_match_overrides (campaign_id, round_number, player_one, player_two, confirmed_by) VALUES (?, ?, ?, ?, ?)",
                       (campaign_id, round_number, match["player_one"], match["player_two"], g.user["id"]))
            db.commit()
            flash("Encounter cards and scores saved. The Wizard Chamberlain confirmed this result.", "success")
            return redirect(url_for("troupe", campaign_id=campaign_id))

    return render_template("admin_match_editor.html", campaign=campaign, round_number=round_number,
                           editor_players=editor_players)


@app.route("/campaigns/<int:campaign_id>/swap-user", methods=["GET", "POST"])
@login_required
def swap_campaign_user(campaign_id: int):
    db = get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if not campaign:
        abort(404)
    if campaign["created_by"] != g.user["id"]:
        abort(403)
    if (campaign["status"] != "in_progress" or campaign["current_phase"] != "troupe_growth"
            or campaign["current_round"] >= campaign["rounds"]):
        flash("A user can only be added during Troupe Growth when future rounds remain.", "error")
        return redirect(url_for("campaign_settings", campaign_id=campaign_id))

    future_schedule_rows = db.execute("SELECT round_number, schedule_round FROM campaign_pairings WHERE campaign_id = ? AND round_number > ? ORDER BY round_number",
                                     (campaign_id, campaign["current_round"])).fetchall()
    active_players = db.execute("SELECT u.id, u.name, cp.faction FROM campaign_players cp JOIN users u ON u.id = cp.user_id WHERE cp.campaign_id = ? AND cp.status != 'replaced' ORDER BY u.name COLLATE NOCASE",
                                (campaign_id,)).fetchall()
    available_users = db.execute("SELECT u.id, u.name, u.email FROM users u WHERE NOT EXISTS(SELECT 1 FROM campaign_players cp WHERE cp.campaign_id = ? AND cp.user_id = u.id) ORDER BY u.name COLLATE NOCASE",
                                (campaign_id,)).fetchall()
    characters = db.execute("SELECT c.id, c.name, c.card_url, (SELECT group_concat(faction, '|') FROM character_factions cf WHERE cf.character_id = c.id) AS factions FROM characters c WHERE c.is_active = 1 ORDER BY c.name COLLATE NOCASE").fetchall()
    upgrades = db.execute("SELECT u.id, u.name, u.image_url, (SELECT group_concat(faction, '|') FROM upgrade_factions uf WHERE uf.upgrade_id = u.id) AS factions FROM upgrades u WHERE u.is_active = 1 ORDER BY u.name COLLATE NOCASE").fetchall()
    future_bye_rounds = 0
    for schedule in future_schedule_rows:
        if db.execute("SELECT 1 FROM pairing_options WHERE campaign_id = ? AND schedule_round = ? AND player_two IS NULL",
                      (campaign_id, schedule["schedule_round"])).fetchone():
            future_bye_rounds += 1
    bye_available = bool(future_schedule_rows) and future_bye_rounds == len(future_schedule_rows)

    if request.method == "POST":
        db.execute("BEGIN IMMEDIATE")
        errors = []
        slot_type = request.form.get("slot_type", "")
        try:
            new_user_id = int(request.form.get("new_user_id", "0"))
            replace_user_id = int(request.form.get("replace_user_id", "0")) if slot_type == "player" else None
        except ValueError:
            new_user_id = replace_user_id = 0
        faction = request.form.get("faction", "")
        if slot_type not in ("player", "bye"):
            errors.append("Choose a player slot or a BYE slot to replace.")
        if slot_type == "bye" and not bye_available:
            errors.append("Future pairings do not have a BYE slot in every remaining round.")
        if slot_type == "player" and replace_user_id not in {player["id"] for player in active_players}:
            errors.append("Choose an active campaign player to replace.")
        if not any(user["id"] == new_user_id for user in available_users):
            errors.append("Choose a registered user who is not already in this campaign.")
        if faction not in FACTIONS:
            errors.append("Choose a faction for the new player.")
        if slot_type == "bye" and campaign["allowed_players"] is not None:
            active_count = len(campaign_active_player_ids(db, campaign_id, campaign["current_round"]))
            if active_count >= campaign["allowed_players"]:
                errors.append("Adding a player in place of BYE would exceed the campaign player limit.")

        selected_characters = request.form.getlist("character_ids", type=int)
        if len(selected_characters) != 5 or len(set(selected_characters)) != 5:
            errors.append("Choose exactly five different starting characters for the new player.")
        eligible_characters = {row["id"] for row in db.execute(
            "SELECT c.id FROM characters c JOIN character_factions cf ON cf.character_id = c.id WHERE c.is_active = 1 AND cf.faction = ?",
            (faction,))} if faction in FACTIONS else set()
        if any(character_id not in eligible_characters for character_id in selected_characters):
            errors.append("Every starting character must be active and assigned to the new player's faction.")

        eligible_upgrades = {row["id"] for row in db.execute(
            "SELECT u.id FROM upgrades u JOIN upgrade_factions uf ON uf.upgrade_id = u.id WHERE u.is_active = 1 AND uf.faction = ?",
            (faction,))} if faction in FACTIONS else set()
        upgrade_selections: dict[int, list[int]] = {}
        for key in request.form:
            if key.startswith("upgrade_ids_"):
                try:
                    character_id = int(key.removeprefix("upgrade_ids_"))
                except ValueError:
                    errors.append("Invalid character upgrade selection.")
                    continue
                chosen_upgrades = request.form.getlist(key, type=int)
                upgrade_selections[character_id] = chosen_upgrades
                if chosen_upgrades and character_id not in selected_characters:
                    errors.append("Upgrades can only be attached to one of the five selected characters.")
                if len(chosen_upgrades) > MAX_UPGRADES_PER_CHARACTER or len(set(chosen_upgrades)) != len(chosen_upgrades):
                    errors.append(f"Each character can have no more than {MAX_UPGRADES_PER_CHARACTER} different upgrades.")
                if any(upgrade_id not in eligible_upgrades for upgrade_id in chosen_upgrades):
                    errors.append("Every upgrade must be active and assigned to the new player's faction.")

        future_pairings = []
        for schedule in future_schedule_rows:
            options = db.execute("SELECT player_one, player_two FROM pairing_options WHERE campaign_id = ? AND schedule_round = ? ORDER BY player_one",
                                 (campaign_id, schedule["schedule_round"])).fetchall()
            if not options:
                errors.append(f"Future round {schedule['round_number']} has no saved pairing options.")
                continue
            if slot_type == "bye" and sum(option["player_two"] is None for option in options) != 1:
                errors.append(f"Future round {schedule['round_number']} does not have exactly one BYE slot.")
            if slot_type == "player" and sum(replace_user_id in (option["player_one"], option["player_two"]) for option in options) != 1:
                errors.append(f"The selected player does not have exactly one pairing in future round {schedule['round_number']}.")
            updated = []
            for option in options:
                one, two = option["player_one"], option["player_two"]
                if slot_type == "player":
                    if one == replace_user_id:
                        one = new_user_id
                    elif two == replace_user_id:
                        two = new_user_id
                elif two is None:
                    two = new_user_id
                if two is not None and one > two:
                    one, two = two, one
                updated.append((one, two))
            future_pairings.append((schedule["schedule_round"], updated))

        if errors:
            db.rollback()
            for error in dict.fromkeys(errors):
                flash(error, "error")
        else:
            db.execute("INSERT INTO campaign_players (campaign_id, user_id, faction, status) VALUES (?, ?, ?, 'ready')",
                       (campaign_id, new_user_id, faction))
            db.execute("INSERT INTO troupes (campaign_id, user_id, status, submitted_at) VALUES (?, ?, 'ready', CURRENT_TIMESTAMP)",
                       (campaign_id, new_user_id))
            troupe_id = db.execute("SELECT id FROM troupes WHERE campaign_id = ? AND user_id = ?",
                                   (campaign_id, new_user_id)).fetchone()["id"]
            for character_id in selected_characters:
                cursor = db.execute("INSERT INTO troupe_characters (troupe_id, character_id) VALUES (?, ?)",
                                    (troupe_id, character_id))
                for upgrade_id in upgrade_selections.get(character_id, []):
                    db.execute("INSERT INTO character_upgrades (troupe_character_id, upgrade_id, added_after_round) VALUES (?, ?, ?)",
                               (cursor.lastrowid, upgrade_id, campaign["current_round"]))
            if replace_user_id is not None:
                db.execute("UPDATE campaign_players SET status = 'replaced' WHERE campaign_id = ? AND user_id = ?",
                           (campaign_id, replace_user_id))
            for schedule_round, updated in future_pairings:
                db.execute("DELETE FROM pairing_options WHERE campaign_id = ? AND schedule_round = ?",
                           (campaign_id, schedule_round))
                db.executemany("INSERT INTO pairing_options (campaign_id, schedule_round, player_one, player_two) VALUES (?, ?, ?, ?)",
                               [(campaign_id, schedule_round, one, two) for one, two in updated])
            db.execute("INSERT INTO campaign_replacements (campaign_id, replaced_user_id, new_user_id, effective_round) VALUES (?, ?, ?, ?)",
                       (campaign_id, replace_user_id, new_user_id, campaign["current_round"] + 1))
            db.commit()
            flash("User added with a ready troupe. Future pairings were updated.", "success")
            return redirect(url_for("campaign_settings", campaign_id=campaign_id))

    return render_template("swap_user.html", campaign=campaign, active_players=active_players,
                           available_users=available_users, characters=characters, upgrades=upgrades,
                           bye_available=bye_available, factions=FACTIONS,
                           selected_faction=request.form.get("faction", FACTIONS[0]),
                           selected_replace_user=request.form.get("replace_user_id", str(active_players[0]["id"]) if active_players else ""))


@app.route("/campaigns/<int:campaign_id>/machinations")
@login_required
def campaign_machinations(campaign_id: int):
    db = get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if not campaign:
        abort(404)
    if campaign["created_by"] != g.user["id"]:
        abort(403)

    players = db.execute("SELECT u.id, u.name FROM campaign_players cp JOIN users u ON u.id = cp.user_id WHERE cp.campaign_id = ? ORDER BY u.name COLLATE NOCASE",
                         (campaign_id,)).fetchall()
    rounds = []
    for round_number in range(1, campaign["current_round"] + 1):
        hidden = (campaign["status"] == "in_progress" and campaign["current_phase"] == "machinations"
                  and round_number == campaign["current_round"] and round_number > 1)
        if hidden:
            rounds.append({"number": round_number, "hidden": True})
            continue

        starting_tiers = {row["user_id"]: row["tier"].lower()
                          for row in campaign_leaderboard(db, campaign_id, round_number - 1, tier_round=round_number)}
        submitted_ids = {row["user_id"] for row in db.execute(
            "SELECT user_id FROM machination_submissions WHERE campaign_id = ? AND round_number = ?",
            (campaign_id, round_number))}
        actions = db.execute("SELECT m.actor_id, m.target_id, m.kind, actor.name AS actor_name, target.name AS target_name FROM machinations m JOIN users actor ON actor.id = m.actor_id JOIN users target ON target.id = m.target_id WHERE m.campaign_id = ? AND m.round_number = ? ORDER BY actor.name COLLATE NOCASE, m.id",
                             (campaign_id, round_number)).fetchall()
        submitted_ids.update(action["actor_id"] for action in actions)
        action_points = {player["id"]: 0 for player in players}
        pending_actions = {player["id"]: 0 for player in players}
        action_rows = []
        for action in actions:
            tier = starting_tiers.get(action["target_id"], "bottom")
            matchup = current_match(db, campaign_id, round_number, action["target_id"])
            outcome = "Pending"
            points = None
            if matchup and matchup["player_two"] is None:
                outcome = "BYE"
                points = 0
            elif matchup:
                scores = db.execute("SELECT user_id, moonstones, victory_points FROM duel_scores WHERE campaign_id = ? AND round_number = ? AND user_id IN (?, ?)",
                                    (campaign_id, round_number, matchup["player_one"], matchup["player_two"])).fetchall()
                by_user = {score["user_id"]: score for score in scores}
                if len(by_user) == 2 and duel_result_confirmed(db, campaign_id, round_number, matchup):
                    target_score = by_user[action["target_id"]]
                    opponent_id = matchup["player_two"] if matchup["player_one"] == action["target_id"] else matchup["player_one"]
                    target_vp = target_score["moonstones"] + target_score["victory_points"]
                    opponent_vp = by_user[opponent_id]["moonstones"] + by_user[opponent_id]["victory_points"]
                    if target_vp > opponent_vp:
                        outcome = "Won"
                        points = machination_points_for(action["kind"], tier, "won")
                    elif target_vp < opponent_vp:
                        outcome = "Lost"
                        points = machination_points_for(action["kind"], tier, "lost")
                    else:
                        outcome = "Draw"
                        points = 0
            if points is None:
                pending_actions[action["actor_id"]] += 1
            else:
                action_points[action["actor_id"]] += points
            action_rows.append({"actor_name": action["actor_name"], "target_name": action["target_name"],
                                "kind": action["kind"], "tier": tier.title(), "outcome": outcome,
                                "points": points})

        overflow = {row["user_id"]: row["machination_points"] for row in db.execute(
            "SELECT user_id, machination_points FROM machination_results WHERE campaign_id = ? AND round_number = ?",
            (campaign_id, round_number))}
        round_active_ids = campaign_active_player_ids(db, campaign_id, round_number)
        player_totals = []
        for player in players:
            user_id = player["id"]
            if user_id not in round_active_ids:
                continue
            player_totals.append({"name": player["name"],
                                  "submission": "Submitted · no machinations" if user_id in submitted_ids and not any(a["actor_id"] == user_id for a in actions) else "Submitted" if user_id in submitted_ids else "Not submitted",
                                  "action_points": action_points[user_id],
                                  "pending_actions": pending_actions[user_id],
                                  "overflow_points": overflow.get(user_id, 0),
                                  "total_points": action_points[user_id] + overflow.get(user_id, 0)})
        rounds.append({"number": round_number, "hidden": False, "actions": action_rows,
                       "players": player_totals})

    return render_template("machinations_admin.html", campaign=campaign, rounds=rounds)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
