
"""ZAD OSINT - Secure Video Portal (Flask + SQLite/PostgreSQL). Deploy on Render."""

import os
import re
import time
import hmac
import secrets
import string
import sqlite3

from datetime import timedelta
from urllib.parse import urlparse

import requests

from flask import (
    Flask, Response, abort, flash, g, redirect, render_template,
    request, session, stream_with_context, url_for
)

from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.middleware.proxy_fix import ProxyFix


# ---------------- DOTENV ----------------

def _load_dotenv():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

    if not os.path.exists(p):
        return

    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(
                    k.strip(),
                    v.strip().strip('"').strip("'")
                )


_load_dotenv()


# ---------------- CONFIG ----------------

SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "change-me-now")

DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(__file__), "data.db")
)

YT_URL = "https://www.youtube.com/@zadosint"
BRAND = "ZAD OSINT"

CATS = {
    "free": "RF Free",
    "paid": "RF Paid"
}


app = Flask(__name__)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1
)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("INSECURE_COOKIES") != "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=365),
    MAX_CONTENT_LENGTH=64 * 1024,
)

signer = URLSafeTimedSerializer(
    SECRET_KEY,
    salt="stream"
)


# ---------------- LANGUAGES ----------------

TR = {
    "en": {
        "home": "Home",
        "history": "My History",
        "hero_t": "Unlock. Watch. Learn.",
        "hero_s": "Pick a category, enter your video code and start watching.",
        "choose": "Choose a category",
        "free_d": "Free videos for everyone",
        "paid_d": "Premium paid videos",
        "videos": "videos",
        "enter": "Enter your video code",
        "ph": "e.g. ZAD-AB12CD",
        "unlock": "Unlock Video",
        "noc": "Don't have a code?",
        "getc": "Watch on YouTube to get the code",
        "bad": "Invalid code for this category.",
        "wait": "Too many attempts. Try again in a minute.",
        "getf": "Get File",
        "yt": "Open YouTube Channel",
        "back": "Back",
        "nohist": "No videos watched yet.",
        "views": "views",
        "cat": "Category",
        "code": "Code",
        "watched": "Last watched",
        "again": "Watch again",
        "sub": "Subscribe for new codes"
    },

    "hi": {
        "home": "होम",
        "history": "मेरी हिस्ट्री",
        "hero_t": "अनलॉक करो. देखो. सीखो.",
        "hero_s": "कैटेगरी चुनो, वीडियो कोड डालो और देखना शुरू करो.",
        "choose": "कैटेगरी चुनें",
        "free_d": "सभी के लिए फ्री वीडियो",
        "paid_d": "प्रीमियम पेड वीडियो",
        "videos": "वीडियो",
        "enter": "अपना वीडियो कोड डालें",
        "ph": "जैसे ZAD-AB12CD",
        "unlock": "वीडियो अनलॉक करें",
        "noc": "कोड नहीं है?",
        "getc": "कोड के लिए YouTube वीडियो देखें",
        "bad": "इस कैटेगरी के लिए कोड गलत है.",
        "wait": "बहुत ज्यादा कोशिशें. एक मिनट बाद try करें.",
        "getf": "फाइल पाएं",
        "yt": "YouTube चैनल खोलें",
        "back": "वापस",
        "nohist": "अभी तक कोई वीडियो नहीं देखा.",
        "views": "व्यूज",
        "cat": "कैटेगरी",
        "code": "कोड",
        "watched": "आखिरी बार देखा",
        "again": "फिर देखें",
        "sub": "नए कोड के लिए Subscribe करें"
    }
}


# ---------------- DATABASE CONFIG ----------------

def _clean_url(u):

    u = (u or "").strip().strip('"').strip("'")

    if u.upper().startswith("DATABASE_URL="):
        u = u.split("=", 1)[1].strip().strip('"').strip("'")

    return re.sub(
        r"^postgres(ql)?(\+\w+)?://",
        "postgresql://",
        u
    )


DATABASE_URL = _clean_url(
    os.environ.get("DATABASE_URL", "")
)

USE_PG = DATABASE_URL.startswith("postgresql://")

DB_ERROR = ""

IntegrityErrors = (sqlite3.IntegrityError,)


if USE_PG:

    import psycopg2
    import psycopg2.extras

    if "sslmode=" not in DATABASE_URL:
        DATABASE_URL += (
            "&" if "?" in DATABASE_URL else "?"
        ) + "sslmode=require"

    IntegrityErrors = (
        sqlite3.IntegrityError,
        psycopg2.IntegrityError
    )

elif os.environ.get("DATABASE_URL"):

    DB_ERROR = (
        "DATABASE_URL value is not a valid postgresql:// link"
    )


def _mask(text):

    try:
        pw = re.search(
            r"://[^:/@]+:([^@]+)@",
            DATABASE_URL
        ).group(1)

        return str(text).replace(pw, "****")

    except Exception:
        return str(text)


# ---------------- DATABASE CLASS ----------------

class DB:

    def __init__(self):

        if USE_PG:

            self.c = psycopg2.connect(
                DATABASE_URL,
                connect_timeout=15,
                cursor_factory=psycopg2.extras.RealDictCursor
            )

        else:

            self.c = sqlite3.connect(
                DB_PATH,
                timeout=15
            )

            self.c.row_factory = sqlite3.Row

            self.c.execute("PRAGMA foreign_keys=ON")


    def execute(self, sql, params=()):

        if USE_PG:

            cur = self.c.cursor()

            cur.execute(
                sql.replace("?", "%s"),
                params
            )

            return cur

        return self.c.execute(sql, params)


    def commit(self):
        self.c.commit()


    def rollback(self):
        self.c.rollback()


    def close(self):

        try:
            self.c.close()

        except Exception:
            pass


def db():

    if "db" not in g:
        g.db = DB()

    return g.db


@app.teardown_appcontext
def close_db(_):

    d = g.pop("db", None)

    if d:
        d.close()


# ---------------- DATABASE INITIALIZATION + MIGRATION ----------------

def init_db():

    pk = (
        "SERIAL PRIMARY KEY"
        if USE_PG
        else "INTEGER PRIMARY KEY AUTOINCREMENT"
    )

    big = "BIGINT" if USE_PG else "INTEGER"

    stmts = [

        f"""
        CREATE TABLE IF NOT EXISTS videos(
            id {pk},
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            code TEXT NOT NULL,
            mp4_url TEXT NOT NULL,
            file_url TEXT DEFAULT '',
            description TEXT DEFAULT '',
            views INTEGER DEFAULT 0,
            created {big} NOT NULL
        )
        """,

        """
        CREATE UNIQUE INDEX IF NOT EXISTS videos_code_ci
        ON videos(lower(code))
        """,

        f"""
        CREATE TABLE IF NOT EXISTS portal_users(
            uid TEXT PRIMARY KEY,
            first_seen {big},
            last_seen {big}
        )
        """,

        f"""
        CREATE TABLE IF NOT EXISTS history(
            id {pk},
            uid TEXT NOT NULL,
            video_id INTEGER NOT NULL
                REFERENCES videos(id) ON DELETE CASCADE,
            watched_at {big} NOT NULL,
            count INTEGER DEFAULT 1,
            UNIQUE(uid, video_id)
        )
        """
    ]

    last = None

    for attempt in range(4):

        d = None

        try:

            d = DB()

            if not USE_PG:
                d.execute("PRAGMA journal_mode=WAL")

            # Create missing tables and indexes
            for q in stmts:
                d.execute(q)

            # IMPORTANT:
            # Keep portal visitor tracking separate from any legacy users table.
            # Existing records and tables are NOT deleted.

            if USE_PG:

                d.execute("""
                    ALTER TABLE portal_users
                    ADD COLUMN IF NOT EXISTS uid TEXT
                """)

                d.execute("""
                    ALTER TABLE portal_users
                    ADD COLUMN IF NOT EXISTS first_seen BIGINT
                """)

                d.execute("""
                    ALTER TABLE portal_users
                    ADD COLUMN IF NOT EXISTS last_seen BIGINT
                """)

                d.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS users_uid_unique
                    ON portal_users(uid)
                """)

            d.commit()
            d.close()

            print(
                "DATABASE INITIALIZED SUCCESSFULLY",
                flush=True
            )

            return

        except Exception as e:

            last = e

            if d:
                try:
                    d.rollback()
                    d.close()
                except Exception:
                    pass

            print(
                "DB init failed (try %d): %s"
                % (attempt + 1, _mask(e)[:200]),
                flush=True
            )

            time.sleep(3)

    raise last


try:

    init_db()

except Exception as _e:

    if not USE_PG:
        raise

    print(
        "WARNING: Postgres initialization failed: "
        + _mask(_e)[:300],
        flush=True
    )

    DB_ERROR = (
        "Postgres connection/schema failed ("
        + type(_e).__name__
        + "). Check DATABASE_URL and database schema."
    )

    # Do not silently switch to temporary SQLite.
    # Doing so would make the website appear to work
    # while losing persistent database functionality.

    raise


# ---------------- SECURITY HELPERS ----------------

_hits = {}


def limited(key, limit, window=60):

    now = time.time()

    lst = [
        x for x in _hits.get(key, [])
        if now - x < window
    ]

    if len(lst) >= limit:

        _hits[key] = lst

        return True

    lst.append(now)

    _hits[key] = lst

    if len(_hits) > 5000:
        _hits.clear()

    return False


def valid_url(u):

    try:

        p = urlparse(u)

        return (
            p.scheme in ("http", "https")
            and bool(p.netloc)
            and len(u) < 2000
        )

    except Exception:

        return False


def gen_code():

    a = string.ascii_uppercase + string.digits

    return "ZAD-" + "".join(
        secrets.choice(a)
        for _ in range(6)
    )


# ---------------- REQUEST GUARD ----------------

@app.before_request
def guard():

    session.permanent = True

    if "uid" not in session:
        session["uid"] = secrets.token_hex(16)

    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)

    now = int(time.time())

    if (
        request.endpoint not in ("static", "stream", "healthz")
        and now - session.get("seen", 0) > 300
    ):

        db().execute(
            """
            INSERT INTO portal_users(uid,first_seen,last_seen)
            VALUES(?,?,?)
            ON CONFLICT(uid)
            DO UPDATE SET last_seen=excluded.last_seen
            """,
            (
                session["uid"],
                now,
                now
            )
        )

        db().commit()

        session["seen"] = now

    if request.method == "POST":

        if not hmac.compare_digest(
            request.form.get("csrf", ""),
            session["csrf"]
        ):

            abort(400)


# ---------------- SECURITY HEADERS ----------------

@app.after_request
def headers(r):

    r.headers["X-Content-Type-Options"] = "nosniff"

    r.headers["X-Frame-Options"] = "DENY"

    r.headers["Referrer-Policy"] = "same-origin"

    r.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    r.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )

    r.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https://cdn.plyr.io; "
        "media-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src https://cdn.jsdelivr.net; "
        "connect-src 'self' https://cdn.plyr.io; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    if request.endpoint not in ("static",):
        r.headers["Cache-Control"] = "no-store"

    return r


# ---------------- TEMPLATE CONTEXT ----------------

@app.context_processor
def ctx():

    lang = session.get("lang", "en")

    return {
        "t": lambda k: TR[lang].get(k, k),
        "lang": lang,
        "csrf": session.get("csrf", ""),
        "YT_URL": YT_URL,
        "BRAND": BRAND,
        "CATS": CATS,
        "DB_ERROR": DB_ERROR
    }


# ---------------- USER ROUTES ----------------

@app.route("/lang/<code>")
def lang(code):

    if code in TR:
        session["lang"] = code

    return redirect(
        request.referrer
        if (
            request.referrer or ""
        ).startswith(request.host_url)
        else url_for("index")
    )


@app.route("/")
def index():

    counts = {
        r["category"]: r["n"]
        for r in db().execute(
            """
            SELECT category, COUNT(*) AS n
            FROM videos
            GROUP BY category
            """
        )
    }

    return render_template(
        "index.html",
        counts=counts
    )


@app.route("/c/<cat>", methods=["GET", "POST"])
def category(cat):

    if cat not in CATS:
        abort(404)

    if request.method == "POST":

        if limited(
            "code:" + (request.remote_addr or ""),
            12
        ):

            flash("wait", "err")

            return render_template(
                "category.html",
                cat=cat
            ), 429

        code = request.form.get(
            "code",
            ""
        ).strip()[:40]

        v = (
            db().execute(
                """
                SELECT id FROM videos
                WHERE lower(code)=lower(?)
                AND category=?
                """,
                (code, cat)
            ).fetchone()
            if code
            else None
        )

        if not v:

            flash("bad", "err")

            return render_template(
                "category.html",
                cat=cat
            )

        now = int(time.time())

        db().execute(
            """
            INSERT INTO history(uid,video_id,watched_at)
            VALUES(?,?,?)
            ON CONFLICT(uid,video_id)
            DO UPDATE SET
                watched_at=excluded.watched_at,
                count=history.count+1
            """,
            (
                session["uid"],
                v["id"],
                now
            )
        )

        db().commit()

        return redirect(
            url_for(
                "watch",
                vid=v["id"]
            )
        )

    return render_template(
        "category.html",
        cat=cat
    )


@app.route("/watch/<int:vid>")
def watch(vid):

    ok = db().execute(
        """
        SELECT 1 FROM history
        WHERE uid=? AND video_id=?
        """,
        (
            session["uid"],
            vid
        )
    ).fetchone()

    v = db().execute(
        """
        SELECT * FROM videos
        WHERE id=?
        """,
        (vid,)
    ).fetchone()

    if not v or not ok:
        return redirect(url_for("index"))

    db().execute(
        """
        UPDATE videos
        SET views=views+1
        WHERE id=?
        """,
        (vid,)
    )

    db().commit()

    token = signer.dumps({
        "v": vid,
        "u": session["uid"]
    })

    return render_template(
        "watch.html",
        v=v,
        token=token
    )


@app.route("/stream/<int:vid>")
def stream(vid):

    try:

        d = signer.loads(
            request.args.get("t", ""),
            max_age=6 * 3600
        )

    except BadSignature:

        abort(403)

    if (
        d.get("v") != vid
        or d.get("u") != session.get("uid")
    ):

        abort(403)

    v = db().execute(
        """
        SELECT mp4_url FROM videos
        WHERE id=?
        """,
        (vid,)
    ).fetchone()

    if not v:
        abort(404)

    h = {
        "User-Agent": "Mozilla/5.0"
    }

    if request.headers.get("Range"):
        h["Range"] = request.headers["Range"]

    try:

        r = requests.get(
            v["mp4_url"],
            headers=h,
            stream=True,
            timeout=(10, 30)
        )

    except requests.RequestException:

        abort(502)

    if r.status_code >= 400:

        r.close()

        abort(502)

    out = {
        k: r.headers[k]
        for k in (
            "Content-Length",
            "Content-Range",
            "Accept-Ranges"
        )
        if k in r.headers
    }

    out["Content-Type"] = r.headers.get(
        "Content-Type",
        "video/mp4"
    )

    out["Cache-Control"] = "private, max-age=3600"

    def gen():

        try:

            for chunk in r.iter_content(64 * 1024):

                if chunk:
                    yield chunk

        finally:

            r.close()

    return Response(
        stream_with_context(gen()),
        status=r.status_code,
        headers=out
    )


@app.route("/history")
def history():

    rows = db().execute(
        """
        SELECT
            v.id,
            v.title,
            v.category,
            v.code,
            h.watched_at,
            h.count
        FROM history h
        JOIN videos v ON v.id=h.video_id
        WHERE h.uid=?
        ORDER BY h.watched_at DESC
        """,
        (session["uid"],)
    ).fetchall()

    return render_template(
        "history.html",
        rows=rows
    )


@app.template_filter("dt")
def dt(ts):

    return (
        time.strftime(
            "%d %b %Y, %H:%M",
            time.gmtime(ts)
        )
        + " UTC"
    )


# ---------------- ADMIN ----------------

def admin_only(f):

    from functools import wraps

    @wraps(f)
    def w(*a, **k):

        if (
            not session.get("admin")
            or time.time() - session.get("admin_ts", 0) > 7200
        ):

            session.pop("admin", None)

            return redirect(
                url_for("admin_login")
            )

        return f(*a, **k)

    return w


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        if limited(
            "adm:" + (request.remote_addr or ""),
            5,
            300
        ):

            flash(
                "Too many attempts. Wait 5 minutes.",
                "err"
            )

            return render_template(
                "admin_login.html"
            ), 429

        u = request.form.get("u", "")
        p = request.form.get("p", "")

        if (
            hmac.compare_digest(
                u.encode(),
                ADMIN_USER.encode()
            )
            &
            hmac.compare_digest(
                p.encode(),
                ADMIN_PASS.encode()
            )
        ):

            session["admin"] = True
            session["admin_ts"] = time.time()

            return redirect(
                url_for("admin")
            )

        flash(
            "Wrong credentials.",
            "err"
        )

    return render_template(
        "admin_login.html"
    )


@app.route("/admin/logout", methods=["POST"])
def admin_logout():

    session.pop("admin", None)

    return redirect(
        url_for("index")
    )


@app.route("/admin")
@admin_only
def admin():

    d = db()

    stats = {

        "total": d.execute(
            "SELECT COUNT(*) AS n FROM videos"
        ).fetchone()["n"],

        "free": d.execute(
            """
            SELECT COUNT(*) AS n
            FROM videos
            WHERE category='free'
            """
        ).fetchone()["n"],

        "paid": d.execute(
            """
            SELECT COUNT(*) AS n
            FROM videos
            WHERE category='paid'
            """
        ).fetchone()["n"],

        "views": d.execute(
            """
            SELECT COALESCE(SUM(views),0) AS n
            FROM videos
            """
        ).fetchone()["n"],

        "users": d.execute(
            "SELECT COUNT(*) AS n FROM portal_users"
        ).fetchone()["n"]
    }

    vids = d.execute(
        """
        SELECT * FROM videos
        ORDER BY id DESC
        """
    ).fetchall()

    recent = d.execute(
        """
        SELECT
            substr(h.uid,1,8) AS u,
            v.title,
            h.watched_at
        FROM history h
        JOIN videos v ON v.id=h.video_id
        ORDER BY h.watched_at DESC
        LIMIT 10
        """
    ).fetchall()

    edit = None

    if request.args.get("edit", "").isdigit():

        edit = d.execute(
            """
            SELECT * FROM videos
            WHERE id=?
            """,
            (int(request.args["edit"]),)
        ).fetchone()

    return render_template(
        "admin.html",
        stats=stats,
        vids=vids,
        recent=recent,
        edit=edit
    )


@app.route("/admin/save", methods=["POST"])
@admin_only
def admin_save():

    f = request.form

    title = f.get(
        "title",
        ""
    ).strip()[:150]

    cat = f.get(
        "category",
        ""
    )

    mp4 = f.get(
        "mp4_url",
        ""
    ).strip()

    fu = f.get(
        "file_url",
        ""
    ).strip()

    desc = f.get(
        "description",
        ""
    ).strip()[:1000]

    code = f.get(
        "code",
        ""
    ).strip()[:40] or gen_code()

    vid = f.get(
        "id",
        ""
    )

    if (
        not title
        or cat not in CATS
        or not valid_url(mp4)
        or (fu and not valid_url(fu))
    ):

        flash(
            "Check title, category and URLs (must start with http/https).",
            "err"
        )

        return redirect(
            url_for(
                "admin",
                edit=vid
            )
            if vid.isdigit()
            else url_for("admin")
        )

    try:

        if vid.isdigit():

            db().execute(
                """
                UPDATE videos
                SET
                    title=?,
                    category=?,
                    code=?,
                    mp4_url=?,
                    file_url=?,
                    description=?
                WHERE id=?
                """,
                (
                    title,
                    cat,
                    code,
                    mp4,
                    fu,
                    desc,
                    int(vid)
                )
            )

        else:

            db().execute(
                """
                INSERT INTO videos(
                    title,
                    category,
                    code,
                    mp4_url,
                    file_url,
                    description,
                    created
                )
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    title,
                    cat,
                    code,
                    mp4,
                    fu,
                    desc,
                    int(time.time())
                )
            )

        db().commit()

        flash(
            "Saved. Code: " + code,
            "ok"
        )

    except IntegrityErrors:

        db().rollback()

        flash(
            "This code already exists. Use another.",
            "err"
        )

    return redirect(
        url_for("admin")
    )


@app.route("/admin/delete/<int:vid>", methods=["POST"])
@admin_only
def admin_delete(vid):

    db().execute(
        """
        DELETE FROM videos
        WHERE id=?
        """,
        (vid,)
    )

    db().commit()

    flash(
        "Deleted.",
        "ok"
    )

    return redirect(
        url_for("admin")
    )


# ---------------- HEALTH CHECK ----------------

@app.route("/healthz")
def healthz():

    db().execute(
        "SELECT 1"
    ).fetchone()

    msg = (
        "ok postgres"
        if USE_PG
        else "ok sqlite"
    )

    return msg, 200, {
        "Content-Type": "text/plain"
    }


# ---------------- ERROR HANDLERS ----------------

@app.errorhandler(500)
def err500(_):

    return render_template(
        "msg.html",
        m="500 - Server/database error. Try again in a minute."
    ), 500


@app.errorhandler(404)
def nf(_):

    return render_template(
        "msg.html",
        m="404 - Not found"
    ), 404


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(502)
def bad(e):

    return render_template(
        "msg.html",
        m=f"{e.code} - Request blocked / unavailable"
    ), e.code


# ---------------- START ----------------

if __name__ == "__main__":

    os.environ.setdefault(
        "INSECURE_COOKIES",
        "1"
    )

    app.config["SESSION_COOKIE_SECURE"] = False

    app.run(
        debug=True,
        port=5000
    )
