"""SQLite 存储：会话、消息、情报、告警。生产环境可换成 Postgres。"""
import json
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = "honeypot.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,           -- 渠道:对方ID，如 telegram:123456
    channel TEXT,
    persona TEXT,
    started_at REAL,
    last_at REAL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT,
    role TEXT,                     -- scammer / bot
    content TEXT,
    ts REAL
);
CREATE TABLE IF NOT EXISTS intel (
    conversation_id TEXT PRIMARY KEY,
    data TEXT,                     -- LLM 结构化抽取结果(JSON)
    updated_at REAL
);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT,
    kind TEXT,                     -- bank_account / crypto_wallet / phone / url / app / social ...
    value TEXT,
    source TEXT,                   -- llm / regex / agent
    first_seen REAL,
    UNIQUE(conversation_id, kind, value)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT,
    level TEXT,                    -- info / high / guard(代码拦截)
    reason TEXT,
    ts REAL
);
"""

# 旧版数据库升级：给 conversations 补上“是否结束”的字段
MIGRATIONS = [
    "ALTER TABLE conversations ADD COLUMN ended INTEGER DEFAULT 0",
    "ALTER TABLE conversations ADD COLUMN end_reason TEXT",
]


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn() as c:
        c.executescript(SCHEMA)
        for sql in MIGRATIONS:
            try:
                c.execute(sql)
            except sqlite3.OperationalError:
                pass  # 字段已存在


# ---------------------------------------------------------------------------
# 会话与消息
# ---------------------------------------------------------------------------
def ensure_conversation(cid: str, channel: str, persona: str):
    now = time.time()
    with conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO conversations (id, channel, persona, started_at, last_at) "
            "VALUES (?,?,?,?,?)",
            (cid, channel, persona, now, now),
        )


def get_persona(cid: str) -> str | None:
    with conn() as c:
        row = c.execute("SELECT persona FROM conversations WHERE id=?", (cid,)).fetchone()
        return row["persona"] if row else None


def mark_ended(cid: str, reason: str):
    with conn() as c:
        c.execute("UPDATE conversations SET ended=1, end_reason=? WHERE id=?", (reason, cid))


def is_ended(cid: str) -> bool:
    with conn() as c:
        row = c.execute("SELECT ended FROM conversations WHERE id=?", (cid,)).fetchone()
        return bool(row and row["ended"])


def add_message(cid: str, role: str, content: str):
    now = time.time()
    with conn() as c:
        c.execute(
            "INSERT INTO messages (conversation_id, role, content, ts) VALUES (?,?,?,?)",
            (cid, role, content, now),
        )
        c.execute("UPDATE conversations SET last_at=? WHERE id=?", (now, cid))


def get_messages(cid: str, limit: int = 60) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT role, content, ts FROM messages WHERE conversation_id=? "
            "ORDER BY id DESC LIMIT ?",
            (cid, limit),
        ).fetchall()
    return [dict(r) for r in reversed(rows)]


# ---------------------------------------------------------------------------
# 情报
# ---------------------------------------------------------------------------
def save_intel(cid: str, data: dict):
    with conn() as c:
        c.execute(
            "INSERT INTO intel VALUES (?,?,?) ON CONFLICT(conversation_id) "
            "DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
            (cid, json.dumps(data, ensure_ascii=False), time.time()),
        )


def add_indicator(cid: str, kind: str, value: str, source: str):
    value = value.strip()
    if not value:
        return
    with conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO indicators (conversation_id, kind, value, source, first_seen) "
            "VALUES (?,?,?,?,?)",
            (cid, kind, value, source, time.time()),
        )


def get_indicators(cid: str) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT DISTINCT kind, value, source FROM indicators WHERE conversation_id=? ORDER BY id",
            (cid,),
        ).fetchall()
    return [dict(r) for r in rows]


def indicator_seen_elsewhere(value: str, cid: str) -> int:
    """这个值在其他多少个会话里出现过（包含匹配，兼容“卡号 / 户名 / 银行”这类组合记录）。"""
    if not value:
        return 0
    with conn() as c:
        row = c.execute(
            "SELECT COUNT(DISTINCT conversation_id) AS n FROM indicators "
            "WHERE instr(value, ?) > 0 AND conversation_id != ?",
            (value, cid),
        ).fetchone()
    return row["n"]


def lookup_indicator(value: str, exclude_cid: str = "") -> dict:
    with conn() as c:
        rows = c.execute(
            "SELECT conversation_id, kind, MIN(first_seen) AS first_seen FROM indicators "
            "WHERE instr(value, ?) > 0 AND conversation_id != ? GROUP BY conversation_id, kind",
            (value, exclude_cid),
        ).fetchall()
    if not rows:
        return {"found": False}
    return {
        "found": True,
        "conversations": len({r["conversation_id"] for r in rows}),
        "kinds": sorted({r["kind"] for r in rows}),
        "first_seen": time.strftime("%Y-%m-%d %H:%M", time.localtime(min(r["first_seen"] for r in rows))),
    }


# ---------------------------------------------------------------------------
# 告警
# ---------------------------------------------------------------------------
def add_alert(cid: str, level: str, reason: str):
    with conn() as c:
        c.execute(
            "INSERT INTO alerts (conversation_id, level, reason, ts) VALUES (?,?,?,?)",
            (cid, level, reason, time.time()),
        )


def get_alerts(cid: str | None = None) -> list[dict]:
    with conn() as c:
        if cid:
            rows = c.execute("SELECT * FROM alerts WHERE conversation_id=? ORDER BY id", (cid,)).fetchall()
        else:
            rows = c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# 看板
# ---------------------------------------------------------------------------
def dashboard_data() -> dict:
    with conn() as c:
        convs = c.execute(
            """SELECT c.id, c.channel, c.persona, c.started_at, c.last_at, c.ended, c.end_reason,
                      (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id) AS n_msgs,
                      i.data AS intel
               FROM conversations c LEFT JOIN intel i ON i.conversation_id=c.id
               ORDER BY c.last_at DESC"""
        ).fetchall()
        inds = c.execute(
            """SELECT kind, value, COUNT(DISTINCT conversation_id) AS n_convs,
                      MIN(first_seen) AS first_seen
               FROM indicators GROUP BY kind, value ORDER BY n_convs DESC, first_seen DESC"""
        ).fetchall()
    return {
        "conversations": [dict(r) for r in convs],
        "indicators": [dict(r) for r in inds],
        "alerts": get_alerts(),
    }
