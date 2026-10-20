"""情报看板：python dashboard.py 后打开 http://localhost:8000"""
import html
import json
from datetime import datetime

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

import db

app = FastAPI(title="Scam Honeypot Intel")


def fmt(ts):
    return datetime.fromtimestamp(ts).strftime("%m-%d %H:%M") if ts else ""


@app.get("/api/data")
def api_data():
    return JSONResponse(db.dashboard_data())


@app.get("/api/conversation/{cid}")
def api_conv(cid: str):
    return JSONResponse(db.get_messages(cid, limit=1000))


@app.get("/", response_class=HTMLResponse)
def index():
    d = db.dashboard_data()
    e = html.escape
    conv_rows = []
    for c in d["conversations"]:
        intel = json.loads(c["intel"]) if c["intel"] else {}
        status = f"已结束：{e(c['end_reason'] or '')}" if c.get("ended") else "进行中"
        conv_rows.append(
            f"<tr><td>{e(c['id'])}</td><td>{status}</td><td>{e(c['persona'])}</td>"
            f"<td>{e(intel.get('scam_type',''))}</td><td>{e(intel.get('stage',''))}</td>"
            f"<td>{c['n_msgs']}</td><td>{round((c['last_at']-c['started_at'])/60)} 分钟</td>"
            f"<td>{e(intel.get('summary',''))}</td></tr>"
        )
    ind_rows = [
        f"<tr><td>{e(i['kind'])}</td><td><code>{e(i['value'])}</code></td>"
        f"<td>{i['n_convs']}</td><td>{fmt(i['first_seen'])}</td></tr>"
        for i in d["indicators"]
    ]
    level_name = {"high": "高", "info": "一般", "guard": "代码拦截"}
    alert_rows = [
        f"<tr class='{e(a['level'])}'><td>{fmt(a['ts'])}</td><td>{level_name.get(a['level'], e(a['level']))}</td>"
        f"<td>{e(a['conversation_id'])}</td><td>{e(a['reason'])}</td></tr>"
        for a in d["alerts"]
    ]
    n_high = sum(1 for a in d["alerts"] if a["level"] == "high")
    total_min = sum((c["last_at"] - c["started_at"]) for c in d["conversations"]) / 60
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>反诈情报看板</title>
<meta http-equiv="refresh" content="30">
<style>body{{font-family:system-ui,sans-serif;margin:24px;color:#222}}
table{{border-collapse:collapse;width:100%;margin-bottom:32px}}
td,th{{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left;font-size:14px}}
th{{background:#f5f5f5}} .k{{display:inline-block;margin-right:32px}} .k b{{font-size:28px;display:block}}
tr.high td{{color:#a32d2d}} tr.guard td{{color:#854f0b}}</style>
</head><body><h1>反诈蜜罐情报看板</h1>
<div class="k"><b>{len(d['conversations'])}</b>会话</div>
<div class="k"><b>{len(d['indicators'])}</b>情报指标</div>
<div class="k"><b>{total_min:.0f}</b>拖住骗子的分钟数</div>
<div class="k"><b>{n_high}</b>高级告警</div>
<h2>告警</h2>
<table><tr><th>时间</th><th>级别</th><th>会话</th><th>原因</th></tr>{''.join(alert_rows) or '<tr><td colspan=4>暂无</td></tr>'}</table>
<h2>情报指标（账户 / 钱包 / 电话 / 链接）</h2>
<table><tr><th>类型</th><th>值</th><th>出现会话数</th><th>首次发现</th></tr>{''.join(ind_rows)}</table>
<h2>会话</h2>
<table><tr><th>会话</th><th>状态</th><th>人设</th><th>诈骗类型</th><th>阶段</th><th>消息数</th><th>时长</th><th>摘要</th></tr>{''.join(conv_rows)}</table>
</body></html>"""


if __name__ == "__main__":
    db.init()
    uvicorn.run(app, host="127.0.0.1", port=8000)
