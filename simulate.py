"""本地测试：你在命令行里扮演骗子，和诱饵对话。不需要 Telegram。

运行：
    python simulate.py                     # 默认人设王阿姨，普通版
    python simulate.py li_shushu           # 指定人设
    python simulate.py li_shushu --agent   # Agent 版：会显示它调用了哪些工具

输入 /intel 查看当前抽取的情报，/quit 退出。
"""
import argparse
import json
import uuid

from dotenv import load_dotenv

load_dotenv()

import agent  # noqa: E402
import db  # noqa: E402
import decoy_agent  # noqa: E402
import extractor  # noqa: E402
from persona import PERSONAS  # noqa: E402


def show_trace(trace: list):
    for t in trace:
        args = json.dumps(t["input"], ensure_ascii=False)
        out = json.dumps(t["output"], ensure_ascii=False)
        print(f"   [工具] {t['tool']} {args} -> {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("persona", nargs="?", default="wang_ayi", choices=list(PERSONAS))
    ap.add_argument("--agent", action="store_true", help="使用 Agent 版诱饵")
    args = ap.parse_args()

    db.init()
    cid = f"sim:{uuid.uuid4().hex[:8]}"
    db.ensure_conversation(cid, "simulator", args.persona)
    mode = "Agent 版" if args.agent else "普通版"
    print(f"会话 {cid}，人设 {args.persona}，{mode}。你来扮演骗子。/intel 查看情报，/quit 退出。\n")

    while True:
        try:
            text = input("骗子> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not text:
            continue
        if text == "/quit":
            break
        if text == "/intel":
            print(json.dumps(extractor.extract(cid), ensure_ascii=False, indent=2))
            continue

        db.add_message(cid, "scammer", text)
        if args.agent:
            trace: list = []
            reply = decoy_agent.respond(cid, args.persona, trace)
            show_trace(trace)
        else:
            reply = agent.reply(db.get_messages(cid), args.persona)

        if reply:
            db.add_message(cid, "bot", reply)
            print(f"诱饵> {reply}\n")
        if args.agent and db.is_ended(cid):
            print("（诱饵已结束对话）")
            break

    print("\n最终情报：")
    print(json.dumps(extractor.extract(cid), ensure_ascii=False, indent=2))
    alerts = db.get_alerts(cid)
    if alerts:
        print("\n告警：")
        for a in alerts:
            print(f"  [{a['level']}] {a['reason']}")


if __name__ == "__main__":
    main()
