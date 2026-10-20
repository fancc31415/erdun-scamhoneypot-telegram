"""情报抽取：LLM 结构化抽取 + 正则兜底，结果写入数据库。"""
import os
import re

import anthropic

import db

MODEL = os.getenv("CLAUDE_EXTRACT_MODEL", os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5"))
client = anthropic.Anthropic()

INTEL_TOOL = {
    "name": "record_scam_intel",
    "description": "记录从诈骗对话中抽取的结构化情报。只记录对话中对方（诈骗者）明确给出的信息，不要编造。",
    "input_schema": {
        "type": "object",
        "properties": {
            "is_scam": {"type": "boolean", "description": "对方是否确为诈骗"},
            "confidence": {"type": "number", "description": "0-1"},
            "scam_type": {
                "type": "string",
                "description": "如：冒充公检法、冒充客服退款、刷单返利、虚假投资理财、杀猪盘、冒充熟人、贷款诈骗、其他",
            },
            "impersonated_entity": {"type": "string", "description": "冒充的机构或身份"},
            "stage": {
                "type": "string",
                "enum": ["接触", "建立信任", "制造紧迫感", "索要信息", "索要资金", "已结束"],
            },
            "bank_accounts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "account_number": {"type": "string"},
                        "holder_name": {"type": "string"},
                        "bank": {"type": "string"},
                    },
                    "required": ["account_number"],
                },
            },
            "payment_accounts": {
                "type": "array", "items": {"type": "string"},
                "description": "支付宝/微信/PayPal 等收款账号",
            },
            "crypto_wallets": {"type": "array", "items": {"type": "string"}},
            "phone_numbers": {"type": "array", "items": {"type": "string"}},
            "social_accounts": {"type": "array", "items": {"type": "string"}, "description": "QQ、微信号、Telegram 等"},
            "urls": {"type": "array", "items": {"type": "string"}},
            "apps": {"type": "array", "items": {"type": "string"}, "description": "要求下载的 APP 名称"},
            "claimed_ids": {"type": "array", "items": {"type": "string"}, "description": "工号、警号、案件编号等"},
            "tactics": {"type": "array", "items": {"type": "string"}, "description": "使用的话术/心理操控手法，简述"},
            "summary": {"type": "string", "description": "一句话概括这次诈骗"},
        },
        "required": ["is_scam", "confidence", "scam_type", "stage", "summary"],
    },
}

# 正则兜底（会有误报，标记 source=regex，供人工复核）
REGEXES = {
    "url": re.compile(r"(?:https?://|www\.)[^\s<>\"'，。]+", re.I),
    "crypto_wallet": re.compile(
        r"\b(?:0x[a-fA-F0-9]{40}"            # ETH / BSC / ERC20
        r"|T[1-9A-HJ-NP-Za-km-z]{33}"        # TRON (TRC20 USDT)
        r"|bc1[a-z0-9]{25,59}"               # BTC bech32
        r"|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"  # BTC legacy
    ),
    "phone": re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"),
    "bank_account": re.compile(r"(?<!\d)(?:\d[ -]?){15,18}\d(?!\d)"),
}


def luhn_ok(num: str) -> bool:
    digits = [int(d) for d in num if d.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return total % 10 == 0


def regex_extract(text: str) -> list[tuple[str, str]]:
    found = []
    for kind, rx in REGEXES.items():
        for m in rx.findall(text):
            v = re.sub(r"[ -]", "", m) if kind in ("bank_account", "phone") else m
            if kind == "bank_account" and not luhn_ok(v):
                continue
            found.append((kind, v))
    return found


def transcript(history: list[dict]) -> str:
    return "\n".join(f"[{'对方' if m['role']=='scammer' else '诱饵'}] {m['content']}" for m in history)


def extract(cid: str) -> dict | None:
    history = db.get_messages(cid, limit=200)
    if not history:
        return None

    # 1) 正则：只扫描对方发的内容
    scammer_text = "\n".join(m["content"] for m in history if m["role"] == "scammer")
    for kind, v in regex_extract(scammer_text):
        db.add_indicator(cid, kind, v, "regex")

    # 2) LLM 结构化抽取
    resp = client.messages.create(
        model=MODEL,
        max_tokens=1500,
        system="你是反诈骗情报分析员。阅读对话记录，只抽取“对方”给出的信息，调用工具记录。",
        tools=[INTEL_TOOL],
        tool_choice={"type": "tool", "name": "record_scam_intel"},
        messages=[{"role": "user", "content": transcript(history)}],
    )
    data = next((b.input for b in resp.content if b.type == "tool_use"), None)
    if not data:
        return None

    db.save_intel(cid, data)
    for acct in data.get("bank_accounts", []):
        label = " / ".join(x for x in (acct.get("account_number"), acct.get("holder_name"), acct.get("bank")) if x)
        db.add_indicator(cid, "bank_account", label, "llm")
    for kind, key in [
        ("payment_account", "payment_accounts"),
        ("crypto_wallet", "crypto_wallets"),
        ("phone", "phone_numbers"),
        ("social", "social_accounts"),
        ("url", "urls"),
        ("app", "apps"),
    ]:
        for v in data.get(key, []):
            db.add_indicator(cid, kind, v, "llm")
    return data
