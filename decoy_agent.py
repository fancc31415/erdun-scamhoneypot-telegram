"""Agent 版诱饵：边聊边自己决定调用工具。

和普通版（agent.py）的区别：
- 普通版：每条消息固定调用一次 Claude 生成回复，什么时候抽取情报由代码写死。
- Agent 版：Claude 拿到一组工具，自己判断什么时候记录情报、查询情报库、告警、结束对话，
  工具调用对骗子完全不可见，最后输出的那句话才会发给骗子。

另外有一道代码层的安全防护（guard）：诱饵的回复里如果出现了骗子没说过的 6 位以上数字，
直接拦截并换成一句拖延的话，同时记一条告警。即使模型出错，也不会把“像真的”号码发出去。

启用方式：
    simulate.py  →  python simulate.py li_shushu --agent
    bot.py       →  在 .env 里设置 AGENT_MODE=1
    evaluate.py  →  python evaluate.py --agent
"""
import json
import logging
import re

import agent  # 复用 Claude 客户端、模型设置和消息格式转换
import db
from persona import build_system_prompt

log = logging.getLogger("decoy_agent")
MAX_STEPS = 6  # 每回复一条消息，最多连续调用几轮工具

TOOLS = [
    {
        "name": "record_intel",
        "description": (
            "记录对方刚说出的一条可追查的信息。每条信息单独调用一次。"
            "返回结果会告诉你这条信息是否在其他会话中出现过。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": [
                        "bank_account", "holder_name", "bank", "payment_account",
                        "crypto_wallet", "phone", "social", "url", "app",
                        "claimed_id", "person_name",
                    ],
                    "description": (
                        "bank_account 银行卡号；holder_name 收款户名；bank 开户行；"
                        "payment_account 支付宝/微信收款账号；crypto_wallet 钱包地址；phone 电话；"
                        "social 微信号/QQ号/Telegram 等；url 网址；app APP 名称；"
                        "claimed_id 工号/警号/案件编号；person_name 对方自称的姓名"
                    ),
                },
                "value": {"type": "string", "description": "原样抄录的信息，不要改写"},
            },
            "required": ["kind", "value"],
        },
    },
    {
        "name": "lookup_indicator",
        "description": "查询某个账户、号码、网址以前是否在其他会话中出现过。",
        "input_schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
        },
    },
    {
        "name": "raise_alert",
        "description": "向反诈分析人员发出告警。",
        "input_schema": {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": ["info", "high"]},
                "reason": {"type": "string", "description": "一句话说明告警原因"},
            },
            "required": ["level", "reason"],
        },
    },
    {
        "name": "end_conversation",
        "description": "结束本次对话，之后不再回复对方。",
        "input_schema": {
            "type": "object",
            "properties": {"reason": {"type": "string"}},
            "required": ["reason"],
        },
    },
]

AGENT_GUIDE = """
## 你的工具（对方完全看不到）
回复之前，你可以先调用工具。
- record_intel：对方一说出可追查的信息（卡号、户名、开户行、收款账号、钱包地址、电话、微信号、QQ 号、网址、APP 名称、工号、警号、案件编号、对方自称的姓名），立刻逐条记录。下方“已记录的情报”里有的，不要重复记录。
- lookup_indicator：想确认某个号码以前是否出现过时使用。record_intel 的返回结果已包含这个信息，一般不用再查。
- raise_alert：以下情况告警。
  high：某条情报在其他会话中出现过（说明是同一团伙）；对方给出了加密货币钱包地址；对方提到了真实第三方受害人的信息。
  info：对方使用了新的诈骗话术或新的收款方式。
- end_conversation：只在以下情况使用：对方明显不是骗子；你已如实承认自己是 AI；对方明确放弃或拉黑。不要因为聊得久就结束，拖得越久越好。

## 输出规则
- 工具调用完成后，你最后输出的文字会原样发送给对方，所以只写人设要说的那一句话。
- 发给对方的文字里，绝不能提到工具、记录、情报、告警这些词。
- 结束对话时，可以写一句符合人设的告别，也可以什么都不写。
"""


# ---------------------------------------------------------------------------
# 安全防护
# ---------------------------------------------------------------------------
def _norm(s: str) -> str:
    return re.sub(r"[\s\-()（）_]", "", str(s)).lower()


def new_digit_strings(text: str, history: list[dict]) -> list[str]:
    """text 中 6 位以上、且骗子从没说过的数字串。"""
    scammer = _norm("".join(m["content"] for m in history if m["role"] == "scammer"))
    found = []
    for d in re.findall(r"\d[\d\s\-]{4,}[\dXx]", text):
        d = _norm(d)
        if len(d) >= 6 and d not in scammer:
            found.append(d)
    return found


STALL_LINE = "哎呀 号码我一下子找不到了 你等等我"


def guard(cid: str, text: str, history: list[dict]) -> str:
    leaked = new_digit_strings(text, history)
    if leaked:
        db.add_alert(cid, "guard", f"拦截了诱饵回复中的数字：{', '.join(leaked)}")
        log.warning("[%s] 拦截可能泄露的数字: %s", cid, leaked)
        return STALL_LINE
    return text


# ---------------------------------------------------------------------------
# 工具执行
# ---------------------------------------------------------------------------
def _run_tool(cid: str, name: str, args: dict) -> dict:
    if name == "record_intel":
        value = str(args.get("value", "")).strip()
        if not value:
            return {"saved": False, "error": "value 为空"}
        db.add_indicator(cid, args.get("kind", "other"), value, "agent")
        return {"saved": True, "seen_in_other_conversations": db.indicator_seen_elsewhere(value, cid)}
    if name == "lookup_indicator":
        return db.lookup_indicator(str(args.get("value", "")).strip(), exclude_cid=cid)
    if name == "raise_alert":
        db.add_alert(cid, args.get("level", "info"), args.get("reason", ""))
        log.warning("[%s] 告警(%s): %s", cid, args.get("level"), args.get("reason"))
        return {"ok": True}
    if name == "end_conversation":
        db.mark_ended(cid, args.get("reason", ""))
        return {"ended": True}
    return {"error": f"未知工具 {name}"}


def _system(cid: str, persona: str) -> str:
    rows = db.get_indicators(cid)
    recorded = "\n".join(f"- {r['kind']}: {r['value']}" for r in rows) or "（暂无）"
    return f"{build_system_prompt(persona)}\n{AGENT_GUIDE}\n## 本会话已记录的情报\n{recorded}\n"


def _text_of(content) -> str:
    return "".join(b.text for b in content if b.type == "text").strip()


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
def respond(cid: str, persona: str, trace: list | None = None) -> str | None:
    """生成下一条回复。返回 None 表示对话已结束、不再回复。

    trace：传入一个列表时，会把工具调用记录追加进去，方便 simulate.py 显示。
    """
    if db.is_ended(cid):
        return None

    history = db.get_messages(cid, limit=200)
    messages = agent.to_claude_messages(history)
    if not messages:
        return None

    last_text = ""
    final_text = ""
    for _ in range(MAX_STEPS):
        resp = agent.client.messages.create(
            model=agent.MODEL,
            max_tokens=800,
            system=_system(cid, persona),
            tools=TOOLS,
            messages=messages,
        )
        step_text = _text_of(resp.content)
        if step_text:
            last_text = step_text
        if resp.stop_reason != "tool_use":
            final_text = step_text
            break

        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for b in resp.content:
            if b.type != "tool_use":
                continue
            out = _run_tool(cid, b.name, b.input)
            if trace is not None:
                trace.append({"tool": b.name, "input": b.input, "output": out})
            results.append({
                "type": "tool_result",
                "tool_use_id": b.id,
                "content": json.dumps(out, ensure_ascii=False),
            })
        messages.append({"role": "user", "content": results})
    else:
        log.warning("[%s] 工具调用轮数超过 %d，停止", cid, MAX_STEPS)

    text = final_text or last_text
    if db.is_ended(cid):
        return guard(cid, text, history) if text else None
    return guard(cid, text or "哎呀 刚才没看清 你再说一遍", history)
