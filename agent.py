"""对话 Agent：根据历史消息，以诱饵人设生成下一条回复。"""
import os
import random

import anthropic

from persona import build_system_prompt

MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5")
client = anthropic.Anthropic()  # 读取环境变量 ANTHROPIC_API_KEY


def to_claude_messages(history: list[dict]) -> list[dict]:
    """把数据库里的消息转成 Claude 的 user/assistant 交替格式（合并相邻同角色消息）。"""
    msgs: list[dict] = []
    for m in history:
        role = "user" if m["role"] == "scammer" else "assistant"
        if msgs and msgs[-1]["role"] == role:
            msgs[-1]["content"] += "\n" + m["content"]
        else:
            msgs.append({"role": role, "content": m["content"]})
    # Claude 要求第一条是 user
    while msgs and msgs[0]["role"] != "user":
        msgs.pop(0)
    return msgs


def reply(history: list[dict], persona_key: str) -> str:
    resp = client.messages.create(
        model=MODEL,
        max_tokens=300,
        system=build_system_prompt(persona_key),
        messages=to_claude_messages(history),
    )
    text = "".join(b.text for b in resp.content if b.type == "text").strip()
    return text or "哎呀，刚才没看清，你再说一遍？"


def human_delay_seconds(text: str) -> float:
    """模拟真人打字速度（老年人人设：慢），让对方更难识破，也顺便拖时间。"""
    return min(8 + len(text) * random.uniform(0.4, 0.9), 90)


def pick_persona() -> str:
    from persona import PERSONAS
    return random.choice(list(PERSONAS))
