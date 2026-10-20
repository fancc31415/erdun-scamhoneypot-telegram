"""Telegram 蜜罐机器人（Bot API 版，用于跑通流程）。

运行：python bot.py
说明见 README.md「接入真实渠道」一节。
"""
import asyncio
import logging
import os

from dotenv import load_dotenv

load_dotenv()

from telegram import Update  # noqa: E402
from telegram.constants import ChatAction  # noqa: E402
from telegram.ext import Application, ContextTypes, MessageHandler, filters  # noqa: E402

import agent  # noqa: E402
import db  # noqa: E402
import decoy_agent  # noqa: E402
import extractor  # noqa: E402

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("honeypot")
# httpx 每次轮询都会打印一行带 token 的网址，既刷屏又泄露 token，这里关掉
logging.getLogger("httpx").setLevel(logging.WARNING)

EXTRACT_EVERY = int(os.getenv("EXTRACT_EVERY_N_MESSAGES", "4"))
FAST_MODE = os.getenv("FAST_MODE", "0") == "1"  # 测试时设为1，跳过拟人延迟
AGENT_MODE = os.getenv("AGENT_MODE", "0") == "1"  # 设为1使用 Agent 版诱饵（decoy_agent.py）

# 每个会话一把锁，避免对方连发多条时并发生成多条回复
locks: dict[str, asyncio.Lock] = {}


async def on_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg or not msg.text:
        return
    cid = f"telegram:{update.effective_chat.id}"

    persona = db.get_persona(cid) or agent.pick_persona()
    db.ensure_conversation(cid, "telegram", persona)
    db.add_message(cid, "scammer", msg.text)

    log.info("[%s] 收到: %s", cid, msg.text[:60])
    if db.is_ended(cid):
        return  # 诱饵已结束这段对话，只记录不回复

    lock = locks.setdefault(cid, asyncio.Lock())
    if lock.locked():
        return  # 正在回复中，这条消息已入库，回复完会接着处理
    async with lock:
        # 循环处理：只要最后一条还是对方的消息，就继续回复（对方连发几条会合并成一次回复）
        while True:
            history = db.get_messages(cid)
            if not history or history[-1]["role"] != "scammer":
                break
            await asyncio.sleep(0 if FAST_MODE else 3)  # 等对方可能的连发
            history = db.get_messages(cid)

            try:
                if AGENT_MODE:
                    trace: list = []
                    text = await asyncio.to_thread(decoy_agent.respond, cid, persona, trace)
                    for t in trace:
                        log.info("[%s] 工具 %s %s", cid, t["tool"], t["input"])
                else:
                    text = await asyncio.to_thread(agent.reply, history, persona)
            except Exception as e:
                log.error("[%s] 调用 Claude 失败: %s", cid, e)
                return  # 不再重试，避免刷屏；下一条消息到来时会重新尝试

            if not text:  # Agent 决定结束对话且不留告别语
                log.info("[%s] 诱饵已结束对话", cid)
                break

            if not FAST_MODE:
                delay = agent.human_delay_seconds(text)
                end = asyncio.get_event_loop().time() + delay
                while asyncio.get_event_loop().time() < end:
                    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
                    await asyncio.sleep(4)

            await context.bot.send_message(update.effective_chat.id, text)
            db.add_message(cid, "bot", text)
            log.info("[%s] 回复: %s", cid, text[:60])
            if db.is_ended(cid):
                log.info("[%s] 诱饵已结束对话", cid)

            n_scammer = sum(1 for m in db.get_messages(cid, limit=1000) if m["role"] == "scammer")
            if n_scammer % EXTRACT_EVERY == 0:
                try:
                    data = await asyncio.to_thread(extractor.extract, cid)
                    if data:
                        log.info("[%s] 情报: %s", cid, data.get("summary"))
                except Exception as e:
                    log.error("[%s] 情报抽取失败: %s", cid, e)


def main():
    db.init()
    builder = (
        Application.builder()
        .token(os.environ["TELEGRAM_BOT_TOKEN"])
        # VPN 线路延迟较高，默认 5 秒超时容易报 TimedOut，这里放宽到 30 秒
        .connect_timeout(30).read_timeout(30).write_timeout(30).pool_timeout(30)
        .get_updates_connect_timeout(30).get_updates_read_timeout(30)
        .get_updates_write_timeout(30).get_updates_pool_timeout(30)
        # 允许同时处理多条消息：一个会话在“打字”时，不会卡住其他会话
        .concurrent_updates(True)
    )
    # 国内访问 Telegram 需要代理，例如 Clash 默认是 http://127.0.0.1:7890
    proxy = os.getenv("TELEGRAM_PROXY", "").strip()
    if proxy:
        builder = builder.proxy(proxy).get_updates_proxy(proxy)
        log.info("Using proxy %s", proxy)
    app = builder.build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_message))
    log.info("Honeypot bot running…（%s）", "Agent 版" if AGENT_MODE else "普通版")
    app.run_polling()


if __name__ == "__main__":
    main()
