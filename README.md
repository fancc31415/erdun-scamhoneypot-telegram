# 反诈蜜罐 AI Agent（文本版 MVP）

仿照 Apate.ai 思路的最小原型：AI 扮演“易受骗的普通人”，拖住诈骗者，同时自动抽取收款账户、钱包地址、电话、链接等情报，汇总到看板。

```
诈骗者消息 → bot.py(Telegram) ─┐
                               ├→ agent.py（Claude 扮演人设，拖延+套话）→ 回复
simulate.py(命令行测试) ───────┘
                    ↓ 每 N 条消息
            extractor.py（LLM 结构化抽取 + 正则兜底）→ honeypot.db → dashboard.py
```

| 文件 | 作用 |
|---|---|
| `persona.py` | 人设与策略提示词（最重要，决定像不像真人、能否套到情报） |
| `agent.py` | 调用 Claude 生成回复，模拟真人打字延迟 |
| `extractor.py` | 用工具调用强制输出结构化情报；正则 + Luhn 校验兜底 |
| `db.py` | SQLite 存储会话、消息、情报 |
| `bot.py` | Telegram 接入 |
| `simulate.py` | 本地命令行，你扮演骗子测试 |
| `dashboard.py` | 情报看板 |
| `decoy_agent.py` | Agent 版诱饵：自己调用工具记录情报、查团伙、告警、结束对话 |
| `evaluate.py` | 批量评估：AI 扮演骗子自动对话，生成评分报告 |

## 第一步：本地跑通（10 分钟）

```bash
cd scam_honeypot
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # 填入 ANTHROPIC_API_KEY（在 console.anthropic.com 获取）
python simulate.py          # 你扮演骗子聊几轮，输入 /intel 看抽取结果
python dashboard.py         # 浏览器打开 http://localhost:8000
```

测试话术示例：“您好，我是XX市公安局刑侦支队的，您的身份证涉嫌一起洗钱案……”，然后逐步要求对方转账到“安全账户”，看诱饵能否拖住你、套出你给的卡号。

## 第二步：接入 Telegram

1. 在 Telegram 找 @BotFather，`/newbot` 拿到 token，填入 `.env`。
2. `python bot.py`，用另一个账号给机器人发消息测试。测试时可设 `FAST_MODE=1`。

> 注意：诈骗者通常是主动私信“真人账号”，而 Bot API 机器人不能被陌生人主动搜到并像真人那样聊天。正式的蜜罐通常需要用**专门的手机号注册的独立账号**（如用 Telethon 实现 userbot），并把这个号码“投放”到诈骗者会接触的地方（公开留联系方式的帖子、已知诈骗群等）。做之前请阅读平台服务条款，并优先与平台方合作。

## Agent 版诱饵（decoy_agent.py）

普通版每条消息固定调用一次 Claude；Agent 版给 Claude 一组工具，由它自己决定什么时候用：

| 工具 | 作用 |
|---|---|
| `record_intel` | 骗子一说出卡号、钱包、电话等，立刻记录；返回这条情报是否在其他会话出现过 |
| `lookup_indicator` | 查询情报库，发现同一团伙 |
| `raise_alert` | 向分析人员告警（看板“告警”区） |
| `end_conversation` | 对方不是骗子、或已如实承认是 AI 时结束对话 |

另有代码层防护：诱饵回复里出现骗子没说过的 6 位以上数字，会被直接拦截并记一条“代码拦截”告警。

```bash
python simulate.py li_shushu --agent    # 命令行测试，会显示工具调用
python evaluate.py --agent              # 批量评估，结果存 eval_report_agent.md
# Telegram：在 .env 里设置 AGENT_MODE=1 后运行 python bot.py
```

## 第三步：迭代方向

1. **提升拟真度**：多人设、错别字、真实作息（夜里不回）、偶尔发语音/图片（需多模态）。
2. **评估**：建一个“骗子模拟器”（另一个 LLM 扮演各类骗子脚本），批量跑对话，统计平均拖延时长、情报抽取率、被识破率。用这个指标迭代 `persona.py`。
3. **识别层**：在真实用户流量入口加分类器（LLM 或微调小模型），只有高置信诈骗才转给诱饵。误判转接真实用户的代价很高，阈值要保守。
4. **语音版**：Twilio/Telnyx 或 FreeSWITCH 接电话 → 流式 ASR → Claude → 流式 TTS，端到端延迟要压到 1 秒内并支持打断。
5. **情报出口**：指标去重聚类（同一卡号/钱包出现在多个会话 = 同一团伙），对接银行、交易所、反诈中心的上报接口。
6. **生产化**：Postgres、消息队列、人工复核界面、审计日志、数据加密。

## 合规与安全红线

- 只与已判定为诈骗的对象对话；对话记录中可能有被冒用的无辜者信息，需加密存储、限制访问。
- 诱饵绝不提供真实个人信息、绝不真实转账或点击链接（已写进提示词，建议再在代码层过滤：例如检测回复中出现身份证/卡号格式就拦截）。
- 录音/记录、伪装身份、情报共享在不同司法辖区有不同规定；正式上线前请咨询律师，并尽量与运营商、银行或警方合作。
