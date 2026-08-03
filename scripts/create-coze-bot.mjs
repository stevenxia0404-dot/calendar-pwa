#!/usr/bin/env node
/**
 * 创建菠萝日程 Coze Bot「小菠萝」并发布到 API 渠道
 */
import { readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";

const mcpCfg = JSON.parse(readFileSync(join(homedir(), ".claude", ".mcp.json"), "utf-8"));
const { COZE_API_TOKEN, COZE_API_BASE = "https://api.coze.cn" } = mcpCfg.mcpServers["coze-mcp-server"].env;
const BASE = COZE_API_BASE.replace(/\/$/, "");

async function api(method, path, body) {
  const url = path.startsWith("http") ? path : `${BASE}${path}`;
  const opts = { method, headers: { Authorization: `Bearer ${COZE_API_TOKEN}`, "Content-Type": "application/json" } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const text = await res.text();
  if (!res.ok) { throw new Error(`${res.status}: ${text}`); }
  return JSON.parse(text);
}

async function createBot() {
  // 获取工作空间
  const raw = await api("GET", "/v1/workspaces");
  const ws = raw.data?.workspaces?.[0];
  if (!ws) throw new Error("No workspace found");

  const systemPrompt = `你是小菠萝，菠萝日程的AI助理。根据用户输入判断意图并调用对应函数。

规则：
- 创建日程用 create_events，event=有明确时间段的事项，task=只说"今天/明天做XX"没有具体时间的待办
- 修改日程用 update_event，需要先确认要修改哪条日程
- 删除日程用 delete_event
- 查询日程用 query_events
- 闲聊或回答问题用文字直接回复，不要调用函数
- 回复简洁友好，一次不要超过两句话`;

  const botData = await api("POST", "/v1/bot/create", {
    space_id: ws.id,
    name: "小菠萝",
    description: "菠萝日程的 AI 助理，帮助用户创建、修改、删除、查询日程和任务",
    prompt_info: { prompt: systemPrompt }
  });
  const botId = botData.data?.bot_id;
  console.log(`Bot 创建成功: ${botId}`);

  await api("POST", "/v1/bot/publish", { bot_id: botId, connector_ids: ["1024"] });
  console.log("Bot 已发布到 API 渠道");

  console.log(`\nBOT_ID=${botId}`);
  console.log(`TOKEN=${COZE_API_TOKEN}`);
  return botId;
}

createBot().catch(e => { console.error(e.message); process.exit(1); });
