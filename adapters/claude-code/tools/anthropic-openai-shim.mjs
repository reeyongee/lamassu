#!/usr/bin/env node
/**
 * anthropic-openai-shim — lets the real Claude Code CLI drive a model behind an
 * OpenAI-compatible endpoint.
 *
 * Why this exists: lamassu's live-integration goal is to exercise the Claude Code
 * hook adapter against a REAL Claude Code session whose model is served by the
 * CommandCode provider (mimo v2.5). Claude Code speaks only the Anthropic
 * Messages wire protocol (ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN), and the
 * CommandCode endpoint is OpenAI-shaped with no /v1/messages route — verified by
 * probing seven candidate paths, all 404. Something has to translate.
 *
 * This is deliberately minimal and self-contained: node:http only, no
 * dependencies. It is TEST INFRASTRUCTURE, not part of lamassu — lamassu never
 * imports it, and the C core has no idea it exists. What it must NOT do is
 * pretend to be more than a wire translator: it does not evaluate safety, and it
 * is not in any trust path. Everything that judges a payload is in C, in core/.
 *
 *   node anthropic-openai-shim.mjs [--port 3456] [--upstream http://127.0.0.1:8787/v1]
 *                                 [--model xiaomi/mimo-v2.5]
 *
 * Streaming and tool use are both implemented, because without them the agent
 * never calls a tool and PreToolUse/PostToolUse never fire — which is the whole
 * point of running Claude Code here.
 */
import http from "node:http";

const argv = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
};

const PORT = Number(flag("port", "3456"));
const UPSTREAM = flag("upstream", "http://127.0.0.1:8787/v1");
const MODEL = flag("model", "xiaomi/mimo-v2.5");
const UPSTREAM_KEY = process.env.COMMANDCODE_API_KEY ?? flag("key", "");
const VERBOSE = argv.includes("--verbose");

const up = new URL(UPSTREAM);

function log(...a) {
  if (VERBOSE) console.error("[shim]", ...a);
}

/** Anthropic `system` may be a string or an array of text blocks. */
function systemText(system) {
  if (!system) return "";
  if (typeof system === "string") return system;
  if (Array.isArray(system))
    return system.filter((b) => b?.type === "text").map((b) => b.text ?? "").join("\n");
  return "";
}

/** Flatten Anthropic content blocks to plain text (used for tool results). */
function blocksToText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((b) => {
      if (b?.type === "text") return b.text ?? "";
      if (b?.type === "image") return "[image]";
      if (b?.type === "tool_result") return blocksToText(b.content);
      return "";
    })
    .join("\n");
}

/**
 * Anthropic messages -> OpenAI messages.
 * Anthropic packs tool_use inside assistant content and tool_result inside user
 * content; OpenAI wants role:tool messages with tool_call_id and tool_calls on
 * the assistant turn. This is the translation that actually matters.
 */
function toOpenAIMessages(system, messages) {
  const out = [];
  const sys = systemText(system);
  if (sys) out.push({ role: "system", content: sys });

  for (const m of messages ?? []) {
    const content = m.content;
    if (typeof content === "string") {
      out.push({ role: m.role, content });
      continue;
    }
    if (!Array.isArray(content)) continue;

    const textParts = [];
    const toolCalls = [];
    const toolResults = [];

    for (const b of content) {
      if (b?.type === "text") textParts.push(b.text ?? "");
      else if (b?.type === "tool_use")
        toolCalls.push({
          id: b.id,
          type: "function",
          function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) },
        });
      else if (b?.type === "tool_result")
        toolResults.push({
          role: "tool",
          tool_call_id: b.tool_use_id,
          content: blocksToText(b.content),
        });
    }

    if (m.role === "assistant") {
      const msg = { role: "assistant" };
      if (textParts.length) msg.content = textParts.join("\n");
      if (toolCalls.length) msg.tool_calls = toolCalls;
      if (msg.content !== undefined || msg.tool_calls) out.push(msg);
    } else {
      // user turn: tool results must precede any accompanying text
      for (const r of toolResults) out.push(r);
      if (textParts.length) out.push({ role: "user", content: textParts.join("\n") });
      if (!textParts.length && !toolResults.length) out.push({ role: "user", content: "" });
    }
  }
  return out;
}

/** Anthropic tool schema -> OpenAI function schema. */
function toOpenAITools(tools) {
  if (!Array.isArray(tools) || !tools.length) return undefined;
  return tools.map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description ?? "",
      parameters: t.input_schema ?? { type: "object", properties: {} },
    },
  }));
}

function mapStopReason(finish) {
  switch (finish) {
    case "tool_calls":
    case "function_call":
      return "tool_use";
    case "length":
      return "max_tokens";
    default:
      return "end_turn";
  }
}

function upstreamRequest(body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request(
      {
        hostname: up.hostname,
        port: up.port,
        path: `${up.pathname}/chat/completions`,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          ...(UPSTREAM_KEY ? { authorization: `Bearer ${UPSTREAM_KEY}` } : {}),
        },
      },
      (res) => resolve(res),
    );
    req.on("error", reject);
    req.end(payload);
  });
}

function sse(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

/**
 * Stream an OpenAI SSE response back as Anthropic SSE.
 * Text deltas become text_delta; tool-call deltas become input_json_delta on a
 * tool_use block. Block indices must be allocated as blocks are opened.
 */
async function streamToAnthropic(upstreamRes, res, wantModel) {
  let msgId = "msg_shim";
  let inputTokens = 0;
  let outputTokens = 0;
  let stopReason = "end_turn";
  let textIndex = -1;
  let toolIndex = -1;
  const toolByOaiIndex = new Map();
  let started = false;

  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });

  let buf = "";
  for await (const chunk of upstreamRes) {
    buf += chunk.toString("utf8");
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line.startsWith("data:")) continue;
      const data = line.slice(5).trim();
      if (data === "[DONE]") continue;

      let ev;
      try {
        ev = JSON.parse(data);
      } catch {
        continue;
      }

      if (ev.id) msgId = ev.id;
      if (ev.usage) {
        inputTokens = ev.usage.prompt_tokens ?? inputTokens;
        outputTokens = ev.usage.completion_tokens ?? outputTokens;
      }

      if (!started) {
        started = true;
        sse(res, "message_start", {
          type: "message_start",
          message: {
            id: msgId,
            type: "message",
            role: "assistant",
            model: wantModel,
            content: [],
            stop_reason: null,
            stop_sequence: null,
            usage: { input_tokens: inputTokens, output_tokens: 0 },
          },
        });
      }

      const choice = ev.choices?.[0];
      if (!choice) continue;
      const delta = choice.delta ?? {};
      if (choice.finish_reason) stopReason = mapStopReason(choice.finish_reason);

      if (typeof delta.content === "string" && delta.content.length) {
        if (textIndex < 0) {
          textIndex = toolIndex < 0 ? 0 : Math.max(textIndex, toolIndex) + 1;
          sse(res, "content_block_start", {
            type: "content_block_start",
            index: textIndex,
            content_block: { type: "text", text: "" },
          });
        }
        sse(res, "content_block_delta", {
          type: "content_block_delta",
          index: textIndex,
          delta: { type: "text_delta", text: delta.content },
        });
      }

      for (const tc of delta.tool_calls ?? []) {
        const oaiIdx = tc.index ?? 0;
        if (!toolByOaiIndex.has(oaiIdx)) {
          if (textIndex >= 0) {
            sse(res, "content_block_stop", { type: "content_block_stop", index: textIndex });
            textIndex = -1;
          }
          toolIndex += 1;
          const idx = toolIndex;
          toolByOaiIndex.set(oaiIdx, { idx, id: tc.id ?? `toolu_${idx}`, name: tc.function?.name ?? "" });
          sse(res, "content_block_start", {
            type: "content_block_start",
            index: idx,
            content_block: { type: "tool_use", id: tc.id ?? `toolu_${idx}`, name: tc.function?.name ?? "", input: {} },
          });
        }
        const args = tc.function?.arguments;
        if (args) {
          sse(res, "content_block_delta", {
            type: "content_block_delta",
            index: toolByOaiIndex.get(oaiIdx).idx,
            delta: { type: "input_json_delta", partial_json: args },
          });
        }
      }
    }
  }

  for (const { idx } of toolByOaiIndex.values())
    sse(res, "content_block_stop", { type: "content_block_stop", index: idx });
  if (toolByOaiIndex.size === 0)
    sse(res, "content_block_stop", { type: "content_block_stop", index: Math.max(textIndex, 0) });

  sse(res, "message_delta", {
    type: "message_delta",
    delta: { stop_reason: stopReason, stop_sequence: null },
    usage: { output_tokens: outputTokens },
  });
  sse(res, "message_stop", { type: "message_stop" });
  res.end();
}

/** Non-streaming translation. */
function toAnthropicMessage(oai, wantModel) {
  const choice = oai.choices?.[0];
  const msg = choice?.message ?? {};
  const content = [];
  if (msg.content) content.push({ type: "text", text: msg.content });
  for (const tc of msg.tool_calls ?? []) {
    let input = {};
    try {
      input = JSON.parse(tc.function?.arguments || "{}");
    } catch {
      input = {};
    }
    content.push({ type: "tool_use", id: tc.id, name: tc.function?.name, input });
  }
  return {
    id: oai.id ?? "msg_shim",
    type: "message",
    role: "assistant",
    model: wantModel,
    content,
    stop_reason: mapStopReason(choice?.finish_reason),
    stop_sequence: null,
    usage: {
      input_tokens: oai.usage?.prompt_tokens ?? 0,
      output_tokens: oai.usage?.completion_tokens ?? 0,
    },
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "GET" && url.pathname === "/healthz") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ ok: true, model: MODEL, upstream: UPSTREAM }));
  }

  // Claude Code counts tokens before sending; a rough estimate keeps it moving.
  if (url.pathname.endsWith("/count_tokens")) {
    let body = "";
    for await (const c of req) body += c;
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ input_tokens: Math.ceil(body.length / 4) }));
  }

  if (req.method !== "POST" || !url.pathname.endsWith("/messages")) {
    res.writeHead(404, { "content-type": "application/json" });
    return res.end(JSON.stringify({ type: "error", error: { type: "not_found", message: url.pathname } }));
  }

  let raw = "";
  for await (const c of req) raw += c;
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    res.writeHead(400, { "content-type": "application/json" });
    return res.end(JSON.stringify({ type: "error", error: { type: "invalid_request_error", message: "bad JSON" } }));
  }

  const wantStream = body.stream !== false;
  const oai = {
    model: MODEL,
    messages: toOpenAIMessages(body.system, body.messages),
    max_tokens: body.max_tokens ?? 4096,
    stream: wantStream,
  };
  const tools = toOpenAITools(body.tools);
  if (tools) oai.tools = tools;
  if (body.temperature != null) oai.temperature = body.temperature;

  log(`-> ${oai.messages.length} msgs, ${tools ? tools.length : 0} tools, stream=${wantStream}`);

  try {
    const upRes = await upstreamRequest(oai);
    if (upRes.statusCode !== 200) {
      let detail = "";
      for await (const c of upRes) detail += c;
      res.writeHead(upRes.statusCode ?? 502, { "content-type": "application/json" });
      return res.end(
        JSON.stringify({
          type: "error",
          error: { type: "api_error", message: `upstream ${upRes.statusCode}: ${detail.slice(0, 500)}` },
        }),
      );
    }

    if (wantStream) return void (await streamToAnthropic(upRes, res, MODEL));

    let text = "";
    for await (const c of upRes) text += c;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(toAnthropicMessage(JSON.parse(text), MODEL)));
  } catch (err) {
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ type: "error", error: { type: "api_error", message: String(err) } }));
    } else res.end();
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.error(`anthropic-openai-shim on http://127.0.0.1:${PORT}  ->  ${UPSTREAM}  (model ${MODEL})`);
  console.error(`  export ANTHROPIC_BASE_URL=http://127.0.0.1:${PORT}`);
  console.error(`  export ANTHROPIC_AUTH_TOKEN=shim`);
});
