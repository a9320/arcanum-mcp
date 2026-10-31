"""插件清单守卫：mcp.json 的服务器条目必须带合法 type（Copilot 会跳过缺 type 的服务器）。

2026-10-31 实测：缺 "type" 字段 → Copilot CLI 日志报
"Skipped MCP server ...: missing the required type field"，服务器整个不加载。
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALID_TYPES = {"stdio", "streamable-http", "sse"}


def test_mcp_json_entries_have_valid_type():
    data = json.loads((ROOT / "plugins" / "arcanum-security" / "mcp.json").read_text(encoding="utf-8"))
    servers = data["mcpServers"]
    assert servers, "mcpServers 不能为空"
    for name, srv in servers.items():
        assert srv.get("type") in VALID_TYPES, f"{name}: type 缺失或非法（会被 Copilot 跳过）"
        assert srv.get("command"), f"{name}: stdio 服务器必须给 command"


def test_marketplace_lists_the_plugin():
    data = json.loads((ROOT / "marketplace.json").read_text(encoding="utf-8"))
    names = [p["name"] for p in data["plugins"]]
    assert "arcanum-security" in names
    for entry in data["plugins"]:
        assert entry.get("source"), f"{entry['name']}: 缺 source（Copilot 校验必填）"
