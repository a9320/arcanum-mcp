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


def test_policy_file_ships_with_plugin_and_covers_every_tool():
    """instructed 形态装机足迹：AGENTS.md 必须随 plugin 分发（路由 0/5→9/9 的杠杆），
    且分派表覆盖服务端注册的全部工具——政策与工具集不得漂移。"""
    import asyncio

    from arcanum_mcp import server as srv

    policy = (ROOT / "plugins" / "arcanum-security" / "AGENTS.md").read_text(encoding="utf-8")
    registered = {t.name for t in asyncio.run(srv.build_server().list_tools())}
    for tool in registered:
        assert f"`{tool}`" in policy, f"AGENTS.md 未覆盖已注册工具 {tool}"
    # 处置边界必须写死（2026-11-01 现场事故链：误报→宿主提议删文件）；
    # 原文跨行排版，先归一硬换行再断言
    flat = " ".join(policy.split())
    assert "advisory" in policy.lower()
    assert "do not fix, modify, or delete" in flat
    # 政策自身不得含触发短语（自扫 FP 防线：防御性 prose 必须 stay clean）
    for phrase in ("ignore previous instructions", "ignore all previous"):
        assert phrase not in policy.lower(), f"政策文件含触发短语: {phrase!r}"
