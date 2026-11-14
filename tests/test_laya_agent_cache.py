"""_patch_laya_agent_cache：loader 缓存包装行为锚（2026-11-14 Windows 实测驱动）。

背景：slim score_laya 每次 score 都重载 ~421M 模型（~22s/次），常驻 server 须单例；
同时 serve 前主线程预加载把大 safetensors 加载挪出 stdio 线程池（挂死绕开，见
server.py 块注释）。本文件只锚 mcp 侧 wrapper 语义，不锚模型本身。
"""
import types

import arcanum_mcp.server as srv


def _fake_runtime(calls):
    rt = types.SimpleNamespace()
    rt._arcanum_cache_patched = False

    def _orig(model_path):
        calls.append(model_path)
        return object()

    rt._load_laya_agent = _orig
    return rt


def test_cached_load_calls_orig_once_per_path(monkeypatch):
    calls = []
    rt = _fake_runtime(calls)
    monkeypatch.setitem(__import__("sys").modules, "codeark_pitax.laya_runtime", rt)
    monkeypatch.setattr(srv, "_LAYA_AGENT_CACHE", {})
    monkeypatch.setattr(srv, "_LAYA_CACHE_PATCHED", False)

    srv._patch_laya_agent_cache()
    assert rt._arcanum_cache_patched is True

    a1 = rt._load_laya_agent("/m/laya")
    a2 = rt._load_laya_agent("/m/laya")
    assert a1 is a2
    assert calls == ["/m/laya"]  # orig 只跑一次

    a3 = rt._load_laya_agent("/m/other")
    assert a3 is not a1
    assert calls == ["/m/laya", "/m/other"]


def test_prewarm_no_env_is_noop(monkeypatch):
    monkeypatch.delenv("ARCA_LAYA_PATH", raising=False)
    assert srv._prewarm_laya() == ""


def test_prewarm_failure_is_silent(monkeypatch):
    calls = []
    rt = _fake_runtime(calls)

    def _boom(model_path):
        raise RuntimeError("broken checkpoint")

    rt._load_laya_agent = _boom
    monkeypatch.setitem(__import__("sys").modules, "codeark_pitax.laya_runtime", rt)
    monkeypatch.setattr(srv, "_LAYA_AGENT_CACHE", {})
    monkeypatch.setattr(srv, "_LAYA_CACHE_PATCHED", False)
    monkeypatch.setenv("ARCA_LAYA_PATH", "/m/laya")
    # 预加载失败=静默（返回 ""），不抛异常——rank_hypotheses 保留自己的 hint/error 路径
    assert srv._prewarm_laya() == ""
