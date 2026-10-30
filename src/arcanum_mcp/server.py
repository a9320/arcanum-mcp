"""Arcanum Security MCP server — two tools, one job each (v0.1).

Design constraints:
- **Engine reuse, not a second rule set.** Both tools call codeark's deterministic
  PITAX scanner (`codeark.agents.agent0_pitax.run_agent0`); no model, no network.
- **Small returns.** Summary + top findings + where to get the full report.
- **stdio only.** Scanned content never leaves the machine.

MCP SDK note: `mcp>=2` renamed `FastMCP` to `MCPServer`; `mcp<2` still ships
`FastMCP`. `build_server()` accepts either.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

MAX_TEXT = 20_000
MAX_FINDINGS = 5
MAX_FILES = 200
MAX_FILE_BYTES = 512 * 1024

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".pytest_cache",
}
_SOURCE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
    ".c", ".cpp", ".h", ".rb", ".php", ".sh", ".bash", ".sql",
    ".html", ".htm", ".vue", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".txt", ".md",
}
_SURFACES = {
    "prompt": "input/prompt.txt",
    "system_prompt": "SYSTEM_PROMPT.md",
    "agent_instructions": ".cursor/rules",
    "tool_output": "tool_output.md",
    "doc": "docs/input.md",
}
_LANG_EXT = {
    "python": ".py", "py": ".py", "javascript": ".js", "js": ".js",
    "typescript": ".ts", "ts": ".ts", "go": ".go", "rust": ".rs",
    "java": ".java", "php": ".php", "ruby": ".rb", "bash": ".sh", "sql": ".sql",
}


def _engine() -> Any:
    """Return codeark's deterministic scanner; import lazily so the server starts offline."""
    try:
        from codeark.agents.agent0_pitax import run_agent0
        return run_agent0
    except ImportError:
        extra = (os.environ.get("ARCA_SPARK_PATH") or "").strip()
        if extra and Path(extra).is_dir():
            sys.path.insert(0, extra)
            from codeark.agents.agent0_pitax import run_agent0
            return run_agent0
        raise


def _engine_error(exc: Exception) -> str:
    return (
        "codeark engine is not importable. Install it "
        '(`pip install "codeark @ git+https://github.com/a9320/arcanum-spark"`) or point '
        f"ARCA_SPARK_PATH at a local arcanum-spark checkout. (import error: {exc})"
    )


def _clip(text: Any, limit: int) -> str:
    value = " ".join(str(text or "").split())
    return value[:limit] + ("…" if len(value) > limit else "")


def _render(findings: list[dict[str, Any]], title: str) -> str:
    if not findings:
        return f"{title}: no PITAX findings (deterministic rules; no model called)."
    counts: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity") or "medium").lower()
        counts[sev] = counts.get(sev, 0) + 1
    summary = ", ".join(
        f"{sev}={n}" for sev, n in sorted(counts.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))
    )
    ordered = sorted(
        findings, key=lambda f: _SEV_ORDER.get(str(f.get("severity") or "medium").lower(), 9)
    )
    lines = [
        f"{title}: {len(findings)} finding(s) ({summary}). "
        f"Top {min(len(findings), MAX_FINDINGS)}:"
    ]
    for finding in ordered[:MAX_FINDINGS]:
        rule = str(finding.get("type") or finding.get("rule") or "PITAX")
        location = str(finding.get("file") or "?")
        line = finding.get("line")
        where = f"{location}:{line}" if line else location
        detail = _clip(
            finding.get("code_snippet") or finding.get("title") or finding.get("description"), 140
        )
        lines.append(f"- [{str(finding.get('severity') or 'medium').upper()}] {rule} @ {where} — {detail}")
    if len(findings) > MAX_FINDINGS:
        lines.append(
            f"- … {len(findings) - MAX_FINDINGS} more; full report: "
            "`python -m codeark.cli scan <repo> --formats html`"
        )
    return "\n".join(lines)


def _read_path(target: Path) -> tuple[dict[str, str], int]:
    """Read a file or a directory tree (bounded: file count, size, skip dirs)."""
    if target.is_file():
        candidates = [target]
    else:
        candidates = []
        for path in sorted(target.rglob("*")):
            if not path.is_file():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in _SOURCE_EXTS:
                continue
            candidates.append(path)

    files: dict[str, str] = {}
    skipped = max(0, len(candidates) - MAX_FILES)
    for path in candidates[:MAX_FILES]:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped += 1
                continue
            files[str(path)] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
    return files, skipped


def pitax_scan(text: str, surface: str = "prompt") -> str:
    """Scan text for prompt-injection and instruction-override risks (PITAX).

    Use when the user pastes a suspicious prompt, reviews an agent's system prompt,
    checks whether model output or an MCP tool return value can hijack the agent,
    or asks for a prompt-injection "security check".
    Triggers: prompt injection, jailbreak, instruction override, system prompt,
    tool output, MCP security.
    Not for: static code vulnerability review — use code_audit instead.
    """
    cleaned = (text or "").strip()
    if not cleaned:
        return "pitax_scan: empty input — paste the text you want scanned."
    key = (surface or "prompt").strip().lower()
    if key not in _SURFACES:
        return f"pitax_scan: unknown surface {surface!r}; use one of: {', '.join(sorted(_SURFACES))}."
    notes: list[str] = []
    if len(cleaned) > MAX_TEXT:
        cleaned = cleaned[:MAX_TEXT]
        notes.append(f"truncated to {MAX_TEXT} chars")
    try:
        findings = _engine()({_SURFACES[key]: cleaned})
    except ImportError as exc:
        return _engine_error(exc)
    except Exception as exc:  # scanner errors must never crash the host session
        return f"pitax_scan: scanner error ({type(exc).__name__}): {_clip(exc, 200)}"
    suffix = f" [{'; '.join(notes)}]" if notes else ""
    return _render(findings, f"PITAX scan · surface={key}{suffix}")


def code_audit(code: str = "", path: str = "", language: str = "") -> str:
    """Run a deterministic security audit (PITAX rule set) over a code snippet or a local path.

    Use when the user asks to review a code snippet or a repository for AI-specific
    security issues (prompt injection in comments/docs/configs, invisible characters,
    encoded payloads, trojan-source patterns).
    Pass exactly one of `code` or `path`. `language` is optional (python, js, ts, go, …).
    Not for: full multi-agent verdicts or attack-chain reasoning — this is the
    deterministic rules layer only.
    """
    snippet = (code or "").strip()
    target_arg = (path or "").strip()
    if bool(snippet) == bool(target_arg):
        return "code_audit: pass exactly one of `code` (snippet) or `path` (file or directory)."

    if snippet:
        ext = _LANG_EXT.get((language or "").strip().lower(), ".txt")
        notes = []
        if len(snippet) > MAX_TEXT:
            snippet = snippet[:MAX_TEXT]
            notes.append(f"truncated to {MAX_TEXT} chars")
        try:
            findings = _engine()({f"snippet{ext}": snippet})
        except ImportError as exc:
            return _engine_error(exc)
        except Exception as exc:
            return f"code_audit: scanner error ({type(exc).__name__}): {_clip(exc, 200)}"
        suffix = f" [{'; '.join(notes)}]" if notes else ""
        return _render(findings, f"Code audit · snippet ({language or 'auto'}){suffix}")

    target = Path(target_arg).expanduser()
    if not target.exists():
        return f"code_audit: path not found: {target_arg}"
    files, skipped = _read_path(target)
    if not files:
        return f"code_audit: no supported source files under {target_arg}."
    try:
        findings = _engine()(files)
    except ImportError as exc:
        return _engine_error(exc)
    except Exception as exc:
        return f"code_audit: scanner error ({type(exc).__name__}): {_clip(exc, 200)}"
    return _render(
        findings,
        f"Code audit · {len(files)} file(s) from {target.name} ({skipped} skipped)",
    )


def build_server():
    """Build the MCP server (works with mcp>=2 MCPServer and mcp<2 FastMCP)."""
    try:
        from mcp.server.mcpserver import MCPServer  # mcp>=2
    except ImportError:  # pragma: no cover - exercised only on mcp<2
        from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[no-redef]
    server = MCPServer("arcanum-security")
    server.add_tool(pitax_scan)
    server.add_tool(code_audit)
    return server