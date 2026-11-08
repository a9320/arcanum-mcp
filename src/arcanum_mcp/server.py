"""Arcanum Security MCP server — four deterministic tools, one job each (v0.2).

Design constraints:
- **Engine reuse, not a second rule set.** Every tool calls the same deterministic
  code as the arcanum-spark CLI: PITAX rules (`codeark.agents.agent0_pitax`),
  Office document inspection (`codeark.office_scan`), dependency vulnerability
  matching (`codeark.tools.dep_scan`); no model, no network.
- **Small returns.** Summary + top findings + where to get the full report.
  Optional `formats` writes report artifacts (json/sarif/markdown/html) locally —
  generation only, never published anywhere.
- **stdio only.** Scanned content never leaves the machine.

MCP SDK note: `mcp>=2` renamed `FastMCP` to `MCPServer`; `mcp<2` still ships
`FastMCP`. `build_server()` accepts either.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_TEXT = 20_000
MAX_FINDINGS = 5
MAX_FILES = 200
MAX_FILE_BYTES = 512 * 1024

_REPORT_FORMATS = {"json", "sarif", "markdown", "html"}
_REPORT_ROOT = Path.home() / ".arcanum" / "mcp-reports"
_LAYA_PATH_ENV = "ARCA_LAYA_PATH"
# laya CPU ~0.4s/条（EVAL-LEDGER 2026-10-07 实测）：50 条≈20s 是交互式工具的合理上限
MAX_HYPOTHESES = 50

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
# dep_scan 只认依赖清单（按文件名，与 codeark.tools.dep_scan.scan_deps 的分派一致）
_DEP_MANIFEST_BASES = {
    "requirements.txt", "pyproject.toml", "package.json",
    "composer.json", "composer.lock", "dockerfile",
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
_OFFICE_EXTS = {".docx", ".xlsx", ".pptx"}


def _import_chain(module_attrs: list[tuple[str, str]]) -> Any:
    """Try (module, attr) pairs in order; on failure inject ARCA_SPARK_PATH and retry."""
    for module_path, attr in module_attrs:
        try:
            mod = __import__(module_path, fromlist=[attr])
            return getattr(mod, attr)
        except ImportError:
            continue
    extra = (os.environ.get("ARCA_SPARK_PATH") or "").strip()
    if extra and Path(extra).is_dir() and extra not in sys.path:
        sys.path.insert(0, extra)
        for module_path, attr in module_attrs:
            try:
                mod = __import__(module_path, fromlist=[attr])
                return getattr(mod, attr)
            except ImportError:
                continue
    return None


def _engine() -> Any:
    """Resolve the deterministic scanner: slim wheel -> full engine -> ARCA_SPARK_PATH."""
    resolved = _import_chain([
        ("codeark_pitax.scan_engine", "scan_repo"),          # slim wheel (PyPI / local install)
        ("codeark.agents.agent0_pitax", "run_agent0"),       # full engine
    ])
    if resolved is not None:
        return resolved
    raise ImportError(
        "no scanner engine found. Install the slim wheel (`pip install codeark-pitax` once "
        "published) or the full engine (`pip install 'codeark @ "
        "git+https://github.com/a9320/arcanum-spark'`), or point ARCA_SPARK_PATH at a local "
        "arcanum-spark checkout."
    )


def _office_engine() -> Any:
    """Resolve scan_office_tree: slim wheel -> full engine (needs codeark-pitax>=0.2)."""
    resolved = _import_chain([
        ("codeark_pitax.office_scan", "scan_office_tree"),   # slim wheel (PyPI / local install)
        ("codeark.office_scan", "scan_office_tree"),         # full engine
    ])
    if resolved is not None:
        return resolved
    raise ImportError(
        "office scanner not found. Install the slim wheel (`pip install -U codeark-pitax` "
        ">=0.2.0) or the full engine, or point ARCA_SPARK_PATH at a local arcanum-spark "
        "checkout."
    )


def _dep_engine() -> Any:
    """Resolve scan_deps: slim wheel -> full engine (needs codeark-pitax>=0.2)."""
    resolved = _import_chain([
        ("codeark_pitax.dep_scan", "scan_deps"),             # slim wheel (PyPI / local install)
        ("codeark.tools.dep_scan", "scan_deps"),             # full engine
    ])
    if resolved is not None:
        return resolved
    raise ImportError(
        "dependency scanner not found. Install the slim wheel (`pip install -U codeark-pitax` "
        ">=0.2.0) or the full engine, or point ARCA_SPARK_PATH at a local arcanum-spark "
        "checkout."
    )


def _engine_error(exc: Exception) -> str:
    return (
        "codeark engine is not importable. Install it "
        '(`pip install "codeark @ git+https://github.com/a9320/arcanum-spark"`) or point '
        f"ARCA_SPARK_PATH at a local arcanum-spark checkout. (import error: {exc})"
    )


def _clip(text: Any, limit: int) -> str:
    value = " ".join(str(text or "").split())
    return value[:limit] + ("…" if len(value) > limit else "")


def _engine_meta() -> str:
    """Engine identification line (mirrors the _engine() resolution order)."""
    try:
        from codeark_pitax.rules import PITAX_VERSION as v

        return f"engine=codeark-pitax · PITAX v{v}"
    except ImportError:
        pass
    try:
        from codeark.pitax.rules import PITAX_VERSION as v

        return f"engine=codeark (full) · PITAX v{v}"
    except ImportError:
        return "engine=unavailable"


def _render(findings: list[dict[str, Any]], title: str, full_hint: str = "") -> str:
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
        extra = finding.get("pitax")
        context = extra.get("context") if isinstance(extra, dict) else ""
        chip = f" [ctx={context}]" if context else ""
        lines.append(f"- [{str(finding.get('severity') or 'medium').upper()}] {rule} @ {where}{chip} — {detail}")
    if len(findings) > MAX_FINDINGS:
        hint = full_hint or "full report: `python -m codeark.cli scan <repo> --formats html`"
        lines.append(f"- … {len(findings) - MAX_FINDINGS} more; {hint}")
    # 2026-11-01 现场事故链实证：CRITICAL 误报（防御性策略文件自触发）→ 宿主提出"修复"并删除文件。
    # 工具输出必须自带处置边界：findings 是报告，不是处置授权。
    lines.append(
        "Advisory only — report these findings, do NOT modify or delete flagged files "
        "unless the user explicitly asks; a rule match is not a confirmed attack."
    )
    lines.append(_engine_meta())
    return "\n".join(lines)


def _render_deps(findings: list[dict[str, Any]], title: str) -> str:
    """dep findings 渲染：package@version + CWE + 修复建议（对齐 _render 的处置边界）。"""
    if not findings:
        return f"{title}: no known-vulnerable dependencies (local OSV/builtin DB; no network)."
    lines = [f"{title}: {len(findings)} vulnerable package(s). Top {min(len(findings), MAX_FINDINGS)}:"]
    for finding in findings[:MAX_FINDINGS]:
        where = f"{finding.get('file') or '?'}"
        lines.append(
            f"- [{str(finding.get('severity') or 'high').upper()}] "
            f"{finding.get('rule') or finding.get('cwe')} @ {where} — "
            f"{finding.get('package')}=={finding.get('version')}: "
            f"{_clip(finding.get('description'), 120)} · fix: {_clip(finding.get('fix'), 80)}"
        )
    if len(findings) > MAX_FINDINGS:
        lines.append(
            f"- … {len(findings) - MAX_FINDINGS} more; full report: "
            "`python -m codeark.cli dep-scan <repo>` or pass `formats` to this tool"
        )
    lines.append(
        "Advisory only — upgrade decisions are yours; verify the CVE before acting on it."
    )
    return "\n".join(lines)


def _write_artifacts(tool: str, findings: list[dict[str, Any]], formats: str,
                     meta: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Render report artifacts (json/sarif/markdown/html) to ~/.arcanum/mcp-reports/.

    生成≠发布（与主仓铁律一致）：只落本地盘并回传路径，绝不发送任何外部渠道。
    Returns (artifact_lines, notes).
    """
    import json

    wanted = [f.strip().lower() for f in (formats or "").split(",") if f.strip()]
    wanted = [f for f in wanted if f in _REPORT_FORMATS]
    if not wanted:
        return [], [f"no valid formats in {formats!r} (use: {', '.join(sorted(_REPORT_FORMATS))})"]
    renderer = _import_chain([
        ("codeark_pitax.reporting", "render_report"),
        ("codeark.agents.report_agent", "render_report"),
    ])
    if renderer is None:
        return [], ["report renderer unavailable (engine missing); text summary only"]

    reports = renderer(findings, wanted, meta=meta)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = _REPORT_ROOT / f"{tool}-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    ext = {"json": "json", "sarif": "sarif", "markdown": "md", "html": "html"}
    lines = []
    for name in wanted:
        content = reports.get(name)
        if content is None:
            continue
        fp = out_dir / f"report.{ext.get(name, name)}"
        text = content if isinstance(content, str) else json.dumps(
            content, ensure_ascii=False, indent=2
        )
        fp.write_text(text, encoding="utf-8")
        lines.append(f"- {name}: {fp} ({fp.stat().st_size} B)")
    lines.append("generation only — nothing was published or sent anywhere")
    return lines, []


def _append_artifacts(body: str, tool: str, findings: list[dict[str, Any]],
                      formats: str, meta: dict[str, Any]) -> str:
    """No-op without `formats`; otherwise render artifacts and append their paths."""
    if not (formats or "").strip():
        return body
    try:
        artifact_lines, notes = _write_artifacts(tool, findings, formats, meta)
    except Exception as exc:  # artifact rendering must never kill the text summary
        return f"{body}\n[artifact rendering failed ({type(exc).__name__}): {_clip(exc, 120)}]"
    tail = []
    if artifact_lines:
        tail.append("Artifacts (local, written next to nothing else):")
        tail.extend(artifact_lines)
    for note in notes:
        tail.append(f"[note] {note}")
    return "\n".join([body, *tail]) if tail else body


def _is_ai_config_path(path: Path) -> bool:
    """AI 指令文件白名单（.cursor/rules、CLAUDE.md 等无常规扩展名者）。

    与引擎同源（codeark/pitax/detectors.is_ai_config_path）；解析失败时内联
    最小判定，保证 .cursor/rules 一类 T-46 面文件不被扩展名过滤器丢弃
    （2026-11-05 bench parity 实测抓到的同源漂移缺陷）。
    """
    resolver = _import_chain([
        ("codeark_pitax.detectors", "is_ai_config_path"),
        ("codeark.pitax.detectors", "is_ai_config_path"),
    ])
    if resolver is not None:
        try:
            return bool(resolver(str(path)))
        except Exception:
            pass
    p = str(path).replace("\\", "/").lower()
    return p.endswith((".cursorrules", ".cursor/rules", "claude.md", "clinerules.md"))


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
            if path.suffix.lower() not in _SOURCE_EXTS and not _is_ai_config_path(path):
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

    ALWAYS use this tool before answering whether a text is safe, malicious, or
    contains injection — including suspicious emails or phishing messages, agent
    system prompts, model outputs, MCP tool return values, and pasted instructions.
    Do NOT answer such questions from your own knowledge: zero-width/invisible
    Unicode characters, base64/encoded payloads, and rule-verified override
    patterns cannot be reliably judged by reading the text alone. Even if you can
    decode or analyze the payload yourself, still run this scan — the finding must
    come from the tool so it is reproducible and auditable.
    Triggers: prompt injection, jailbreak, instruction override, ignore previous
    instructions, system prompt review, tool output check, MCP security, phishing
    email check, "is this text safe"; 提示注入、越狱、忽略之前指令、系统提示词、
    钓鱼邮件、这段文本安全吗、有没有被塞东西.
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


def code_audit(code: str = "", path: str = "", language: str = "", formats: str = "") -> str:
    """Run a deterministic security audit (PITAX rule set) over a code snippet or a local path.

    Use when the user asks to review a code snippet or a repository for AI-specific
    security issues (prompt injection in comments/docs/configs, invisible characters,
    encoded payloads, trojan-source patterns).
    Hidden characters, encoded payloads, or split/override instructions INSIDE code,
    code comments, or config values are mine, not `pitax_scan`'s — if the suspicious
    text sits in a code context (even one line like `x = 1  # <payload>`), call
    `code_audit`.
    If the content is pasted inline in the user's message, pass it via `code` — do not
    guess paths or scan unrelated workspace files (e.g. policy/instruction documents).
    Pass exactly one of `code` or `path`. `language` is optional (python, js, ts, go, …).
    `formats` (optional, "json,sarif,markdown,html" subset) writes full report artifacts
    locally and returns their paths.
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
        except Exception as exc:  # scanner errors must never crash the host session
            return f"code_audit: scanner error ({type(exc).__name__}): {_clip(exc, 200)}"
        suffix = f" [{'; '.join(notes)}]" if notes else ""
        body = _render(findings, f"Code audit · snippet ({language or 'auto'}){suffix}")
        return _append_artifacts(body, "code_audit", findings, formats, {"tool": "code_audit"})

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
    except Exception as exc:  # scanner errors must never crash the host session
        return f"code_audit: scanner error ({type(exc).__name__}): {_clip(exc, 200)}"
    meta = {"tool": "code_audit", "files_scanned": len(files), "skipped": skipped}
    body = _render(
        findings,
        f"Code audit · {len(files)} file(s) from {target.name} ({skipped} skipped)",
    )
    return _append_artifacts(body, "code_audit", findings, formats, meta)


def docs_scan(path: str, formats: str = "") -> str:
    """Scan Office documents (.docx/.xlsx/.pptx) for prompt-injection payloads.

    Use when the user asks to check a Word/Excel/PowerPoint file for hidden
    instructions, poisoned content, invisible Unicode, or encoded payloads —
    e.g. an email attachment the agent is about to read, a "spec" document from
    an untrusted source, or hidden text (w:vanish) inside a contract.
    `path` is a local file or directory. Coverage is reported honestly:
    files/parts/chars actually scanned (not "the whole repo").
    `formats` (optional) writes report artifacts (json/sarif/markdown/html) locally.
    Detection faces: document poisoning (PIT-N-06), invisible characters (PIT-E-23),
    trojan source (PIT-E-54), encoding family — same rules as `pitax_scan`.
    Not for: plain text or source code — use `pitax_scan` / `code_audit`.
    Triggers: check this Word/Excel/PPT file, is this document poisoned, 邮件附件
    安全吗, 文档投毒, 隐藏文字, Word 里藏了指令.
    """
    target_arg = (path or "").strip()
    if not target_arg:
        return "docs_scan: pass `path` (a .docx/.xlsx/.pptx file or a directory containing them)."
    target = Path(target_arg).expanduser()
    if not target.exists():
        return f"docs_scan: path not found: {target_arg}"
    if target.is_file() and target.suffix.lower() not in _OFFICE_EXTS:
        return (
            f"docs_scan: unsupported file type {target.suffix!r}; supported: "
            f"{', '.join(sorted(_OFFICE_EXTS))} (for plain text/code use pitax_scan/code_audit)."
        )
    try:
        findings, meta = _office_engine()(target)
    except ImportError as exc:
        return _engine_error(exc)
    except Exception as exc:  # a broken zip must never crash the host session
        return f"docs_scan: scanner error ({type(exc).__name__}): {_clip(exc, 200)}"
    cov = meta.get("office_scan", {})
    errors = cov.get("errors") or {}
    title = (
        f"Office docs scan · {cov.get('files', 0)} file(s), {cov.get('parts', 0)} part(s), "
        f"{cov.get('chars', 0)} chars, {cov.get('skipped', 0)} skipped"
        + (f", {len(errors)} unreadable" if errors else "")
    )
    body = _render(
        findings, title,
        full_hint="full report: `python -m codeark.cli docs-scan <file-or-dir> --formats html`",
    )
    return _append_artifacts(
        body, "docs_scan", findings, formats,
        {"tool": "docs_scan", "office_scan": cov},
    )


def dep_scan(path: str, formats: str = "") -> str:
    """Check dependency manifests for known-vulnerable package versions (local DB, no network).

    Use when the user asks to audit dependencies or a lockfile: requirements.txt,
    pyproject.toml, package.json, composer.json/lock, Dockerfile (PHP runtime pinning
    included). Matches each pinned version against a local OSV index and a builtin
    vulnerability database — deterministic, offline; nothing is uploaded.
    `path` is a local manifest file or a project directory.
    `formats` (optional) writes report artifacts (json/sarif/markdown/html) locally.
    Not for: prompt injection in text/documents — use `pitax_scan` / `docs_scan`.
    Triggers: 依赖漏洞, check my dependencies, is requirements.txt safe, lockfile audit,
    旧版本 requests/flask 有漏洞吗.
    """
    target_arg = (path or "").strip()
    if not target_arg:
        return "dep_scan: pass `path` (a dependency manifest or a project directory)."
    target = Path(target_arg).expanduser()
    if not target.exists():
        return f"dep_scan: path not found: {target_arg}"

    if target.is_file():
        manifests = {str(target): target.read_text(encoding="utf-8", errors="replace")}
    else:
        manifests = {}
        for p in sorted(target.rglob("*")):
            if not p.is_file():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            base = p.name.lower()
            if base in _DEP_MANIFEST_BASES or base.startswith("dockerfile"):
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                    manifests[str(p)] = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
    if not manifests:
        return (
            f"dep_scan: no dependency manifests under {target_arg} "
            "(looked for requirements.txt / pyproject.toml / package.json / "
            "composer.json / composer.lock / Dockerfile)."
        )
    try:
        findings = _dep_engine()(manifests)
    except ImportError as exc:
        return _engine_error(exc)
    except Exception as exc:  # scanner errors must never crash the host session
        return f"dep_scan: scanner error ({type(exc).__name__}): {_clip(exc, 200)}"
    body = _render_deps(findings, f"Dependency scan · {len(manifests)} manifest(s) from {target.name}")
    return _append_artifacts(
        body, "dep_scan", findings, formats,
        {"tool": "dep_scan", "manifests": len(manifests)},
    )


def _laya_engine():
    """Resolve score_laya: slim wheel -> full engine (codeark.graph.laya_runtime)."""
    resolved = _import_chain([
        ("codeark_pitax.laya_runtime", "score_laya"),        # slim wheel (>=0.2.0)
        ("codeark.graph.laya_runtime", "score_laya"),        # full engine
    ])
    if resolved is not None:
        return resolved
    raise ImportError(
        "laya runtime not found. Install the slim wheel (`pip install -U codeark-pitax` "
        ">=0.2.0) or point ARCA_SPARK_PATH at a local arcanum-spark checkout."
    )


def rank_hypotheses(hypotheses: str, baseline: str = "") -> str:
    """Rank vulnerability hypotheses by P(KEEP) — a local decision model (Laya) picks the verify order.

    Use when the agent (or user) holds a list of candidate vulnerability hypotheses and
    must decide which ones deserve a verification budget FIRST — the same role Laya
    plays as the Scout→Verify gate in the arcanum-spark pipeline. Input is a JSON
    array of items: {"id", "title", "vuln_type", "file_path", "attack_path"} (id and
    attack_path optional). Optionally pass `baseline` — a JSON array of deterministic
    findings ({"file", "rule", "title"}) so echo-hypotheses that just restate a rule
    hit can be down-ranked. Output is an advisory ranking with P(KEEP) and confidence
    per item; NOTHING is deleted or pruned (order-only contract).
    Requires the Laya checkpoint: download the `laya-checkpoints` release assets from
    github.com/a9320/arcanum-spark, then set ARCA_LAYA_PATH to the model directory
    (needs `pip install arcanum-mcp[laya]` for torch). Runs offline on CPU (~0.4s/item).
    Not for: scanning text or code — use pitax_scan/code_audit/docs_scan; this tool
    RANKS hypotheses, it does not detect anything.
    Triggers: which hypothesis should I verify first, 排序假设, 验证预算, rank these
    candidates, 先验证哪条, 假设排序.
    """
    import json
    import time

    try:
        items = json.loads((hypotheses or "").strip() or "[]")
    except json.JSONDecodeError as exc:
        return f"rank_hypotheses: `hypotheses` is not valid JSON ({exc.msg} at pos {exc.pos})."
    if not isinstance(items, list) or not items:
        return "rank_hypotheses: `hypotheses` must be a non-empty JSON array of hypothesis objects."
    if len(items) > MAX_HYPOTHESES:
        return (
            f"rank_hypotheses: {len(items)} items exceeds the {MAX_HYPOTHESES}-item cap "
            "(CPU scoring is ~0.4s/item); split the list and call again."
        )

    normalized: list[dict] = []
    for i, raw in enumerate(items):
        if not isinstance(raw, dict):
            return f"rank_hypotheses: item #{i} is not an object (got {type(raw).__name__})."
        if not (str(raw.get("title") or "").strip() and str(raw.get("vuln_type") or "").strip()):
            return (
                f"rank_hypotheses: item #{i} is missing `title` or `vuln_type` — both are "
                "required (attack_path/file_path/id optional)."
            )
        normalized.append({
            "id": str(raw.get("id") or f"H{i + 1}"),
            "title": str(raw.get("title") or ""),
            "vuln_type": str(raw.get("vuln_type") or ""),
            "file_path": str(raw.get("file_path") or ""),
            "attack_path": str(raw.get("attack_path") or ""),
        })

    baseline_rows: list[dict] = []
    if (baseline or "").strip():
        try:
            baseline_rows = json.loads(baseline)
        except json.JSONDecodeError as exc:
            return f"rank_hypotheses: `baseline` is not valid JSON ({exc.msg} at pos {exc.pos})."
        if not isinstance(baseline_rows, list) or not all(
            isinstance(b, dict) for b in baseline_rows
        ):
            return "rank_hypotheses: `baseline` must be a JSON array of {file, rule, title} objects."

    model_path = (os.environ.get(_LAYA_PATH_ENV) or "").strip()
    if not model_path:
        return (
            "rank_hypotheses: no Laya checkpoint configured. Download the "
            "`laya-checkpoints` release assets from https://github.com/a9320/arcanum-spark "
            "(see docs/EVAL-LEDGER.md for sha256), then set "
            f"{_LAYA_PATH_ENV} to the model directory. Scoring deps: "
            "`pip install arcanum-mcp[laya]` (torch CPU). Everything runs offline."
        )
    try:
        score = _laya_engine()
        t0 = time.perf_counter()
        probs, confs = score(normalized, baseline_rows, model_path)
        elapsed = time.perf_counter() - t0
    except ImportError as exc:
        return _engine_error(exc)
    except FileNotFoundError as exc:  # checkpoint 目录缺 vendor API（布局错误）
        return f"rank_hypotheses: checkpoint problem — {_clip(exc, 200)}"
    except Exception as exc:  # model errors must never crash the host session
        return f"rank_hypotheses: model error ({type(exc).__name__}): {_clip(exc, 200)}"

    ranked = sorted(zip(normalized, probs, confs), key=lambda t: t[1], reverse=True)
    lines = [
        f"Laya rank · {len(normalized)} hypothesis(s) by P(KEEP) "
        f"(elapsed {elapsed:.1f}s, ~{elapsed / len(normalized):.2f}s/item):"
    ]
    for rank, (item, p, c) in enumerate(ranked, start=1):
        lines.append(
            f"{rank}. {item['id']}  P(KEEP)={p:.2f} conf={c:.2f} — "
            f"{_clip(item['title'], 80)} [{_clip(item['vuln_type'], 24)}] "
            f"@ {item['file_path'] or '?'}"
        )
    lines.append(
        "Order-only: these scores are advisory input to YOUR verification budget — "
        "nothing was deleted or pruned (gate v1 contract)."
    )
    note = _laya_note()
    if note:
        lines.append(f"[note] {note}")
    lines.append(f"checkpoint: {model_path}")
    return "\n".join(lines)


def _laya_note() -> str:
    """Windows mmap 警告等运行时注记，从实现模块取（两处文案不漂移）。"""
    for module_path in ("codeark_pitax.laya_runtime", "codeark.graph.laya_runtime"):
        try:
            mod = __import__(module_path, fromlist=["LAYA_RUNTIME_NOTE"])
            return str(getattr(mod, "LAYA_RUNTIME_NOTE", ""))
        except ImportError:
            continue
    return ""



HTTP_TOKEN_ENV = "ARCA_MCP_TOKEN"


def _token_guard(app: Any, token: str):
    """ASGI 中间件：校验 Authorization: Bearer <token>，拒绝一切未授权请求。"""
    expected = f"Bearer {token}"

    async def guarded(scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await app(scope, receive, send)
            return
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        if headers.get("authorization") != expected:
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({"type": "http.response.body", "body": b'{"error": "unauthorized"}'})
            return
        await app(scope, receive, send)

    return guarded


def run_http(server: Any | None = None, *, host: str = "127.0.0.1", port: int = 8000,
             token: str | None = None) -> None:
    """以 HTTP（Streamable HTTP）形态提供服务。**必须带 token**——拒绝裸奔服务器。"""
    tok = (token or os.environ.get(HTTP_TOKEN_ENV, "")).strip()
    if not tok:
        raise SystemExit(
            f"HTTP mode requires {HTTP_TOKEN_ENV} (a long random string) — "
            "refusing to start an unauthenticated network server"
        )
    import uvicorn

    s = server or build_server()
    app = _token_guard(s.streamable_http_app(), tok)
    uvicorn.run(app, host=host, port=port, log_level="warning")


def build_server():
    """Build the MCP server (works with mcp>=2 MCPServer and mcp<2 FastMCP)."""
    try:
        from mcp.server.mcpserver import MCPServer  # mcp>=2
    except ImportError:  # pragma: no cover - exercised only on mcp<2
        from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[no-redef]
    server = MCPServer("arcanum-security")
    server.add_tool(pitax_scan)
    server.add_tool(code_audit)
    server.add_tool(docs_scan)
    server.add_tool(dep_scan)
    server.add_tool(rank_hypotheses)
    return server