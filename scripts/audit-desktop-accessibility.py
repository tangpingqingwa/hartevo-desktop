#!/usr/bin/env python3
"""Audit checked-in native Hartevo AX snapshots and CSS accessibility contracts."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AX_ROOT = ROOT / "artifacts" / "visual" / "prototype-baseline" / "native-ax"
CSS_PATH = ROOT / "hartevo-rs" / "desktop" / "assets" / "prototype.css"
REPORT_PATH = (
    ROOT
    / "artifacts"
    / "visual"
    / "prototype-baseline"
    / "accessibility-audit.md"
)

REQUIRED_SURFACES = (
    "orchestrator",
    "mission-conversation",
    "mission-streaming",
    "mission-workpad",
    "mission-inspector",
    "mission-approval",
    "mission-outcome",
    "current",
    "missions",
    "channels",
    "relationships",
    "partners",
    "connections",
    "outcomes",
    "capability-evidence",
    "settings",
    "state-coverage",
)

REQUIRED_STATE_CODES = (
    "LOADING",
    "EMPTY",
    "OFFLINE",
    "ERROR",
    "BLOCKED",
    "WAITING_USER",
    "WAITING_APPROVAL",
    "HANDOFF",
    "SUCCESS",
    "RECOVERY",
)


def unlabeled_controls(text: str) -> list[str]:
    unlabeled: list[str] = []
    for line in text.splitlines():
        stripped = re.sub(r"^\s*\d+\s+", "", line.strip())
        if re.fullmatch(r"(?:button|switch|text field|pop up button)(?: \([^)]*\))*", stripped):
            unlabeled.append(line.strip())
    return unlabeled


def main() -> None:
    failures: list[str] = []
    rows: list[tuple[str, int, int, str]] = []

    for surface in REQUIRED_SURFACES:
        path = AX_ROOT / f"{surface}.txt"
        if not path.exists():
            failures.append(f"missing AX snapshot: {surface}")
            rows.append((surface, 0, 0, "FAIL"))
            continue
        text = path.read_text(encoding="utf-8")
        controls = sum(
            1
            for line in text.splitlines()
            if re.search(r"\b(button|switch|text field|pop up button)\b", line)
        )
        unlabeled = unlabeled_controls(text)
        if "Window: \"Hartevo Desktop\"" not in text:
            failures.append(f"{surface}: native window was not identified")
        if unlabeled:
            failures.append(f"{surface}: unlabeled controls: {unlabeled}")
        rows.append((surface, len(text.splitlines()), controls, "PASS" if not unlabeled else "FAIL"))

    state_text = (AX_ROOT / "state-coverage.txt").read_text(encoding="utf-8")
    missing_states = [code for code in REQUIRED_STATE_CODES if code not in state_text]
    if missing_states:
        failures.append(f"state-coverage: missing codes {missing_states}")

    settings_text = (AX_ROOT / "settings.txt").read_text(encoding="utf-8")
    for expected in (
        "搜索设置分区",
        "新项目默认存储方式",
        "默认本地项目位置",
        "切换项目后的默认页面",
        "开机启动",
        "建议下一步",
    ):
        if expected not in settings_text:
            failures.append(f"settings: missing accessible name {expected}")

    mission_expectations = {
        "mission-conversation": (
            "Mission Conversation",
            "Operating Contract 目标、约束与停止条件",
            "添加附件或上下文",
        ),
        "mission-streaming": (
            "Runtime 事件流",
            "停止 Runtime 交互结构样例",
            "VISUAL_FIXTURE",
        ),
        "mission-workpad": (
            "调整 Mission 会话与工作台宽度",
            "任务工作台",
            "工作产物标签",
        ),
        "mission-inspector": (
            "运行检查器",
            "MISSION INSPECTOR",
            "Browser Workspace",
        ),
        "mission-approval": (
            "等待审批",
            "修改样例",
            "不创建 ApprovalGrant / EffectIntent",
        ),
        "mission-outcome": (
            "未执行",
            "ProviderReceipt",
            "下一步",
        ),
    }
    for surface, expectations in mission_expectations.items():
        surface_text = (AX_ROOT / f"{surface}.txt").read_text(encoding="utf-8")
        for expected in expectations:
            if expected not in surface_text:
                failures.append(f"{surface}: missing accessible contract {expected}")

    css = CSS_PATH.read_text(encoding="utf-8")
    for contract in (
        ":focus-visible",
        "@media (prefers-reduced-motion: reduce)",
        "overflow-wrap: anywhere",
    ):
        if contract not in css:
            failures.append(f"CSS: missing {contract}")

    lines = [
        "# Hartevo Desktop accessibility audit",
        "",
        "This report audits native macOS accessibility snapshots from the real Dioxus Desktop window. It does not claim VoiceOver or Windows Narrator completion.",
        "",
        "| Surface | AX lines | named controls | Result |",
        "|---|---:|---:|---|",
    ]
    lines.extend(
        f"| `{surface}` | {ax_lines} | {controls} | {result} |"
        for surface, ax_lines, controls, result in rows
    )
    lines.extend(
        [
            "",
            f"Required UI state codes: {len(REQUIRED_STATE_CODES) - len(missing_states)}/{len(REQUIRED_STATE_CODES)} present.",
            "",
            "CSS gates: visible focus, reduced motion, and long-text wrapping are present.",
            "",
            "VoiceOver and Narrator scripted journeys remain `BLOCKED_ENV`; semantic AX exposure is verified here, but assistive-technology behavior is not inferred from the tree alone.",
            "",
            f"Overall: **{'FAIL' if failures else 'PASS'}**",
        ]
    )
    if failures:
        lines.extend(["", "## Failures", ""] + [f"- {failure}" for failure in failures])
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if failures:
        raise SystemExit("\n".join(failures))
    print(f"accessibility audit passed: {len(rows)} native surfaces")


if __name__ == "__main__":
    main()
