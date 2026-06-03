#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.8"
# ///
from __future__ import annotations
"""
拦截红线清单中的高危 bash 命令。
事件: PreToolUse (Bash)
策略: 命中红线 exit 2 阻断执行 + JSON output + stderr 反馈给 Claude
"""

import json
import re
import sys
from typing import NamedTuple


class Rule(NamedTuple):
    pattern: str
    label: str
    severity: str   # "critical" / "high" / "medium"
    why: str        # 一句话解释为什么危险


# 红线规则
DANGEROUS_RULES: list[Rule] = [
    # === CRITICAL: 不可逆数据丢失 ===
    Rule(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*[rf]", "rm -rf/fr 类删除", "critical",
         "递归强制删除，文件不可恢复"),
    Rule(r"\brm\s+--recursive\s+--force", "rm --recursive --force", "critical",
         "长选项等价 rm -rf"),
    Rule(r"\brm\s+--force\s+--recursive", "rm --force --recursive", "critical",
         "长选项等价 rm -rf"),
    Rule(r"\brm\s+-rf?\s+[/~]", "rm -rf / 或 ~ 根目录/家目录", "critical",
         "删除根目录或用户家目录，系统不可恢复"),
    Rule(r"\brm\s+-rf?\s+\*", "rm -rf * 通配符", "critical",
         "通配符删除当前目录所有文件"),

    # === PowerShell/Windows 删除 ===
    Rule(r"Remove-Item\s+.*(-Recurse.*-Force|-Force.*-Recurse)", "PowerShell 递归强删", "critical",
         "PowerShell 递归强制删除（参数顺序无关）"),
    Rule(r"\brd\s+/s\s+/q", "cmd rd /s /q", "critical",
         "cmd 静默递归删除目录"),
    Rule(r"\brmdir\s+/s\s+/q", "cmd rmdir /s /q", "critical",
         "cmd 静默递归删除目录"),
    Rule(r"\bdel\s+/[sf]\s+/[qf]", "cmd del /s /q", "high",
         "cmd 静默递归删除文件"),

    # === 磁盘 / 格式化 ===
    Rule(r"Format-Volume", "PowerShell 格式化卷", "critical",
         "格式化磁盘卷，所有数据丢失"),
    Rule(r"\bmkfs\.", "mkfs 格式化", "critical",
         "创建文件系统，等同格式化"),
    Rule(r"\bformat\s+[a-zA-Z]:", "format C: 格式化分区", "critical",
         "格式化分区，所有数据丢失"),
    Rule(r"\bdiskpart\b", "diskpart 磁盘分区工具", "critical",
         "磁盘分区操作，可导致数据丢失"),
    Rule(r"\bdd\s+if=", "dd 块写入", "critical",
         "底层块写入，误操作可覆盖整盘"),

    # === Git 危险操作 ===
    Rule(r"git\s+push\s+.*--force(?!-with-lease)", "git push --force (无 with-lease)", "medium",
         "覆盖远端历史，可能影响协作者"),
    Rule(r"git\s+push\s+\S*\s*-f\b", "git push -f", "medium",
         "覆盖远端历史，可能影响协作者"),
    Rule(r"git\s+reset\s+--hard", "git reset --hard", "high",
         "丢弃未提交修改，工作区不可恢复"),
    Rule(r"git\s+rebase\s+(-i\s+)?\S", "git rebase 交互", "medium",
         "重写提交历史，可能导致冲突"),
    Rule(r"git\s+clean\s+-[a-zA-Z]*f[a-zA-Z]*d", "git clean -fd", "high",
         "删除未跟踪文件和目录"),

    # === 发布 / 发布工具 ===
    Rule(r"npm\s+publish\b", "npm publish", "medium",
         "发布包到 npm 仓库，不可撤回"),
    Rule(r"cargo\s+publish\b", "cargo publish", "medium",
         "发布 crate 到 crates.io，不可撤回"),
    Rule(r"pnpm\s+publish\b", "pnpm publish", "medium",
         "发布包到 npm 仓库，不可撤回"),

    # === 敏感文件写入 ===
    Rule(r">\s*\.env\b(?!\.sample|\.example|\.template)", "覆写 .env", "high",
         "覆盖环境变量文件，可能丢失密钥配置"),
    Rule(r"Set-Content\s+.*\.env\b(?!\.sample)", "PowerShell 写入 .env", "high",
         "覆盖环境变量文件"),
    Rule(r"cat\s+\.env\b(?!\.sample|\.example)", "cat .env", "medium",
         "读取环境变量文件，可能泄露密钥"),

    # === 数据库 ===
    Rule(r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", "SQL DROP", "critical",
         "删除数据库表/库，数据不可恢复"),
    Rule(r"\bTRUNCATE\s+TABLE\b", "SQL TRUNCATE", "high",
         "清空表数据，不可恢复"),

    # === 系统级 ===
    Rule(r"\bshutdown\s+/[srh]", "Windows shutdown", "critical",
         "关闭/重启 Windows 系统"),
    Rule(r"\bshutdown\s+-[rh]", "Unix shutdown", "critical",
         "关闭/重启 Unix 系统"),
    Rule(r"\bsudo\s+rm\b", "sudo rm", "critical",
         "以 root 权限删除文件"),
    Rule(r"\bchmod\s+-R\s+777", "chmod -R 777 危险权限", "high",
         "递归设置全开放权限，安全风险"),

    # === Pipe to shell ===
    Rule(r"curl\s+[^|]+\|\s*(sh|bash|zsh|pwsh)", "curl | sh", "critical",
         "从网络下载脚本直接执行，供应链攻击风险"),
    Rule(r"wget\s+[^|]+\|\s*(sh|bash|zsh|pwsh)", "wget | sh", "critical",
         "从网络下载脚本直接执行，供应链攻击风险"),
]

# 模块加载时预编译正则
_COMPILED_RULES: list[tuple[re.Pattern, Rule]] = [
    (re.compile(r.pattern, re.IGNORECASE), r) for r in DANGEROUS_RULES
]


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
        tool_name = input_data.get("tool_name", "")

        # 只检查 Bash 工具
        if tool_name != "Bash":
            sys.exit(0)

        command = input_data.get("tool_input", {}).get("command", "")
        if not command:
            sys.exit(0)

        # 逐条匹配（预编译正则）
        for compiled, rule in _COMPILED_RULES:
            if compiled.search(command):
                # 截断命令显示
                display = command[:300]
                if len(command) > 300:
                    display += f"... (总 {len(command)} 字符)"

                # JSON output（与其他 hook 对齐）
                output = {
                    "decision": "block",
                    "reason": (
                        f"命中红线命令 [{rule.severity}]: {rule.label}\n"
                        f"  原因: {rule.why}\n"
                        f"  命令: {display}\n"
                        f"  如确需执行,请手动在终端运行。"
                    ),
                }
                print(json.dumps(output, ensure_ascii=False))

                # 同时输出到 stderr
                print("BLOCKED: 命中红线命令", file=sys.stderr)
                print(f"  级别: {rule.severity}", file=sys.stderr)
                print(f"  规则: {rule.label}", file=sys.stderr)
                print(f"  原因: {rule.why}", file=sys.stderr)
                print(f"  命令: {display}", file=sys.stderr)
                print("  如确需执行,请手动在终端运行。", file=sys.stderr)

                sys.exit(2)  # exit 2 阻断 PreToolUse 并反馈 Claude

        sys.exit(0)
    except json.JSONDecodeError:
        sys.exit(0)
    except Exception:
        sys.exit(0)


if __name__ == "__main__":
    main()
