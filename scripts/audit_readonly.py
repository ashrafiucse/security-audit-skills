#!/usr/bin/env python3
"""audit_readonly.py - safety gate: the skills must never harm an audited project.

Two layers:
1. EXECUTABLES (scripts, install.sh): zero tolerance for mutating commands.
2. SKILL.md fenced ```bash blocks: action commands are forbidden (detection
   greps only). Prose outside fences is knowledge, not execution — exempt.

Fails with exit 1 on any violation. Run in CI and before releases.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Commands that modify state, exfiltrate, or execute — forbidden anywhere executable
DANGEROUS = [
    r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+",      # rm -rf anything
    r"\bmv\s+\S+\s+/(etc|usr|var|bin|boot)\b",     # mv into system paths
    r"\bdd\s+if=",                                  # raw disk writes
    r"\bchmod\s+777",                               # dangerous perms
    r"\bchown\s+-R",                                # recursive ownership
    r"\bgit\s+(push|reset\s+--hard|clean\s+-[fdx]|checkout\s+--\s)",  # repo mutation
    r"\bcurl[^|>]*-X\s*(POST|PUT|DELETE|PATCH)",   # state-changing HTTP
    r"\bwget[^|>]*--post",                          # ditto
    r"\bmkfs\b|\bshutdown\b|\breboot\b",
    r">\s*/(etc|usr|var|bin|boot)/",                # redirect into system paths
    r"\bpip\s+install\b|\bnpm\s+(install|i)\b(?!.*--package-lock-only)",  # dep installs (supply chain)
    r"\beval\s+\$\(",                               # eval of command substitution
]

FENCE_RE = re.compile(r"```(?:bash|sh|shell|zsh)\s*\n(.*?)```", re.S)


def scan_text(text):
    hits = []
    for rx in DANGEROUS:
        for m in re.finditer(rx, text):
            snippet = text[max(0, m.start() - 40):m.end() + 40].replace("\n", " ")
            hits.append(f"{m.group(0)!r} …{snippet}…")
    return hits


def main():
    violations = []

    # Layer 1: executables — strict, whole-file
    executables = list(ROOT.glob("skills/*/scripts/*")) + list(ROOT.glob("scripts/*"))
    executables = [p for p in executables if p.suffix in (".py", ".sh") and p.name != "audit_readonly.py"]
    executables.append(ROOT / "install.sh")
    for path in executables:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        # scripts may write to their OWN tmp/output: allow /tmp/ and stdout paths
        for hit in scan_text(text):
            violations.append(f"[executable] {path.relative_to(ROOT)}: {hit}")

    # Layer 2: SKILL.md fenced bash blocks only (prose is knowledge, not execution)
    for skill_md in ROOT.glob("skills/*/SKILL.md"):
        text = skill_md.read_text(encoding="utf-8", errors="replace")
        for i, block in enumerate(FENCE_RE.findall(text), 1):
            for hit in scan_text(block):
                violations.append(
                    f"[skill-bash] {skill_md.relative_to(ROOT)} block#{i}: {hit}")

    if violations:
        print("READ-ONLY SAFETY GATE: FAIL")
        for v in violations:
            print(f"  - {v}")
        return 1
    ex = len(executables)
    blocks = sum(len(FENCE_RE.findall(p.read_text(encoding="utf-8", errors="replace")))
                 for p in ROOT.glob("skills/*/SKILL.md"))
    print(f"read-only gate: {ex} executables + {blocks} skill bash blocks clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
