#!/usr/bin/env python3
"""Validate skills, knowledge-base entries, and cross-references.

Checks:
  1. Every skills/*/SKILL.md has valid frontmatter (name rules, description).
  2. Markdown links and ../<skill>/SKILL.md cross-references resolve to real files.
  3. Referenced helper scripts exist.
  4. vuln-db entries have complete frontmatter, valid severity/ecosystem,
     date-prefixed filenames, a Detection section, and no duplicate IDs.

Usage: python3 scripts/validate.py    (exit 0 = clean)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
ENTRIES = SKILLS / "cve-research" / "vuln-db" / "entries"

errors = []
warnings = []

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
SEVERITIES = {"critical", "high", "medium", "low"}
ECOSYSTEMS = {"npm", "pypi", "rubygems", "crates-io", "packagist", "go",
              "maven", "nuget", "infra", "multi"}


def parse_frontmatter(text):
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?", text, re.S)
    if not m:
        return {}
    fm = {}
    for line in m.group(1).splitlines():
        kv = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
        if kv:
            fm[kv.group(1)] = kv.group(2).strip().strip("\"'")
    return fm


def check_skills():
    names = {}
    for skill in sorted(p for p in SKILLS.iterdir() if p.is_dir()):
        skill_md = skill / "SKILL.md"
        if not skill_md.exists():
            errors.append(f"{skill.name}: missing SKILL.md")
            continue
        text = skill_md.read_text(encoding="utf-8")
        fm = parse_frontmatter(text)
        name, desc = fm.get("name", ""), fm.get("description", "")

        if not name:
            errors.append(f"{skill.name}: frontmatter missing 'name'")
        else:
            if not NAME_RE.match(name):
                errors.append(f"{skill.name}: invalid name '{name}' (lowercase letters, digits, hyphens)")
            if len(name) > 64:
                errors.append(f"{skill.name}: name exceeds 64 chars")
            if name != skill.name:
                warnings.append(f"{skill.name}: name '{name}' differs from directory (pi allows; Agent Skills standard requires match)")
            if name in names:
                errors.append(f"{skill.name}: duplicate skill name '{name}' (also in {names[name]})")
            names[name] = skill.name
        if not desc:
            errors.append(f"{skill.name}: missing description")
        elif len(desc) > 1024:
            errors.append(f"{skill.name}: description exceeds 1024 chars")

        # Markdown links must resolve inside the skill
        for link in re.findall(r"\]\(([^)\s]+)\)", text):
            if link.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = (skill / link.split("#")[0]).resolve()
            if not target.exists():
                errors.append(f"{skill.name}: broken link '{link}'")

        # Cross-skill references
        for other in re.findall(r"\.\./([a-z0-9-]+)/SKILL\.md", text):
            if not (SKILLS / other / "SKILL.md").exists():
                errors.append(f"{skill.name}: references missing skill '../{other}/SKILL.md'")
        for sname, script in set(re.findall(r"\.\./([a-z0-9-]+)/scripts/([\w.\-]+)", text)):
            if not (SKILLS / sname / "scripts" / script).exists():
                errors.append(f"{skill.name}: references missing script ../{sname}/scripts/{script}")

        # Own-script mentions (warn only: prose may mention scripts generically)
        for script in set(re.findall(r"(?<![\w./])scripts/([\w.\-]+)", text)):
            if not (skill / "scripts" / script).exists():
                warnings.append(f"{skill.name}: mentions scripts/{script} but file not found")


def check_fixture_guards():
    """Warn when a fixture has expected-findings.md but zero selftest rules
    referencing it (pattern-rot exposure). Exempt: judgment-based fixtures
    and fixtures covered by explicit CI assertions."""
    st = (ROOT / "scripts" / "selftest_patterns.py").read_text(encoding="utf-8")
    exempt = {"design-threat-review-vuln-app": "judgment-based (LEARNINGS)",
              "dep-manifests": "CI-covered (osv parser step in ci.yml)"}
    fixtures = ROOT / "evals" / "fixtures"
    for d in sorted(p for p in fixtures.iterdir() if p.is_dir()):
        if not (d / "expected-findings.md").exists():
            continue
        if d.name in exempt:
            continue
        if f'"{d.name}/' not in st:
            warnings.append(f"fixture {d.name}: no selftest rule references it "
                            "(add a match rule for its primary sink)")


def check_entries():
    ids = {}
    for entry in sorted(ENTRIES.glob("*.md")):
        fname = entry.name
        text = entry.read_text(encoding="utf-8")
        fm = parse_frontmatter(text)

        if not re.match(r"^\d{4}-\d{2}-\d{2}-", fname):
            errors.append(f"{fname}: filename must start with YYYY-MM-DD-")
        for field in ("id", "title", "published", "ecosystem", "severity", "affected", "fixed"):
            if not fm.get(field):
                errors.append(f"{fname}: missing frontmatter field '{field}'")
        if (fm.get("severity") or "").lower() not in SEVERITIES:
            errors.append(f"{fname}: invalid severity '{fm.get('severity')}'")
        if (fm.get("ecosystem") or "").lower() not in ECOSYSTEMS:
            errors.append(f"{fname}: invalid ecosystem '{fm.get('ecosystem')}'")
        vid = fm.get("id", "")
        if vid and vid in ids:
            errors.append(f"{fname}: duplicate id '{vid}' (also in {ids[vid]})")
        if vid:
            ids[vid] = fname
        if "## Detection" not in text:
            errors.append(f"{fname}: missing '## Detection' section")
        if "## Fix" not in text:
            errors.append(f"{fname}: missing '## Fix' section")


def main():
    check_skills()
    check_entries()
    check_fixture_guards()
    for w in warnings:
        print(f"  warn:  {w}")
    for e in errors:
        print(f"  ERROR: {e}")
    print(f"\n{len(warnings)} warning(s), {len(errors)} error(s)")
    if errors:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
