#!/usr/bin/env python3
"""score_audit.py - score a produced SECURITY-AUDIT.md against ground truth.

Automates the eval round scoring defined in evals/README.md: recall (planted
findings reported), precision (report findings backed by ground truth), and
phantoms (report findings citing evidence that is not in ground truth).

Usage:
    python3 scripts/score_audit.py <SECURITY-AUDIT.md> <fixture-dir> \
        [--min-recall 0.9] [--min-precision 0.8] [--max-phantoms 0]

Exits 1 if thresholds are unmet (CI-able). Matching is line-tolerant (±2,
agents re-cite nearby lines) and basename-based; bare continuation ranges
("app.js:31-41, 46-49") inherit the last cited file. Severity text is ignored.
"""
import argparse
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

TOLERANCE = 2
FILE_LEVEL_MAX = 10 ** 9  # sentinel hi for file-level (`file:-`) anchors
# files may be dotfiles (.env) or well-known extension-less manifests (Gemfile)
FILE_RE = r"[\w./-]*\.[A-Za-z0-9]+|Gemfile|Dockerfile|Procfile|Jenkinsfile|Makefile"
FILE_TOKEN = re.compile(rf"({FILE_RE}):(\d+)(?:-(\d+))?")
FILE_LEVEL_TOKEN = re.compile(rf"({FILE_RE}):-")
BARE_TOKEN = re.compile(r"(?<![\w:./-])(\d+)(?:-(\d+))?(?![\w.])")
# a file mentioned WITHOUT a line — how agents cite global/absence findings
FILE_MENTION = re.compile(rf"(?<![\w./-])({FILE_RE})(?![\w.:])")
ROW_RE = re.compile(r"^\|\s*\w[\w.a-z]*\s*\|.*\|.*\|", re.I)  # 3+ col table row
SEC_RE = re.compile(r"^###\s+((?:SEC|T)-\d+)", re.I)


def scan_tokens(text):
    """[(file, lo, hi)] — bare ranges inherit the most recent file;
    `file:-` anchors become file-level tokens (lo=0, hi=FILE_LEVEL_MAX)."""
    tokens, last_file = [], None
    pos = 0
    while pos < len(text):
        fl = FILE_LEVEL_TOKEN.match(text, pos)
        if fl:
            tokens.append((fl.group(1), 0, FILE_LEVEL_MAX))
            pos = fl.end()
            continue
        fm = FILE_TOKEN.match(text, pos)
        if fm:
            last_file = fm.group(1)
            tokens.append((last_file, int(fm.group(2)),
                           int(fm.group(3) or fm.group(2))))
            pos = fm.end()
            continue
        bm = BARE_TOKEN.match(text, pos)
        if bm and last_file:
            tokens.append((last_file, int(bm.group(1)),
                           int(bm.group(2) or bm.group(1))))
            pos = bm.end()
            continue
        pos += 1
    return tokens


def scan_bare_files(text):
    """Basenames of files cited WITHOUT any line (global/absence findings)."""
    cited = {m.group(1) for m in FILE_TOKEN.finditer(text)}
    return {m.group(1).rsplit("/", 1)[-1] for m in FILE_MENTION.finditer(text)
            if m.group(1) not in cited}


def parse_expected(fixture_dir: Path):
    """[(label, tokens)] from expected-findings.md table rows."""
    ef = fixture_dir / "expected-findings.md"
    if not ef.exists():
        sys.exit(f"error: {ef} not found")
    rows, in_must_not = [], False
    for line in ef.read_text(encoding="utf-8").splitlines():
        if line.strip().lower().startswith("## must not"):
            in_must_not = True
        if in_must_not or not ROW_RE.match(line):
            continue
        tokens = scan_tokens(line)
        if tokens:
            rows.append((line.strip()[:110], tokens))
    return rows


def parse_report(report_path: Path):
    """{SEC-id: (tokens, bare_files)} per findings section."""
    sections, current = {}, None
    for line in report_path.read_text(encoding="utf-8").splitlines():
        m = SEC_RE.match(line)
        if m:
            current = m.group(1).upper()
            sections[current] = []
        elif current:
            sections[current].append(line)
    return {sec: (scan_tokens("\n".join(ls)), scan_bare_files("\n".join(ls)))
            for sec, ls in sections.items()}


def basename(path):
    return path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def token_matches(expected_tok, report_tokens):
    ef, elo, ehi = expected_tok
    for rf, rlo, rhi in report_tokens:
        if basename(rf) != basename(ef):
            continue
        if max(elo, rlo - TOLERANCE) <= min(ehi, rhi + TOLERANCE):
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("fixture_dir")
    ap.add_argument("--min-recall", type=float, default=0.9)
    ap.add_argument("--min-precision", type=float, default=0.8)
    ap.add_argument("--max-phantoms", type=int, default=0)
    ap.add_argument("--append", nargs="?", const="evals/SCOREBOARD.md", default=None,
                    metavar="SCOREBOARD",
                    help="append the round row to evals/SCOREBOARD.md (or given path)")
    ap.add_argument("--label", default="manual round",
                    help="change trigger / PR ref recorded with the row")
    args = ap.parse_args()

    expected = parse_expected(Path(args.fixture_dir))
    report = parse_report(Path(args.report))
    all_report_toks = [t for toks, _ in report.values() for t in toks]

    matched, missed = 0, []
    all_bare = set().union(*(bare for _, bare in report.values())) if report else set()
    for label, toks in expected:
        hit = any(token_matches(t, all_report_toks) for t in toks)
        if not hit:
            # file-level rows are satisfied by ANY bare-file citation of that basename
            hit = any(lo == 0 and basename(f) in all_bare for f, lo, _ in toks)
        if hit:
            matched += 1
        else:
            missed.append(label)

    supported, phantoms = 0, []
    file_level_basenames = {basename(f) for _, etoks in expected
                            for f, lo, _ in etoks if lo == 0}
    for sec, (toks, bare) in report.items():
        ok = any(token_matches(t, toks) for _, etoks in expected for t in etoks)
        if not ok:
            # file-level support: a bare-file citation backs a `file:-` row of
            # the same basename (global/absence findings, e.g. "no lockfile")
            ok = bool(bare & file_level_basenames)
        if ok:
            supported += 1
        else:
            phantoms.append(sec)

    recall = matched / len(expected) if expected else 1.0
    precision = supported / len(report) if report else 1.0

    print(f"expected={len(expected)} reported={len(report)}")
    print(f"recall={recall:.3f} ({matched}/{len(expected)})")
    print(f"precision={precision:.3f} ({supported}/{len(report)})")
    print(f"phantoms={len(phantoms)} {phantoms}")
    for m in missed:
        print(f"  missed: {m}")

    ok = (recall >= args.min_recall and precision >= args.min_precision
          and len(phantoms) <= args.max_phantoms)
    print("RESULT: PASS" if ok else "RESULT: FAIL (thresholds not met)")

    if args.append:
        sb = Path(args.append)
        row = (f"| {date.today().isoformat()} | {Path(args.fixture_dir).name} "
               f"| {recall:.2%} | {precision:.2%} | {len(phantoms)} "
               f"| {matched}/{len(expected)} | {args.label} |")
        header = ("# Eval Scoreboard\n\nRound history for scored audits. "
                  "See evals/run.md and the scorer --append flag.\n\n"
                  "## Round history\n\n"
                  "| Date | Fixture/App | Recall | Precision | Phantoms "
                  "| Found/Expected | Trigger |\n|---|---|---|---|---|---|---|\n")
        if not sb.exists():
            sb.parent.mkdir(parents=True, exist_ok=True)
            sb.write_text(header + row + "\n", encoding="utf-8")
        else:
            with sb.open("a", encoding="utf-8") as fh:
                fh.write(row + "\n")
        print(f"scoreboard: appended -> {sb}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
