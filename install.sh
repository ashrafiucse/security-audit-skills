#!/usr/bin/env bash
# Install security-skills globally by symlinking each skill into ~/.agents/skills.
# Usage:
#   ./install.sh           # install (symlink) globally
#   ./install.sh --print   # just print manual setup instructions
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_SRC="$REPO_ROOT/skills"
DEST="${HOME}/.agents/skills"

print_instructions() {
  cat <<EOF
Manual setup options:

1) Global (all projects):
     ln -s "$SKILLS_SRC"/* "$HOME/.agents/skills/"

2) Per-project — add to <project>/.pi/settings.json:
     { "skills": ["$SKILLS_SRC"] }

3) Load once, no install:
     pi --skill "$SKILLS_SRC/security-audit"
EOF
}

if [ "${1:-}" = "--print" ]; then
  print_instructions
  exit 0
fi

if [ ! -d "$SKILLS_SRC" ]; then
  echo "error: skills/ not found at $SKILLS_SRC" >&2
  exit 1
fi

mkdir -p "$DEST"
count=0
for skill_dir in "$SKILLS_SRC"/*/; do
  name="$(basename "$skill_dir")"
  target="$DEST/$name"
  if [ -e "$target" ] || [ -L "$target" ]; then
    echo "  skip  $name (already exists at $target)"
  else
    ln -s "$skill_dir" "$target"
    echo "  linked $name -> $target"
    count=$((count + 1))
  fi
done

echo
echo "Done. $count skill(s) installed globally."
echo "Restart your agent session, then try: /skill:security-audit"
