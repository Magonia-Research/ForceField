#!/usr/bin/env bash
# Sync docs/ into the GitHub Pages repo that publishes it.
#
# The published site is a second checkout (Magonia-Research/forcefield-docs) that
# carries the same files with Jekyll front matter prepended. Nothing enforced that
# the two agreed, so an edit here could — and did — leave the site quietly stale.
#
# Front matter is read from the destination and re-emitted unchanged: title,
# nav_order and parent are properties of the site's navigation, not of the doc.
# That also means this can only update a page the site already has. A new doc
# needs its front matter written once by hand; the script says so rather than
# guessing a nav position.
#
#   scripts/sync-docs.sh              # write the site copies
#   scripts/sync-docs.sh --check      # report drift, change nothing, exit 1 if any
#   scripts/sync-docs.sh --check ../elsewhere
#
# Exits 0 when the site repo is not present: this is a maintainer convenience,
# not a gate, and a missing sibling checkout is not a failure. The gate that runs
# everywhere is tests/test_docs.py, which needs no second checkout.

set -euo pipefail

CHECK=0
DOCS_REPO=""
for arg in "$@"; do
  case "$arg" in
    --check) CHECK=1 ;;
    -h | --help)
      sed -n '2,20p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    -*)
      echo "unknown option: $arg" >&2
      exit 2
      ;;
    *) DOCS_REPO="$arg" ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "$DOCS_REPO" ]; then
  DOCS_REPO="${FORCEFIELD_DOCS_REPO:-$REPO_ROOT/../forcefield-docs}"
fi

if [ ! -d "$DOCS_REPO" ]; then
  echo "sync-docs: no site checkout at $DOCS_REPO — nothing to do."
  echo "           Clone Magonia-Research/forcefield-docs beside this repo, or set"
  echo "           FORCEFIELD_DOCS_REPO, to sync the published site."
  exit 0
fi
DOCS_REPO=$(cd "$DOCS_REPO" && pwd)

# source-under-docs/ : destination-in-site-repo. Kept in step with tests/test_docs.py,
# which fails if a file under docs/ is missing from this map.
MAP="
threat-model.md:threat-model.md
hooks.md:hooks.md
configuration.md:configuration.md
architecture.md:architecture.md
logging/README.md:logging/index.md
logging/00-field-reference.md:logging/00-field-reference.md
logging/01-records-by-hook.md:logging/01-records-by-hook.md
logging/02-platforms.md:logging/02-platforms.md
"

# Everything up to and including the closing '---' of the YAML front matter.
front_matter() {
  awk 'NR==1 && $0=="---" {print; inside=1; next}
       inside && $0=="---" {print; exit}
       inside {print}' "$1"
}

# Everything after it, with leading blank lines dropped so the join is stable.
body_after_front_matter() {
  local file=$1 close
  if [ "$(head -n 1 "$file")" != "---" ]; then
    cat "$file"
    return
  fi
  close=$(awk 'NR>1 && $0=="---" {print NR; exit}' "$file")
  if [ -z "$close" ]; then
    echo "sync-docs: $file opens front matter it never closes" >&2
    return 1
  fi
  tail -n "+$((close + 1))" "$file" | awk 'NF {found=1} found {print}'
}

drift=0
missing=0
updated=0

while IFS=: read -r src dst; do
  [ -n "$src" ] || continue
  src_path="$REPO_ROOT/docs/$src"
  dst_path="$DOCS_REPO/$dst"

  if [ ! -f "$src_path" ]; then
    echo "MISSING SOURCE  docs/$src (mapped to $dst)"
    missing=$((missing + 1))
    continue
  fi
  if [ ! -f "$dst_path" ]; then
    echo "MISSING PAGE    $dst — add it to the site once, with front matter, then rerun"
    missing=$((missing + 1))
    continue
  fi

  if diff -q <(body_after_front_matter "$dst_path") "$src_path" >/dev/null 2>&1; then
    continue
  fi

  drift=$((drift + 1))
  if [ "$CHECK" -eq 1 ]; then
    echo "DRIFTED         $dst"
    diff -u <(body_after_front_matter "$dst_path") "$src_path" |
      sed -e "s|^--- .*|--- site/$dst|" -e "s|^+++ .*|+++ docs/$src|" || true
  else
    tmp=$(mktemp)
    {
      front_matter "$dst_path"
      echo
      cat "$src_path"
    } >"$tmp"
    mv "$tmp" "$dst_path"
    echo "UPDATED         $dst"
    updated=$((updated + 1))
  fi
done <<EOF
$(echo "$MAP" | sed '/^[[:space:]]*$/d')
EOF

if [ "$missing" -gt 0 ]; then
  echo
  echo "sync-docs: $missing mapping(s) could not be resolved."
  exit 1
fi

if [ "$CHECK" -eq 1 ]; then
  if [ "$drift" -gt 0 ]; then
    echo
    echo "sync-docs: $drift page(s) drifted. Run scripts/sync-docs.sh to update the site."
    exit 1
  fi
  echo "sync-docs: the published site matches docs/ ($DOCS_REPO)."
  exit 0
fi

if [ "$updated" -gt 0 ]; then
  echo
  echo "sync-docs: $updated page(s) updated in $DOCS_REPO. Commit and push there to publish."
else
  echo "sync-docs: already in sync ($DOCS_REPO)."
fi
