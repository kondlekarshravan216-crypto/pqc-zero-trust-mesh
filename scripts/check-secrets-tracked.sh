#!/usr/bin/env bash
# Usage: check-secrets-tracked.sh [dir-inside-git-repo]
# READ-ONLY. Reports PATHS ONLY (never contents). Does not delete or untrack anything.
# Exit: 0 clean | 1 findings | 2 not a git repository.
set -uo pipefail
dir="${1:-.}"
top="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || { echo "NOT A GIT REPOSITORY: $dir (cannot check tracking)"; exit 2; }
cd "$top" || exit 2
modrel=""; if [[ -f "$(cd "$dir" && pwd -P)/scripts/lib.sh" ]]; then modrel="$(realpath --relative-to="$top" "$(cd "$dir" && pwd -P)")/"; [[ "$modrel" == "./" ]] && modrel=""; fi
rc=0
pat='(\.key|\.pem|\.csr|\.p12|\.pfx|\.jks|\.srl)$|(^|/)pki/out/|(^|/)tests/work/'
while IFS= read -r -d '' f; do [[ "$f" =~ $pat ]] && { echo "TRACKED-SECRET-PATH         $f"; rc=1; }; done < <(git ls-files -z)
while IFS= read -r f; do [[ -n "$f" ]] && { echo "TRACKED-PRIVATE-KEY-CONTENT $f"; rc=1; }; done < <(git grep -l -I -E '^-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----' 2>/dev/null)
while IFS= read -r -d '' f; do [[ "$f" =~ $pat ]] && { echo "UNTRACKED-NOT-IGNORED       $f"; rc=1; }; done < <(git ls-files -z --others --exclude-standard)
for p in pki/out/ca/ca.key pki/out/svc/svc.key pki/out/svc/svc.crt pki/out/ca/ca.srl tests/work/x.key tests/work/fixture.csr tests/work/x.p12 tests/work/x.pfx tests/work/x.pem svc.key svc.pem svc.csr; do
  git check-ignore -q -- "${modrel}${p}" || { echo "NOT-IGNORED-BY-RULES        ${modrel}${p}"; rc=1; }
done
[[ $rc -eq 0 ]] && echo "OK: no tracked secret-like paths or key content; sample secret paths are ignored."
exit $rc
