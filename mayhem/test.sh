#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Hamlib's own check programs (tests/test*.c) plus known-answer probes of the rigctl command interpreter
# against the built-in dummy rig. Everything was built by build.sh (normal flags) into build/test/tests.
T="$SRC/build/test/tests"
[ -x "$T/rigctl" ] || { echo "missing $T/rigctl: build.sh did not build the test tree" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

PASS=0
FAIL=0

# check <name> <expected> <actual>: exact comparison
check() {
  if [ "$2" == "$3" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3" >&2
  fi
}

norm() { tr -d '\0' | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//'; }

# --- testbcd: BCD encode/decode round trip, both byte orders
out="$("$T/testbcd" 145000000 10 2>/dev/null | tr -d '\0')"
check "bcd little endian digits" "BCD: 00,00,00,45,01" "$(grep -m1 '^BCD:' <<<"$out")"
check "bcd big endian digits" "BCD: 01,45,00,00,00" "$(grep '^BCD:' <<<"$out" | tail -1)"
check "bcd recoded" "145000000 145000000" "$(grep '^Result after recoding:' <<<"$out" | sed 's/.*: //' | tr '\n' ' ' | sed 's/ $//')"
check "bcd 6 digits" "BCD: 56,34,12,00" "$("$T/testbcd" 123456 8 2>/dev/null | grep -m1 '^BCD:')"

# --- testloc: Maidenhead locator conversion and great-circle distance / bearing
out="$("$T/testloc" JN58td 6 2>/dev/null | tr -d '\0')"
check "locator latitude" "Latitude: 48.145833 48 8' 45.00\"" "$(grep -m1 '^  Latitude:' <<<"$out" | norm)"
check "locator longitude" "Longitude: 11.625000 11 37' 30.00\"" "$(grep -m1 '^  Longitude:' <<<"$out" | norm)"
check "locator recoded" "Recoded: JN58TD55AA00" "$(grep '^  Recoded:' <<<"$out" | norm)"
out="$("$T/testloc" EM49hv 6 JN58td 2>/dev/null | tr -d '\0')"
check "locator distance" "Distance: 7644.000908km" "$(grep '^Distance:' <<<"$out")"
check "locator bearing" "Bearing: 44.00, 44 0' 0.00\"" "$(grep '^Bearing:' <<<"$out" | norm)"

# --- testgrid
check "grid locator to lat/lon" "Locator EM49hv = Lat:39.8958, Lon:-91.375" "$("$T/testgrid" 2>/dev/null | grep '^Locator ')"

# --- testfreq: GHz()/MHz() macros
check "freq macros" "GHz(2) = 2000000000
GHz(4) = 4000000000
GHz(5) = 5000000000
GHz(1.3) = 1300000000
GHz(1.234567890) = 1234567890
GHz(123.456789012) = 123456789012" "$("$T/testfreq" 2>&1 | grep '^GHz')"

# --- testrigcaps: rig_caps structure layout (ABI check)
check "rig_caps offsets" "Offsets are OK (i.e. have not changed)" "$("$T/testrigcaps" 2>&1 | grep -m1 '^Offsets')"

# --- testcookie: rig cookie arbitration; its own "Test#.. OK" lines are the assertions
out="$("$T/testcookie" 2>/dev/null)"
ok=$(grep -c '^Test#.* OK' <<<"$out")
bad=$(grep -c '^Test#.* Failed' <<<"$out")
check "cookie tests passed" "14 0" "$ok $bad"

# --- rigctl against the dummy rig (model 1): the interpreter, caches and the backend's state machine
check "rigctl default frequency" "145000000" "$("$T/rigctl" -m1 f 2>/dev/null)"

script='F 7100000
f
M USB 2400
m
T 1
t
L AF 0.5
l AF
'
expected='F 7100000 
f 7100000
M USB 2400 
m USB
2400
T 1 
t 1
L AF 0.5 
l AF 0.5'
check "rigctl dummy session" "$expected" "$(printf '%s' "$script" | "$T/rigctl" -m1 - 2>/dev/null | grep -v '^$')"

script='V VFOB
v
F 3573000
f
S 1 VFOA
s
'
expected='V VFOB 
v VFOB
F 3573000 
f 3573000
S 1 VFOA 
s 1
VFOA'
check "rigctl dummy vfo and split" "$expected" "$(printf '%s' "$script" | "$T/rigctl" -m1 - 2>/dev/null | grep -v '^$')"

check "rigctl set then get frequency" "F 14074000 f 14074000" "$(printf 'F 14074000\nf\n' | "$T/rigctl" -m1 - 2>/dev/null | norm)"

check "rigctl unknown command" "Command 'bogus' not found!" "$("$T/rigctl" -m1 --skip-init '\bogus' 2>&1 | grep -m1 'not found' | sed 's/\\//')"

emit_ctrf "hamlib-checks" "$PASS" "$FAIL" 0
