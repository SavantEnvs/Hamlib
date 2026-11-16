#!/usr/bin/env bash
#
# mayhem/build.sh - Hamlib: sanitized static library + fuzz harnesses (+ -standalone reproducers), then
# a clean, normal-flags build of upstream's own check programs for mayhem/test.sh.
# Runs inside the commit image as `mayhem` in /mayhem; offline and idempotent (no network, no installs).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS


cd "$SRC"

COMMON_CONF=(--disable-shared --enable-static --without-readline --without-libusb
             --without-cxx-binding --disable-html-matrix --without-indi --without-samplerate
             --disable-winradio --disable-parallel --without-xml-support)

# upstream's autotools are generated, not committed (build-aux/, configure and Makefile.in are untracked/ignored)
[ -x configure ] || ./bootstrap

# 1) the project itself, sanitized + DWARF 3, out of tree in build/fuzz.
#    float-cast-overflow is the one UBSan check relaxed (-fno-sanitize=): frequencies, levels and rates travel
#    as double and are cast to int/long all over the backends (rig.c:2284 `(int)freq % 10` trips on any
#    frequency above 2.1 GHz), so with it on every run would stop at that benign pattern and hide the rest.
RELAX="-fno-sanitize=float-cast-overflow"
FZ="$SRC/build/fuzz"
mkdir -p "$FZ"
if [ ! -f "$FZ/Makefile" ]; then
  (cd "$FZ" && "$SRC/configure" CC="$CC" \
     CFLAGS="$SANITIZER_FLAGS $RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1" \
     LDFLAGS="$SANITIZER_FLAGS" "${COMMON_CONF[@]}")
fi
make -C "$FZ/lib" -j"$MAYHEM_JOBS"
make -C "$FZ/src" -j"$MAYHEM_JOBS"
# rigctl's non-main objects (dump helpers, ...) are what the harness links; rigctl_parse.c itself is #included by it
make -C "$FZ/tests" -j"$MAYHEM_JOBS" rigctl

LIBS_FZ=$(printf 'print-libs:\n\t@echo $(LIBS) $(PTHREAD_LIBS)\n' | make -s -C "$FZ/tests" -f Makefile -f - print-libs)
CORE_OBJS=()
for o in dumpcaps dumpstate rig_tests rigctld_client rigctld_stream daemon_client; do
  CORE_OBJS+=("$FZ/tests/rigctl-$o.o")
done
INCS=(-DHAVE_CONFIG_H -DIN_HAMLIB -I"$SRC/include" -I"$FZ/include" -I"$FZ/include/hamlib" -I"$SRC/include/hamlib" -I"$SRC/tests" -I"$FZ/tests"
      -I"$SRC/src" -I"$FZ/src" -I"$SRC/rigs/icom" -I"$SRC/lib" -I"$FZ/security" -I"$SRC/security")
# Library state that outlives a rig (see mayhem/harnesses/lib_state.c) lives in statics; give the harnesses a copy of
# the archive in which those symbols are global so they can be reset per input.
STATE_SYMS=(read_string_generic.minlen rig_set_freq.last_band rig_get_freq.last_band sf_fails
            dummy_get_level.rfpower dummy_get_dcd.twiddle)
GLOBALIZE=()
for sym in "${STATE_SYMS[@]}"; do GLOBALIZE+=(--globalize-symbol="$sym"); done
LIBHAMLIB="$FZ/libhamlib-state.a"
objcopy "${GLOBALIZE[@]}" "$FZ/src/.libs/libhamlib.a" "$LIBHAMLIB"
LIBMISC="$FZ/lib/.libs/libmisc.a"

# 2) harnesses: fuzzer binary + -standalone reproducer; LSan is off at build time via lsan_off.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FZ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FZ/standalone_main.o"

WRAP_SLEEP=(-Wl,--wrap=usleep -Wl,--wrap=nanosleep -Wl,--wrap=clock_gettime)
build_harness() {  # <binary> <source> <cc defs> <extra objs...>
  local name="$1" src="$2" defs="$3"; shift 3
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1 $defs "${INCS[@]}" "$SRC/mayhem/harnesses/$src" "$SRC/mayhem/harnesses/fakeclock.c" "$SRC/mayhem/harnesses/lib_state.c" "$@" \
      "$LIBHAMLIB" "$LIBMISC" "$FZ/lsan_off.o" $LIBS_FZ $LIB_FUZZING_ENGINE "${WRAP_SLEEP[@]}" -o "$SRC/$name"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1 $defs "${INCS[@]}" "$SRC/mayhem/harnesses/$src" "$SRC/mayhem/harnesses/fakeclock.c" "$SRC/mayhem/harnesses/lib_state.c" "$@" \
      "$LIBHAMLIB" "$LIBMISC" "$FZ/lsan_off.o" $LIBS_FZ -fsanitize=fuzzer-no-link "$FZ/standalone_main.o" \
      "${WRAP_SLEEP[@]}" -o "$SRC/$name-standalone"
}
build_harness fuzz_rigctl_parse fuzz_rigctl_parse.c "" "${CORE_OBJS[@]}"
build_harness fuzz_icom_reply fuzz_rig_reply.c -DTARGET_ICOM
build_harness fuzz_kenwood_reply fuzz_rig_reply.c -DTARGET_KENWOOD
build_harness fuzz_newcat_reply fuzz_rig_reply.c -DTARGET_NEWCAT
build_harness fuzz_netrigctl_reply fuzz_rig_reply.c -DTARGET_NETRIGCTL

# 3) upstream's check programs and rigctl, normal flags, separate tree
TS="$SRC/build/test"
mkdir -p "$TS"
if [ ! -f "$TS/Makefile" ]; then
  (cd "$TS" && env -u CFLAGS -u LDFLAGS "$SRC/configure" CC="$CC" CFLAGS="-O2 $COVERAGE_FLAGS" \
     LDFLAGS="$COVERAGE_FLAGS" "${COMMON_CONF[@]}")
fi
make -C "$TS/lib" -j"$MAYHEM_JOBS"
make -C "$TS/src" -j"$MAYHEM_JOBS"
make -C "$TS/tests" -j"$MAYHEM_JOBS" rigctl testbcd testfreq testloc testgrid testrigcaps cachetest cachetest2 test2038 testcookie
