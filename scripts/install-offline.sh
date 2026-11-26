#!/bin/sh
# Install or upgrade ROMULUS from an offline bundle. Needs no network access and no root.
#
#   sh install-offline.sh [--no-extras] [--python <interpreter>] [--no-doctor] <romulus-home>
#
# Run it from the unpacked bundle, as the account that owns the ROMULUS home. It:
#   1. verifies every file of the bundle against SHA256SUMS, and refuses files SHA256SUMS does not list;
#   2. refuses a host whose Python, architecture or C library the bundle was not built for;
#   3. creates <romulus-home> (mode 700) with db, logs, reports and cache, and a venv if there is none;
#   4. installs the dependencies from the bundle's wheels, with pip's index turned off;
#   5. puts the application tree at <romulus-home>/app (the previous one is kept as app.old) and installs it;
#   6. checks that the installed package finds its prompts, patterns and content;
#   7. runs `romulus doctor` when <romulus-home>/.env exists, and otherwise prints the next steps.
# Run over an existing install it upgrades in place. It never creates, changes or removes .env, the database,
# reports, logs or the stage directory. If a step fails, the previous application tree is put back.
#
#   --no-extras   install without the optional dependency groups the bundle carries (the AI provider SDK)
#   --python P    the interpreter to build the venv with (default: python<target version>, then python3)
#   --no-doctor   do not run doctor at the end
set -eu
umask 077

say() { printf '%s\n' "$*"; }
die() { printf 'install-offline: %s\n' "$*" >&2; exit 1; }

USE_EXTRAS=1
RUN_DOCTOR=1
PY=""
H=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-extras) USE_EXTRAS=0 ;;
    --no-doctor) RUN_DOCTOR=0 ;;
    --python) [ $# -ge 2 ] || die "--python needs an interpreter"; PY="$2"; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $1 (see --help)" ;;
    *) [ -z "$H" ] || die "give one ROMULUS home, not several"; H="$1" ;;
  esac
  shift
done
[ -n "$H" ] || die "usage: sh install-offline.sh [--no-extras] [--python <interpreter>] [--no-doctor] <romulus-home>"
case "$H" in
  /*) ;;
  *) die "give the ROMULUS home as an absolute path, not $H" ;;
esac
case "$H" in
  *[!A-Za-z0-9._/+-]*) die "the ROMULUS home path may hold only letters, digits and . _ + - /" ;;
esac
H=${H%/}
[ -n "$H" ] || die "the ROMULUS home cannot be /"

B=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P) || die "cannot find the bundle directory"
cd "$B"
case "$B/" in
  "$H"/app/*|"$H"/app.new/*|"$H"/app.old/*|"$H"/venv/*)
    die "unpack the bundle outside $H/app, $H/app.old and $H/venv: the install replaces them" ;;
esac

# --- 1. the bundle is whole and unchanged -------------------------------------------------------------------
for f in SHA256SUMS MANIFEST.json TARGET install-offline.sh; do
  [ -f "$f" ] || die "this is not a complete bundle: $f is missing from $B"
done
[ -d app ] && [ -d wheels ] && [ -d requirements ] || die "this is not a complete bundle: app, wheels or requirements is missing"
odd=$(find . ! -type f ! -type d | head -n 5)
[ -z "$odd" ] || die "the bundle holds entries that are not regular files or directories: $odd"
if grep -q -v -E '^[0-9a-f]{64}  [A-Za-z0-9._+/-]+$' SHA256SUMS; then
  die "SHA256SUMS has lines that are not '<sha256>  <path>'"
fi
listed=$(sed 's/^[0-9a-f]*  //' SHA256SUMS | LC_ALL=C sort)
present=$(find . -type f ! -path ./SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort)
if [ "$listed" != "$present" ]; then
  nl='
'
  set -f
  for f in $present; do
    case "$nl$listed$nl" in *"$nl$f$nl"*) ;; *) say "  not listed in SHA256SUMS: $f" >&2 ;; esac
  done
  for f in $listed; do
    case "$nl$present$nl" in *"$nl$f$nl"*) ;; *) say "  listed in SHA256SUMS but missing: $f" >&2 ;; esac
  done
  set +f
  die "the bundle's files are not exactly the files SHA256SUMS lists; nothing was installed"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sums=$(sha256sum -c SHA256SUMS 2>&1) || { say "$sums" | grep -v ': OK$' >&2 || true; die "checksum verification failed; nothing was installed"; }
elif command -v shasum >/dev/null 2>&1; then
  sums=$(shasum -a 256 -c SHA256SUMS 2>&1) || { say "$sums" | grep -v ': OK$' >&2 || true; die "checksum verification failed; nothing was installed"; }
else
  die "sha256sum (coreutils) is needed to verify the bundle"
fi
say "bundle verified: $(grep -c '' SHA256SUMS) files match SHA256SUMS"

# --- 2. the host is the one the bundle was built for ---------------------------------------------------------
fact() { sed -n "s/^$1=//p" TARGET | head -n 1; }
T_PY=$(fact python); T_ARCH=$(fact arch); T_GLIBC=$(fact glibc); T_COMMIT=$(fact commit)
T_VERSION=$(fact version); T_EXTRAS=$(fact extras); T_FORMAT=$(fact format)
for v in "$T_PY" "$T_ARCH" "$T_GLIBC" "$T_COMMIT" "$T_VERSION" "$T_FORMAT"; do
  case "$v" in ""|*[!A-Za-z0-9._+-]*) die "the bundle's TARGET file is not readable" ;; esac
done
case "$T_EXTRAS" in *[!A-Za-z0-9._,-]*) die "the bundle's TARGET file is not readable" ;; esac
[ "$T_FORMAT" = 1 ] || die "this installer reads bundle format 1; the bundle is format $T_FORMAT"

if [ -n "$PY" ]; then
  command -v "$PY" >/dev/null 2>&1 || die "--python $PY: no such interpreter"
elif command -v "python$T_PY" >/dev/null 2>&1; then
  PY="python$T_PY"
elif command -v python3 >/dev/null 2>&1; then
  PY=python3
else
  die "Python $T_PY was not found. Install it, with its venv module, from this host's own package manager, or name it with --python."
fi
probe=$("$PY" -c 'import sys, platform
libc = platform.libc_ver()
impl = getattr(getattr(sys, "implementation", None), "name", "unknown")
print("%d.%d %s %s %s %s" % (sys.version_info[0], sys.version_info[1], impl, platform.machine() or "unknown",
                             libc[0] or "none", libc[1] or "0"))' | tr -d '\r') || die "$PY did not run"
read -r H_PY H_IMPL H_ARCH H_LIBC H_LIBCVER <<EOF
$probe
EOF
[ "$H_PY" = "$T_PY" ] || die "this bundle is for Python $T_PY, but $PY is Python ${H_PY:-unknown}. Its wheels will not install on another version: name a Python $T_PY interpreter with --python, or build a bundle for Python ${H_PY:-unknown} (--python-version). Nothing was installed."
[ "$H_IMPL" = cpython ] || die "this bundle is for CPython, but $PY is $H_IMPL. Nothing was installed."
[ "$(uname -s)" = Linux ] || die "this bundle installs on Linux, and this host is $(uname -s). Nothing was installed."
[ "$H_ARCH" = "$T_ARCH" ] || die "this bundle is for $T_ARCH hosts, but this host is $H_ARCH. Build a bundle with --arch $H_ARCH. Nothing was installed."
t_minor=${T_GLIBC#2.}
h_minor=${H_LIBCVER#2.}; h_minor=${h_minor%%.*}
case "$t_minor$h_minor" in *[!0-9]*) h_minor="" ;; esac
if [ "$H_LIBC" != glibc ] || [ -z "$h_minor" ] || [ "$h_minor" -lt "$t_minor" ]; then
  die "this bundle needs glibc $T_GLIBC or later, and this host has $H_LIBC $H_LIBCVER. Build a bundle with a lower --glibc if the dependencies publish wheels for it. Nothing was installed."
fi

# --- 3. home and venv -------------------------------------------------------------------------------------------
if [ -e "$H" ]; then
  [ -d "$H" ] && [ -w "$H" ] || die "$H is not a directory this account can write to"
fi
VPY="$H/venv/bin/python"
if [ -e "$H/venv" ]; then
  v=$("$VPY" -c 'import sys; print("%d.%d" % (sys.version_info[0], sys.version_info[1]))' 2>/dev/null | tr -d '\r') || v=""
  [ "${v:-unknown}" = "$T_PY" ] || die "the venv at $H/venv runs Python ${v:-(none that works)}, and this bundle is for Python $T_PY. Move it aside (mv $H/venv $H/venv.old) and run the installer again. Nothing was installed."
fi
mkdir -p "$H" "$H/db" "$H/logs" "$H/reports" "$H/cache"
chmod 700 "$H"
if [ ! -e "$H/venv" ]; then
  say "creating the venv with $PY"
  if ! "$PY" -m venv "$H/venv"; then
    rm -rf "$H/venv"
    die "could not create a venv with $PY. Python's venv module (with ensurepip) must be installed from this host's package manager."
  fi
fi
"$VPY" -m pip --version >/dev/null 2>&1 || die "the venv at $H/venv has no pip. Python's venv module must include ensurepip; move the venv aside and run again once it does."

# pip reads nothing from this host's configuration or environment, and has no index to turn to
for v in $(env | sed -n 's/^\(PIP_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$v"; done
PIP_CONFIG_FILE=/dev/null
export PIP_CONFIG_FILE
pip_offline() {
  "$VPY" -m pip install --no-index --find-links "$B/wheels" --no-cache-dir --disable-pip-version-check --no-input -q "$@"
}

# --- 4. dependencies, before anything of the current install is replaced ---------------------------------
SPEC="$H/app"
if [ "$USE_EXTRAS" = 1 ] && [ -n "$T_EXTRAS" ]; then
  SPEC="$H/app[$T_EXTRAS]"
  set -- -r requirements/runtime.txt -r requirements/extras.txt
else
  T_EXTRAS=""
  set -- -r requirements/runtime.txt
fi
say "installing dependencies from the bundle (no index)"
pip_offline "$@" || die "the dependencies did not install from the bundle's wheels (see pip's message above). The application tree at $H/app was not touched."

# --- 5. the application tree, then the package -------------------------------------------------------------
rm -rf "$H/app.new"
mkdir "$H/app.new"
cp -R "$B/app/." "$H/app.new/"
say "$T_COMMIT" > "$H/app.new/DEPLOYED_COMMIT"
rm -rf "$H/app.old"
HAD_APP=0
if [ -d "$H/app" ]; then mv "$H/app" "$H/app.old"; HAD_APP=1; fi
mv "$H/app.new" "$H/app"
roll_back() {
  rm -rf "$H/app"
  if [ "$HAD_APP" = 1 ]; then
    mv "$H/app.old" "$H/app"
    "$VPY" -m pip install --no-index --find-links "$B/wheels" --no-cache-dir --disable-pip-version-check --no-input -q --no-deps -e "$H/app" >/dev/null 2>&1 || true
    die "$1 The previous application tree was put back at $H/app."
  fi
  die "$1 No application tree was left at $H/app."
}
say "installing ROMULUS $T_VERSION ($T_COMMIT) from $H/app"
pip_offline -e "$SPEC" || roll_back "ROMULUS did not install from the bundle (see pip's message above)."

# --- 6. the installed package finds what it ships with ---------------------------------------------------
set --
if [ -n "$T_EXTRAS" ]; then
  for extra in $(say "$T_EXTRAS" | tr ',' ' '); do set -- "$@" --extra "$extra"; done
fi
"$H/venv/bin/romulus" --help >/dev/null || roll_back "The installed romulus command does not run."
"$VPY" "$H/app/scripts/install_check.py" --app "$H/app" "$@" || roll_back "The installed package does not find everything it ships with (see the FAIL lines above)."

say "ROMULUS $T_VERSION ($T_COMMIT) is installed in $H"
if [ -f "$H/web.pid" ] && kill -0 "$(cat "$H/web.pid" 2>/dev/null)" 2>/dev/null; then
  say "The web UI is running the previous code: restart it with  bash $H/app/scripts/web-restart.sh"
fi

# --- 7. doctor, or what to do next ---------------------------------------------------------------------------
if [ ! -f "$H/.env" ]; then
  say "Next steps:"
  say "  cp $H/app/.env.example $H/.env && chmod 600 $H/.env"
  say "  edit $H/.env: set ROMULUS_HOME=$H, the sources and ROMULUS_SECRET_KEY (see $H/app/docs/OPERATOR_GUIDE.md)"
  say "  $H/venv/bin/romulus --env-file $H/.env doctor"
  exit 0
fi
[ "$RUN_DOCTOR" = 1 ] || exit 0
env_home=$(sed -n 's/^ROMULUS_HOME=[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$H/.env" | head -n 1 | tr -d "\"'")
if [ -n "$env_home" ] && [ "${env_home%/}" != "$H" ]; then
  say "Note: $H/.env sets ROMULUS_HOME=$env_home, not $H. Doctor below is run against $H; correct the .env."
fi
say "running: romulus --env-file $H/.env doctor"
rc=0
ROMULUS_HOME="$H" "$H/venv/bin/romulus" --env-file "$H/.env" doctor || rc=$?
if [ "$rc" -ne 0 ]; then
  say "The install is complete. Doctor reported failures (exit $rc): fix the FAIL lines above before a hunt."
fi
exit 0
