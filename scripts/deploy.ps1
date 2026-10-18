# Deploy the working tree to the lab VM (romulus-vm) and install it into the v2 venv.
# Usage: powershell -File scripts/deploy.ps1 [-SkipInstall]
# Fails loudly on any step: PowerShell 5.1 does not stop on failing native commands by itself, which
# once let a stale archive be uploaded. Every deploy is stamped with the git commit it shipped.
param([switch]$SkipInstall)
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "deploy failed at: $what (exit $LASTEXITCODE)" } }

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
# Always Windows' own bsdtar: Git Bash puts GNU tar first on PATH, and GNU tar cannot read this file list.
$tar = Join-Path $env:SystemRoot "System32\tar.exe"
if (-not (Test-Path $tar)) { throw "Windows tar not found at $tar" }

$commit = (git rev-parse --short HEAD).Trim(); Check "git rev-parse"
$dirty = if (git status --porcelain --untracked-files=no) { "+dirty" } else { "" }
$stamp = "$commit$dirty"
$tmp = Join-Path $env:TEMP "romulus-deploy.tgz"
if (Test-Path $tmp) { Remove-Item $tmp -Force }
# tracked + untracked-but-not-ignored files that exist (never .env, .venv, data)
$files = git ls-files --cached --others --exclude-standard | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
Check "git ls-files"
$list = Join-Path $env:TEMP "romulus-deploy.lst"
[IO.File]::WriteAllText($list, (($files -join "`n") + "`n"))
& $tar -czf $tmp -T $list; Check "tar"
if (-not (Test-Path $tmp)) { throw "deploy failed: archive was not created" }
scp -q $tmp romulus-vm:/tmp/romulus-deploy.tgz; Check "scp archive"
$remote = @'
set -e
H=/home/user/romulus-v2
STAMP="$1"; MODE="$2"
mkdir -p $H/app $H/db $H/logs $H/reports $H/cache && chmod 700 $H
rm -rf $H/app.new && mkdir $H/app.new && tar -xzf /tmp/romulus-deploy.tgz -C $H/app.new && rm -f /tmp/romulus-deploy.tgz
echo "$STAMP" > $H/app.new/DEPLOYED_COMMIT
rm -rf $H/app.old; if [ -d $H/app ]; then mv $H/app $H/app.old; fi; mv $H/app.new $H/app
[ -x $H/venv/bin/python ] || python3 -m venv $H/venv
if [ "$MODE" != "skip" ]; then $H/venv/bin/pip install -q --upgrade pip >/dev/null; $H/venv/bin/pip install -q -e "$H/app" pytest respx; fi
echo "deployed commit $(cat $H/app/DEPLOYED_COMMIT): $(cd $H/app && ls | tr '\n' ' ')"
'@
$remoteFile = Join-Path $env:TEMP "romulus-deploy.sh"
[IO.File]::WriteAllText($remoteFile, $remote.Replace("`r", ""))
scp -q $remoteFile romulus-vm:/tmp/romulus-deploy.sh; Check "scp script"
$mode = if ($SkipInstall) { "skip" } else { "install" }
ssh romulus-vm "bash /tmp/romulus-deploy.sh $stamp $mode; rc=`$?; rm -f /tmp/romulus-deploy.sh; exit `$rc"; Check "remote install"
