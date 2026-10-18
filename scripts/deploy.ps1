# Deploy the working tree to the lab VM (romulus-vm) and install it into the v2 venv.
# Usage: powershell -File scripts/deploy.ps1 [-SkipInstall]
param([switch]$SkipInstall)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$tmp = Join-Path $env:TEMP "romulus-deploy.tgz"
# tracked + untracked-but-not-ignored files only (never .env, .venv, data)
$files = git ls-files --cached --others --exclude-standard
$list = Join-Path $env:TEMP "romulus-deploy.lst"
[IO.File]::WriteAllLines($list, $files)
tar -czf $tmp -T $list
scp -q $tmp romulus-vm:/tmp/romulus-deploy.tgz
$remote = @'
set -e
H=/home/user/romulus-v2
mkdir -p $H/app $H/db $H/logs $H/reports $H/cache && chmod 700 $H
rm -rf $H/app.new && mkdir $H/app.new && tar -xzf /tmp/romulus-deploy.tgz -C $H/app.new && rm -f /tmp/romulus-deploy.tgz
rm -rf $H/app.old; mv $H/app $H/app.old; mv $H/app.new $H/app
[ -x $H/venv/bin/python ] || python3 -m venv $H/venv
if [ "$1" != "skip" ]; then $H/venv/bin/pip install -q --upgrade pip >/dev/null; $H/venv/bin/pip install -q -e "$H/app" pytest respx; fi
echo "deployed: $(cd $H/app && ls | tr '\n' ' ')"
'@
$remoteFile = Join-Path $env:TEMP "romulus-deploy.sh"
[IO.File]::WriteAllText($remoteFile, $remote.Replace("`r", ""))
scp -q $remoteFile romulus-vm:/tmp/romulus-deploy.sh
$arg = if ($SkipInstall) { "skip" } else { "" }
ssh romulus-vm "bash /tmp/romulus-deploy.sh $arg; rm -f /tmp/romulus-deploy.sh"
