# AEVP -- Cerebras free-tier full matrix (6x3, N=30)
# Usage:  .\.venv\Scripts\Activate.ps1 ; $env:CEREBRAS_API_KEY="csk-..." ; .\run_cerebras.ps1

$N        = 30
$TWIN_N   = 10
$REASON   = "low"      # blank this ("") if the reasoning probe fails in the check
$MODEL    = "gpt-oss-120b"

Write-Host ""
Write-Host "=== AEVP : Cerebras free tier : full 6x3 matrix (N=$N) ===" -ForegroundColor Cyan

if (-not $env:VIRTUAL_ENV) {
    Write-Host "STOP: venv is not active. Run this first:" -ForegroundColor Red
    Write-Host "  .\.venv\Scripts\Activate.ps1"
    exit 1
}
if (-not $env:CEREBRAS_API_KEY) {
    Write-Host "STOP: CEREBRAS_API_KEY is not set in THIS session. Run:" -ForegroundColor Red
    Write-Host '  $env:CEREBRAS_API_KEY = "csk-..."'
    exit 1
}

$env:PYTHONPATH = "src"
New-Item -ItemType Directory -Force -Path "logs","results" | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmm"
$log   = "logs\cerebras-N$N-$stamp.log"

Write-Host ""
Write-Host "--- Step 1/4 : endpoint check (costs ~3 calls) ---" -ForegroundColor Yellow
python run_range.py --preset cerebras --check --model $MODEL --reasoning-effort $REASON

Write-Host ""
$ans = Read-Host "Did the plain + tool probes both show [OK]? (y/n)"
if ($ans -ne "y") {
    Write-Host "Stopping. If only the reasoning probe failed, set REASON=`"`" at the top and rerun." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "--- Step 2/4 : projection (spends nothing) ---" -ForegroundColor Yellow
python run_range.py --estimate --preset cerebras --tier all --n $N --twin-n $TWIN_N --model $MODEL

Write-Host ""
Write-Host "Cerebras free tier is 1,000,000 tokens/day. If the projection above is close" -ForegroundColor DarkGray
Write-Host "to that, lower N. Trials that fail are non-fatal, but a mid-run daily cap will" -ForegroundColor DarkGray
Write-Host "error out every remaining trial." -ForegroundColor DarkGray
Write-Host ""
$ans = Read-Host "Start the run? It takes HOURS -- keep this window open and the laptop awake. (y/n)"
if ($ans -ne "y") { Write-Host "Cancelled."; exit 0 }

Write-Host ""
Write-Host "--- Step 3/4 : running. Live output is also saved to $log ---" -ForegroundColor Yellow
Write-Host ""

python run_range.py --provider live --preset cerebras --tier all `
    --n $N --twin-n $TWIN_N --model $MODEL --reasoning-effort $REASON `
    --max-steps 6 2>&1 | Tee-Object -FilePath $log

Write-Host ""
Write-Host "--- Step 4/4 : archiving results ---" -ForegroundColor Yellow
if (Test-Path "_runtime\campaign.json") {
    $out = "results\cerebras-N$N-$stamp.json"
    Copy-Item "_runtime\campaign.json" $out -Force
    Write-Host "Saved: $out" -ForegroundColor Green
    Write-Host "IMPORTANT: _runtime\campaign.json is OVERWRITTEN by the next run." -ForegroundColor DarkGray
    Write-Host "The archived copy above is your Cerebras result." -ForegroundColor DarkGray
} else {
    Write-Host "No _runtime\campaign.json found -- the run did not finish." -ForegroundColor Red
}
Write-Host "Log: $log" -ForegroundColor Green
Write-Host ""
