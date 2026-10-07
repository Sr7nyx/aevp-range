# AEVP -- Claude Sonnet 5 via OpenRouter : full 6x3 matrix
# Usage:  .\.venv\Scripts\Activate.ps1 ; $env:OPENROUTER_API_KEY="sk-or-..." ; .\run_sonnet.ps1
#
# Staged on purpose: a SMOKE run at N=5 measures this model's real token use
# before the full run commits your credits. Sonnet 5 is a reasoning model, and
# thinking tokens bill as OUTPUT -- the projection is seeded from gpt-oss-120b
# and could understate it. Measure, then commit.

$MODEL     = "anthropic/claude-sonnet-5"
$PRICE_IN  = 2.0     # USD per 1M input  (introductory through 2026-08-31)
$PRICE_OUT = 10.0    # USD per 1M output
$FX        = 4.7     # MYR per USD
$SMOKE_N   = 5
$FULL_N    = 30
$TWIN_N    = 10

Write-Host ""
Write-Host "=== AEVP : Claude Sonnet 5 (OpenRouter) : staged run ===" -ForegroundColor Cyan

if (-not $env:VIRTUAL_ENV) {
    Write-Host "STOP: venv is not active. Run:  .\.venv\Scripts\Activate.ps1" -ForegroundColor Red
    exit 1
}
if (-not $env:OPENROUTER_API_KEY) {
    Write-Host "STOP: OPENROUTER_API_KEY is not set in THIS session. Run:" -ForegroundColor Red
    Write-Host '  $env:OPENROUTER_API_KEY = "sk-or-..."'
    exit 1
}

$env:PYTHONPATH = "src"
New-Item -ItemType Directory -Force -Path "logs","results" | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmm"

Write-Host ""
Write-Host "--- Step 1/5 : endpoint check ---" -ForegroundColor Yellow
python run_range.py --preset openrouter --check --model $MODEL

Write-Host ""
$ans = Read-Host "Did the plain + tool probes both show [OK]? (y/n)"
if ($ans -ne "y") { Write-Host "Stopping. Fix the endpoint/credits first." -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "--- Step 2/5 : SMOKE run, N=$SMOKE_N blatant (~MYR 1-2) ---" -ForegroundColor Yellow
Write-Host "This measures Sonnet's REAL tokens/trial so the full projection is honest." -ForegroundColor DarkGray
Write-Host ""
$smokeLog = "logs\sonnet-smoke-$stamp.log"

python run_range.py --provider live --preset openrouter --tier blatant `
    --n $SMOKE_N --twin-n $SMOKE_N --model $MODEL `
    --price-in $PRICE_IN --price-out $PRICE_OUT --fx $FX --currency MYR `
    --max-steps 6 2>&1 | Tee-Object -FilePath $smokeLog

if (Test-Path "_runtime\campaign.json") {
    Copy-Item "_runtime\campaign.json" "results\sonnet-smoke-$stamp.json" -Force
}

Write-Host ""
Write-Host "--- Step 3/5 : read the SMOKE 'Budget:' line above ---" -ForegroundColor Yellow
Write-Host "Trials in that run = 6 cases x 2 arms x $SMOKE_N = 60." -ForegroundColor DarkGray
Write-Host "Divide its prompt_tokens and completion_tokens by 60 to get per-trial." -ForegroundColor DarkGray
Write-Host ""
$tokIn  = Read-Host "prompt_tokens / 60 = ? (press Enter to use the gpt-oss default 1172)"
$tokOut = Read-Host "completion_tokens / 60 = ? (press Enter to use the default 185)"
if (-not $tokIn)  { $tokIn  = 1172 }
if (-not $tokOut) { $tokOut = 185 }

Write-Host ""
Write-Host "--- Step 4/5 : projection for the FULL matrix at your measured rates ---" -ForegroundColor Yellow
python run_range.py --estimate --preset openrouter --tier all --n $FULL_N --twin-n $TWIN_N `
    --model $MODEL --tok-in $tokIn --tok-out $tokOut `
    --price-in $PRICE_IN --price-out $PRICE_OUT --fx $FX --currency MYR

Write-Host ""
$ans = Read-Host "Does that fit your budget? Start the full N=$FULL_N matrix? (y/n)"
if ($ans -ne "y") {
    Write-Host "Cancelled. Lower `$FULL_N at the top of this script and rerun." -ForegroundColor DarkGray
    exit 0
}

Write-Host ""
Write-Host "--- Step 5/5 : full matrix ---" -ForegroundColor Yellow
$fullLog = "logs\sonnet-N$FULL_N-$stamp.log"

python run_range.py --provider live --preset openrouter --tier all `
    --n $FULL_N --twin-n $TWIN_N --model $MODEL `
    --price-in $PRICE_IN --price-out $PRICE_OUT --fx $FX --currency MYR `
    --max-steps 6 2>&1 | Tee-Object -FilePath $fullLog

Write-Host ""
if (Test-Path "_runtime\campaign.json") {
    $out = "results\sonnet-N$FULL_N-$stamp.json"
    Copy-Item "_runtime\campaign.json" $out -Force
    Write-Host "Saved: $out" -ForegroundColor Green
} else {
    Write-Host "No _runtime\campaign.json -- the run did not finish." -ForegroundColor Red
}
Write-Host "Log: $fullLog" -ForegroundColor Green
Write-Host ""
