# ─────────────────────────────────────────────────────────────
#  launch.ps1 — Avvia Backend (FastAPI) e Frontend (Angular)
#  Uso: click destro → "Esegui con PowerShell"
#       oppure: .\launch.ps1
# ─────────────────────────────────────────────────────────────

$ROOT     = Split-Path -Parent $MyInvocation.MyCommand.Path
$BACKEND  = Join-Path $ROOT "backend"
$FRONTEND = Join-Path $ROOT "frontend"

# ── Controlla che le cartelle esistano ───────────────────────
foreach ($dir in @($BACKEND, $FRONTEND)) {
    if (-not (Test-Path $dir)) {
        Write-Host "ERRORE: cartella non trovata: $dir" -ForegroundColor Red
        exit 1
    }
}

# ── Avvia il Backend in una nuova finestra PowerShell ────────
Write-Host "Avvio Backend  →  http://localhost:8000 ..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command",
    "cd '$BACKEND'; uvicorn main:app --reload --port 8000"

# ── Avvia il Frontend in una nuova finestra PowerShell ───────
Write-Host "Avvio Frontend →  http://localhost:4200 ..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command",
    "cd '$FRONTEND'; npm start"

# ── Attende che i server siano pronti e apre il browser ──────
Write-Host ""
Write-Host "Attendo che i server siano pronti..." -ForegroundColor Yellow

$backendOk  = $false
$frontendOk = $false
$timeout    = 60   # secondi massimi di attesa
$elapsed    = 0

while ((-not $backendOk -or -not $frontendOk) -and $elapsed -lt $timeout) {
    Start-Sleep -Seconds 2
    $elapsed += 2

    if (-not $backendOk) {
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:8000/health" `
                                   -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
            if ($r.StatusCode -eq 200) {
                Write-Host "  Backend  pronto  (${elapsed}s)" -ForegroundColor Green
                $backendOk = $true
            }
        } catch {}
    }

    if (-not $frontendOk) {
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:4200" `
                                   -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
            if ($r.StatusCode -eq 200) {
                Write-Host "  Frontend pronto  (${elapsed}s)" -ForegroundColor Green
                $frontendOk = $true
            }
        } catch {}
    }
}

if ($backendOk -and $frontendOk) {
    Write-Host ""
    Write-Host "Tutto pronto! Apro il browser..." -ForegroundColor Green
    Start-Process "http://localhost:4200"
} else {
    Write-Host ""
    Write-Host "Timeout: uno o più servizi non hanno risposto in ${timeout}s." -ForegroundColor Red
    Write-Host "Controlla le finestre dei terminali per eventuali errori."     -ForegroundColor Red
}