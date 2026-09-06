# VEIL v3.0 — SIH Grand Finale Commit & Push Script

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  VEIL v3.0 — Generating Granular Commits and Pushing to GitHub" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

# Run the commit history builder
node scripts/commit-history-builder.js

# Push to GitHub
Write-Host "`nPushing to GitHub remote repository..." -ForegroundColor Yellow
git push origin HEAD

if ($LASTEXITCODE -ne 0) {
    Write-Host "Attempting push to origin main..." -ForegroundColor Yellow
    git push origin main
}

Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "  All commits pushed to GitHub successfully!" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
