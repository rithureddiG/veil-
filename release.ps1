# VEIL v3.0.0-sih - Final Release Candidate Tag and GitHub Push

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  VEIL v3.0.0-sih - Final Release Candidate Tag and GitHub Push" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

# 1. Commit any remaining changes
Write-Host "1. Staging and committing release README and metadata..." -ForegroundColor Yellow
git add .
git commit -m "release: VEIL v3.0.0-sih"

# 2. Push main branch
Write-Host "2. Pushing main branch to origin..." -ForegroundColor Yellow
git push origin main

# 3. Create annotated git tag
Write-Host "3. Creating official release tag v3.0.0-sih..." -ForegroundColor Yellow
git tag -a v3.0.0-sih -m "VEIL v3.0.0-sih - SIH Competition Release"

# 4. Push tag to GitHub
Write-Host "4. Pushing tag to GitHub..." -ForegroundColor Yellow
git push origin v3.0.0-sih

Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "  VEIL v3.0.0-sih officially published to GitHub!" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
