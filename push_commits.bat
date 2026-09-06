@echo off
title VEIL v3.0 — SIH Grand Finale Commit & GitHub Push
echo ===============================================================================
echo   VEIL v3.0 — Generating Granular Commits and Pushing to GitHub
echo ===============================================================================
node scripts/commit-history-builder.js
git push origin HEAD
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Pushing to origin main...
    git push origin main
)
pause
