@echo off
title VEIL v3.0.0-sih — Release Candidate Tag and Push
echo ===============================================================================
echo   VEIL v3.0.0-sih — Final Release Candidate Tag and GitHub Push
echo ===============================================================================

echo 1. Staging and committing release README and metadata...
git add .
git commit -m "release: VEIL v3.0.0-sih"

echo 2. Pushing main branch to origin...
git push origin main

echo 3. Creating official release tag v3.0.0-sih...
git tag -a v3.0.0-sih -m "VEIL v3.0.0-sih — SIH Competition Release"

echo 4. Pushing tag to GitHub...
git push origin v3.0.0-sih

echo ===============================================================================
echo   VEIL v3.0.0-sih officially published to GitHub!
echo ===============================================================================
pause
