# VEIL v2.5 — Scientific Reproduction Docker Container
# Provides a clean, isolated environment to verify all VEIL security proofs.

FROM python:3.11-slim

WORKDIR /veil-reproduction

# Copy reproduction harness and golden test vectors
COPY . /veil-reproduction

# Set execution environment
ENV PYTHONUNBUFFERED=1

# Execute master scientific reproduction runner by default
CMD ["python", "run_all_reproductions.py"]
