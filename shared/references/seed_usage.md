# Seed Usage (Semgrep / Joern)

Incorporate Semgrep and Joern scan outputs as seed signals during auto-scan phases.
For secrets/data-protection, use Gitleaks as the primary seed source and keep Semgrep as fallback for config patterns.

Guidance:
- Use seed outputs to prioritize review, but confirm findings in code.
- Do not include seed content in the final Markdown report.
- Record seed usage only in JSON metadata.

Metadata field:
```json
"metadata": {
  "seed_used": true,
  "seed_sources": ["state/<prefix>/seed_gitleaks.json", "state/<prefix>/seed_semgrep.json", "state/<prefix>/seed_joern.json"]
}
```
