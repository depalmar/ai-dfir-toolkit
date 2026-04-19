# Pull request

## What this PR does

<!-- Brief description. New rule? Tuning? Docs? -->

## Type

- [ ] New detection rule
- [ ] Rule tuning (FP reduction or coverage improvement)
- [ ] Test artifact
- [ ] Documentation
- [ ] Bug fix
- [ ] Other: <!-- describe -->

## Attack technique / reference

<!-- For new rules: ATLAS ID, CVE, OWASP category, or public research link -->

## Checklist

- [ ] Rule references an attack technique (ATLAS / CVE / published research)
- [ ] Test artifact added in `tests/` (for new rules)
- [ ] False positives documented in rule metadata
- [ ] Filename is lowercase, snake_case, matches threat
- [ ] `MAPPINGS.md` updated (for new rules)
- [ ] Category `README.md` updated (for new rules)
- [ ] `tests/validate.sh` passes locally (YARA rules)
- [ ] For Sigma: converts cleanly with at least one pySigma backend

## Testing

<!-- How did you test this? -->
<!-- If adding a Sigma rule, paste the output of `sigma convert` against your backend of choice -->

## Additional context

<!-- Anything else worth noting -->
