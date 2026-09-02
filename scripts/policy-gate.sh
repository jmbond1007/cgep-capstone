#!/usr/bin/env bash
# scripts/policy-gate.sh
# Usage: policy-gate.sh --workspace <path> [--policy <dir>]
# Requires a saved tfplan inside the workspace (from terraform plan -out=tfplan).
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/grc-gate"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

# Write plan.json next to tfplan. Use -chdir so a relative WORKSPACE path
# doesn't get doubled after a cd (a common bash footgun).
terraform -chdir="$WORKSPACE" show -json tfplan > "$WORKSPACE/plan.json"

EXIT=0
{
  echo "["
  FIRST=1
  # Acme Health capstone: one namespace per closed gap (GAPS.md). GAP-06 is
  # excluded, it has no HIPAA control citation, only SOC 2/CMMC.
  for ns in \
    compliance.gap01_s3_kms_aws \
    compliance.gap02_dynamodb_kms_aws \
    compliance.gap03_s3_tls_aws \
    compliance.gap04_s3_versioning_aws \
    compliance.gap05_lambda_vpc_aws \
    compliance.gap07_iam_least_priv_aws \
    compliance.gap08_apigw_logging_aws \
  ; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    set +e
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json")
    STATUS=$?
    set -e
    [[ $STATUS -eq 0 ]] || EXIT=1
    printf '%s' "$OUT"
  done
  echo
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $EXIT
