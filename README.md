# Acme Health capstone: GRC-governed Patient Intake API

This repository is a fork of [GRCEngClub/cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter), wrapped with a Terraform baseline, a Rego policy suite, a signed GitHub Actions evidence pipeline, and an OSCAL component definition, all built against the HIPAA Security Rule as the declared primary framework. Full reasoning, control coverage, and trade-offs are in [WRITEUP.md](WRITEUP.md).

## Verification steps for graders

1. **Confirm the fork relationship.** This repository shows "forked from GRCEngClub/cgep-app-starter" on its GitHub page, and the starter's original workload (`terraform/main.tf`, `lambda/handler.py`, `test/intake.sh`) is unchanged in shape, only hardened.

2. **Confirm both required pull requests.**
   - [PR #1](https://github.com/jmbond1007/cgep-capstone/pull/1): merged, passed the policy gate, triggered a real apply on merge.
   - [PR #2](https://github.com/jmbond1007/cgep-capstone/pull/2): intentionally reintroduces GAP-07 (wildcard IAM actions), fails policy-check, and remains open and unmerged by design.

3. **Verify a signed evidence bundle directly.** From the repository root, with the AWS CLI configured against this account:
```bash
   ./scripts/verify-evidence.sh 33582393841 --vault acme-health-intake-evidence-7bf64b40
```
   Expected output ends with `CHAIN INTACT`. This checks the SHA-256 hash, the Cosign signature against the public Sigstore log, and Object Lock retention, all independently of anything this repository claims.

4. **Run the policy test suite.**
```bash
   conftest verify --policy policies
```
   Expected: 20 tests passing, covering all 7 closed gaps.

5. **Validate the OSCAL files.** Requires `compliance-trestle`.
```bash
   mkdir -p .trestle-work && cd .trestle-work && trestle init
   trestle import -f ../oscal/catalogs/hipaa-security-rule.json -o hipaa-security-rule
   trestle import -f ../oscal/profiles/cge-p-minimum.json -o cge-p-minimum
   trestle import -f ../oscal/components/acme-health-intake.json -o acme-health-intake
   trestle validate -t catalog -n hipaa-security-rule
   trestle validate -t profile -n cge-p-minimum
   trestle validate -t component-definition -n acme-health-intake
```
   Expected: `VALID` for all three.

6. **Confirm the live application still works**, if desired.
```bash
   make test AWS_PROFILE=<your-profile>
```
   Expected: `{"submission_id": "...", "status": "received"}`.

## Repository layout

```
cgep-capstone/
├── terraform/
│   ├── main.tf, variables.tf, outputs.tf, lambda/    (starter's original workload)
│   ├── kms.tf                  customer-managed key, rotation enabled
│   ├── hardening.tf            gap-closing overrides (GAP-01, 03, 04, 05, 08)
│   ├── evidence-vault.tf       Object Lock evidence bucket
│   ├── cloudtrail.tf           multi-region audit trail
│   ├── oidc-trust.tf           GitHub OpenID Connect role for the pipeline
│   └── state-backend.tf        remote state bucket
├── policies/
│   ├── gap0{1,2,3,4,5,7,8}_*.rego     one policy per closed gap
│   └── tests/*_test.rego              passing and failing fixtures
├── scripts/
│   ├── policy-gate.sh          runs Conftest across all 7 gap namespaces
│   ├── capture-evidence.sh     builds the evidence bundle
│   └── verify-evidence.sh      the check graders run, above
├── .github/workflows/grc-gate.yml     plan, policy-check, apply-on-merge, sign, upload
├── oscal/
│   ├── catalogs/hipaa-security-rule.json    self-authored, no official one exists
│   ├── profiles/cge-p-minimum.json
│   └── components/acme-health-intake.json
├── WRITEUP.md                  design reasoning, control coverage, trade-offs
└── GAPS.md, FRAMEWORKS.md, WORKLOAD.md    original starter documentation
```

## Attribution

MIT licensed, per the original starter. Forked freely. This submission is my own work.
