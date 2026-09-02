# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

HIPAA Security Rule. Acme Health is a telehealth company, and the Patient Intake API handles real patient submissions end to end (name, intake fields, optional file attachments), making it electronic protected health information by definition, not an edge case requiring interpretation. The Security Rule's technical and administrative safeguards map directly onto the work this capstone actually does: encryption at rest and in transit, access control, audit logging, and contingency planning are the same categories as the 7 gaps closed here. Of the three candidate frameworks, HIPAA required no analogy stretching to justify. SOC 2 or CMMC would have worked too, but each would have needed more argument to connect to this specific system.

## Control coverage

No official public OSCAL catalog exists for the HIPAA Security Rule. NIST publishes one for 800-53, but not HIPAA, confirmed by search before building anything. `oscal/catalogs/hipaa-security-rule.json` is self-authored from the actual regulatory text at 45 CFR Part 164 Subpart C, containing only the 5 controls below.

| Gap | Description | HIPAA Control | Terraform | Policy |
|---|---|---|---|---|
| GAP-01 | S3 uploads bucket: default encryption changed from an AWS-managed key to a customer-managed key | 164.312(a)(2)(iv) | `hardening.tf` | `gap01_s3_kms_aws.rego` |
| GAP-02 | DynamoDB table: default encryption changed from an AWS-owned key to a customer-managed key | 164.312(a)(2)(iv) | `main.tf` (edit) | `gap02_dynamodb_kms_aws.rego` |
| GAP-03 | S3 bucket policy denying non-TLS requests | 164.312(e)(1) | `hardening.tf` | `gap03_s3_tls_aws.rego` |
| GAP-04 | S3 versioning enabled | 164.308(a)(7) | `hardening.tf` | `gap04_s3_versioning_aws.rego` |
| GAP-05 | Lambda moved into the starter's existing private subnets, reachable via VPC gateway endpoints | 164.312(e)(1) | `main.tf` and `hardening.tf` | `gap05_lambda_vpc_aws.rego` |
| GAP-06 | No reserved concurrency, dead-letter queue, or X-Ray tracing | (no HIPAA citation in GAPS.md, only SOC 2 and CMMC) | Not closed | Not enforced |
| GAP-07 | Lambda IAM policy narrowed from `dynamodb:*` and `s3:*` to the exact actions `handler.py` calls | 164.312(a)(1) | `main.tf` (refactored to a `data.aws_iam_policy_document`) | `gap07_iam_least_priv_aws.rego` |
| GAP-08 | API Gateway access logging to CloudWatch | 164.312(b) | `main.tf` and `hardening.tf` (account-level prerequisite) | `gap08_apigw_logging_aws.rego` |

GAP-06 is the only gap left open. GAPS.md cites it only against SOC 2 and CMMC, not HIPAA, so it falls outside this capstone's declared scope. Every other gap is closed in both Terraform, the actual fix, and Rego, the regression guard, not one or the other. See design decisions below for why.

## Design decisions

**AWS region:** us-east-1, matching the starter's default. No data residency requirement in this scenario, so consistency was the only real consideration.

**Object Lock mode: COMPLIANCE.** Chosen over GOVERNANCE because it is the stronger chain of custody claim: nobody, not even the account root, can delete evidence before the retention period expires. The cost is losing the ability to manually clean up early, an acceptable trade for a project where the vault did not need mid-project cleanup. Retention is set to 6 years, matching HIPAA's own documentation retention rule (45 CFR 164.316(b)(2)(i)), not an arbitrary number.

**Apply on merge, not a manual gate.** Matches the brief's own philosophy of governance as automated checks rather than meetings, and the policy gate runs before apply regardless, so a real regression (proven with PR #2) never reaches infrastructure even with automatic apply. The trade-off is real: the pipeline holds genuine deploy power. The mitigation is that the gate has to pass first, every time, with no bypass path.

**Single AWS account**, not a separate evidence vault account. Acceptable per the brief for a 30 day project. The honest trade-off: in this design, an account level compromise could theoretically reach both the workload and its own evidence. A separate account would remove that shared exposure. This is the first thing I would change with more time, not something I overlooked.

**Every gap closed in both Terraform and policy**, not split between the two. The brief allows leaving some gaps as policy-only guards, but the brief also says explicitly it will run the policies against a copy of the starter with one fixed gap reintroduced and confirm the gate fires. Proving that requires an actual fix to revert. PR #2 demonstrates exactly this for GAP-07: `main.tf` was deliberately reverted to the original wildcard IAM actions, and policy-check caught it and blocked the merge.

## How the pipeline produces evidence

Traced end to end, PR #1 (the green PR, run ID 33582393841):

1. PR opened against main. `grc-gate.yml` triggers on the pull request event.
2. plan: Terraform reads state from the S3 backend, recognizes all existing infrastructure, and plans only genuine changes.
3. policy-check: `scripts/policy-gate.sh` runs Conftest against all 7 gap namespaces. All pass.
4. apply-on-merge: skipped on the pull request event. This is correct, since this step only runs on a push to main.
5. sign: `scripts/capture-evidence.sh --no-upload` builds the bundle (plan.json, state.json, commit metadata, manifest.json with a SHA-256 hash per file), and Cosign signs it keylessly through GitHub's OpenID Connect identity provider.
6. upload: the bundle, its SHA-256 file, its signature bundle, and a receipt file land in `s3://acme-health-intake-evidence-7bf64b40/runs/33582393841/`.

On merge, a second run triggered by the push event repeated the same chain. This time apply-on-merge actually executed, with zero resources to add or change, since local state already matched what the pipeline planned.

Independently verified with `scripts/verify-evidence.sh 33582393841 --vault acme-health-intake-evidence-7bf64b40`: the SHA-256 hash recomputed and matched, the Cosign signature verified against the public Sigstore log, and Object Lock retention was confirmed active. Output: chain intact.

PR #2 (the red PR, run ID 33582881786) is the negative control: `main.tf` was deliberately reverted to `dynamodb:*` and `s3:*`. The same chain ran. Policy-check failed, naming the exact wildcard actions and citing 164.312(a)(1). Apply-on-merge correctly never ran. Sign and upload still ran, since those steps are set to run regardless of outcome, so even a blocked pull request has a recorded, signed audit trail of the attempt. This pull request remains open and unmerged by design.

## Trade-offs and what I would do with another sprint

- The GitHub Actions pipeline role's permissions are broad within the specific services this stack uses (full access to EC2, S3, DynamoDB, and so on), not fully scoped to least privilege, while identity and access management permissions themselves stay tightly limited to this stack's role naming pattern. Enumerating every exact action across every service this pipeline touches risked missing one and hitting an opaque access-denied error mid-apply in the automated pipeline, a failure mode this project ran into twice already for other reasons. With more time, I would scope this the same way GAP-07 scopes the Lambda's own policy: exact actions per resource type.
- Remote state was entirely missing from both the brief and the companion guide, confirmed by rereading both in full. It is a real, unstated gap between week two ("apply locally by hand") and layer three ("apply on merge in continuous integration"). Nothing bridges the two. Discovered when the pipeline's first real plan tried to rebuild all 43 resources from scratch against a stack that already existed. Fixed with a dedicated S3 bucket for state and native lock file locking, but a production version of this course might flag the gap explicitly.
- The self-authored HIPAA catalog is grounded in real regulatory text, verified against the electronic Code of Federal Regulations before drafting, but a second reviewer cross-checking each citation, or cross-referencing NIST Special Publication 800-66's mapping from HIPAA to 800-53, would strengthen its credibility further.
- CloudTrail initially failed to deploy because the evidence vault's own default encryption blocked CloudTrail's service principal from using the encryption key. This is a real instance of encrypting everything by default creating friction with AWS's own audit tooling. Fixed with an explicit, narrowly scoped key policy grant rather than a fully open one.
- With another sprint: a separate evidence vault AWS account (the single account trade-off above), tighter scoping of the pipeline role's permissions, a second framework mapping (SOC 2 or CMMC) reusing the same Terraform baseline to demonstrate multi-framework readiness, and automated OSCAL evidence links instead of the current manual per-run capture.

## Known limitations

GAP-06 covers reserved concurrency, a dead-letter queue, and X-Ray tracing on the Lambda function. I left it closed because GAPS.md only cites it under SOC 2 and CMMC, not HIPAA, so it fell outside what this capstone actually declared. If I add a second framework later, this would be a quick addition rather than new work.

The links in the OSCAL component definition point to one specific pipeline run that I checked and verified by hand. They do not update automatically each time the pipeline runs, so right now they are a snapshot of one proven run rather than something that stays current on its own.

I only mapped this system against HIPAA. The same Terraform baseline likely satisfies a good number of overlapping SOC 2 and CMMC controls as well, but I did not take the time to work out that mapping here.

The Lambda function stores the fields object from each patient submission without validating its contents. This is not one of the eight named gaps, so it was out of scope for this capstone, but I noticed it while reading through the code and wanted to name it rather than leave it quietly unmentioned.

The lab's own version of this pipeline includes a tfsec scan. I left it out on purpose, since the brief calls for exactly five named steps, plan, policy check, apply, sign, and upload, and adding a sixth step that is not in the brief felt like scope creep rather than a genuine improvement.
