# policies/gap03_s3_tls_aws.rego
# METADATA
# title: GAP-03 - S3 uploads bucket must deny non-TLS requests
# description: "An aws_s3_bucket_policy attached to the bucket must reference an aws_iam_policy_document containing a Deny statement conditioned on aws:SecureTransport == false."
# custom:
#   control_id: 164.312(e)(1)
#   framework: hipaa-security-rule
#   severity: high
#   gap: GAP-03
package compliance.gap03_s3_tls_aws

import rego.v1

deny contains msg if {
    bucket := bucket_addresses[_]
    not has_tls_deny_policy(bucket)
    msg := sprintf(
        "[GAP-03 / 164.312(e)(1)] %s: no attached bucket policy denies non-TLS requests. Add an aws_s3_bucket_policy referencing a policy document with a Deny statement on aws:SecureTransport == false.",
        [bucket],
    )
}

bucket_addresses contains addr if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket"
    addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_tls_deny_policy(bucket_addr) if {
    some bp in input.configuration.root_module.resources
    bp.type == "aws_s3_bucket_policy"
    some ref in bp.expressions.bucket.references
    references_bucket(ref, bucket_addr)

    some policy_ref in bp.expressions.policy.references
    doc_name := data_doc_name(policy_ref)

    some doc in input.configuration.root_module.resources
    doc.mode == "data"
    doc.type == "aws_iam_policy_document"
    doc.name == doc_name

    some stmt in doc.expressions.statement
    stmt.effect.constant_value == "Deny"
    some cond in stmt.condition
    cond.variable.constant_value == "aws:SecureTransport"
    "false" in cond.values.constant_value
    some res_ref in stmt.resources.references
    contains(res_ref, bucket_addr)
}

data_doc_name(ref) := parts[2] if {
    parts := split(ref, ".")
    count(parts) >= 3
    parts[0] == "data"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
