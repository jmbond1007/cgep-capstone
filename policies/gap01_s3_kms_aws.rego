# policies/gap01_s3_kms_aws.rego
# METADATA
# title: GAP-01 - S3 uploads bucket must use SSE-KMS with a customer-managed key
# description: "aws_s3_bucket_server_side_encryption_configuration must specify aws:kms and reference a customer-managed KMS key, not the AWS-managed default."
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: hipaa-security-rule
#   severity: high
#   gap: GAP-01
package compliance.gap01_s3_kms_aws

import rego.v1

deny contains msg if {
    bucket := bucket_addresses[_]
    not has_cmk_encryption(bucket)
    msg := sprintf(
        "[GAP-01 / 164.312(a)(2)(iv)] %s: missing SSE-KMS with a customer-managed key. Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = \"aws:kms\" and kms_master_key_id referencing a customer-managed aws_kms_key.",
        [bucket],
    )
}

bucket_addresses contains addr if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket"
    addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_cmk_encryption(bucket_addr) if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket_server_side_encryption_configuration"
    some ref in r.expressions.bucket.references
    references_bucket(ref, bucket_addr)
    some rule in r.expressions.rule
    some sse in rule.apply_server_side_encryption_by_default
    sse.sse_algorithm.constant_value == "aws:kms"
    count(sse.kms_master_key_id.references) > 0
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
