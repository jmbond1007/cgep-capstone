# policies/gap04_s3_versioning_aws.rego
# METADATA
# title: GAP-04 - S3 uploads bucket must have versioning enabled
# description: "Every aws_s3_bucket must have a matching aws_s3_bucket_versioning resource with status set to Enabled, so PHI overwrites are recoverable."
# custom:
#   control_id: 164.308(a)(7)
#   framework: hipaa-security-rule
#   severity: medium
#   gap: GAP-04
package compliance.gap04_s3_versioning_aws

import rego.v1

deny contains msg if {
    bucket := bucket_addresses[_]
    not has_versioning_enabled(bucket)
    msg := sprintf(
        "[GAP-04 / 164.308(a)(7)] %s: no aws_s3_bucket_versioning with status = \"Enabled\". PHI overwrites would be unrecoverable.",
        [bucket],
    )
}

bucket_addresses contains addr if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket"
    addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_versioning_enabled(bucket_addr) if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket_versioning"
    some ref in r.expressions.bucket.references
    references_bucket(ref, bucket_addr)
    some vc in r.expressions.versioning_configuration
    vc.status.constant_value == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
