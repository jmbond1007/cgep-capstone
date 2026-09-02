# policies/gap02_dynamodb_kms_aws.rego
# METADATA
# title: GAP-02 - DynamoDB submissions table must use a customer-managed KMS key
# description: "aws_dynamodb_table must have server_side_encryption enabled with kms_key_arn set, not left on the AWS-owned default key."
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: hipaa-security-rule
#   severity: high
#   gap: GAP-02
package compliance.gap02_dynamodb_kms_aws

import rego.v1

deny contains msg if {
    some r in input.configuration.root_module.resources
    r.type == "aws_dynamodb_table"
    not has_cmk_encryption(r)
    msg := sprintf(
        "[GAP-02 / 164.312(a)(2)(iv)] aws_dynamodb_table.%s: missing or incomplete server_side_encryption. Add server_side_encryption { enabled = true; kms_key_arn = <customer CMK arn> }.",
        [r.name],
    )
}

has_cmk_encryption(r) if {
    some sse in r.expressions.server_side_encryption
    sse.enabled.constant_value == true
    count(sse.kms_key_arn.references) > 0
}
