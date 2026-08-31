# policies/gap07_iam_least_priv_aws.rego
# METADATA
# title: GAP-07 - Lambda IAM role must not grant wildcard actions on workload data
# description: "No statement in the Lambda's IAM policy document may use a wildcard action (e.g. dynamodb:* or s3:*) on the workload's data stores."
# custom:
#   control_id: 164.312(a)(1)
#   framework: hipaa-security-rule
#   severity: critical
#   gap: GAP-07
package compliance.gap07_iam_least_priv_aws

import rego.v1

deny contains msg if {
    some doc in input.configuration.root_module.resources
    doc.mode == "data"
    doc.type == "aws_iam_policy_document"
    some stmt in doc.expressions.statement
    stmt.effect.constant_value == "Allow"
    some action in stmt.actions.constant_value
    is_wildcard(action)
    msg := sprintf(
        "[GAP-07 / 164.312(a)(1)] data.aws_iam_policy_document.%s (sid: %s): wildcard action %q grants far more than the workload needs. Scope to the exact actions the code calls.",
        [doc.name, stmt.sid.constant_value, action],
    )
}

is_wildcard(action) if contains(action, "*")
