# policies/gap08_apigw_logging_aws.rego
# METADATA
# title: GAP-08 - API Gateway stage must have access logging enabled
# description: "aws_apigatewayv2_stage must have access_log_settings with a destination_arn referencing a real CloudWatch log group."
# custom:
#   control_id: 164.312(b)
#   framework: hipaa-security-rule
#   severity: medium
#   gap: GAP-08
package compliance.gap08_apigw_logging_aws

import rego.v1

deny contains msg if {
    some r in input.configuration.root_module.resources
    r.type == "aws_apigatewayv2_stage"
    not has_access_logging(r)
    msg := sprintf(
        "[GAP-08 / 164.312(b)] aws_apigatewayv2_stage.%s: no access_log_settings with a destination_arn. Add access_log_settings referencing an aws_cloudwatch_log_group.",
        [r.name],
    )
}

has_access_logging(r) if {
    some settings in r.expressions.access_log_settings
    count(settings.destination_arn.references) > 0
}
