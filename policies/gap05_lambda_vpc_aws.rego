# policies/gap05_lambda_vpc_aws.rego
# METADATA
# title: GAP-05 - Intake Lambda must run inside the private subnets with a security group
# description: "aws_lambda_function must have a vpc_config block whose subnet_ids reference the private subnets (not public), with at least one security group attached."
# custom:
#   control_id: 164.312(e)(1)
#   framework: hipaa-security-rule
#   severity: high
#   gap: GAP-05
package compliance.gap05_lambda_vpc_aws

import rego.v1

deny contains msg if {
    some r in input.configuration.root_module.resources
    r.type == "aws_lambda_function"
    not has_private_vpc_config(r)
    msg := sprintf(
        "[GAP-05 / 164.312(e)(1)] aws_lambda_function.%s: not deployed in the private subnets with a security group. Add vpc_config with subnet_ids referencing aws_subnet.private and a security_group_ids entry.",
        [r.name],
    )
}

has_private_vpc_config(r) if {
    some vc in r.expressions.vpc_config
    some subnet_ref in vc.subnet_ids.references
    contains(subnet_ref, "aws_subnet.private")
    count(vc.security_group_ids.references) > 0
}
