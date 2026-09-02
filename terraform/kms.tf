######################################################################
# Layer 1 - GRC baseline (Terraform): KMS
# Customer-managed key for PHI at rest.
# Closes GAP-01 (S3 uploads bucket) and GAP-02 (DynamoDB table).
#
# Explicit key policy (not the AWS default) because CloudTrail needs
# its own grant to use this key. The evidence bucket it writes to has
# SSE-KMS as its default encryption. EnableIAMUserPermissions preserves
# the same delegate-to-IAM behavior the default policy provides, so
# existing IAM-based grants (the Lambda role's kms:Decrypt /
# GenerateDataKey) keep working unchanged.
######################################################################

data "aws_iam_policy_document" "phi_key" {
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::890742589439:root"]
    }
  }

  statement {
    sid       = "AllowCloudTrailEncryptLogs"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:890742589439:trail/${local.name_prefix}-trail"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:890742589439:trail/${local.name_prefix}-trail"]
    }
  }

  statement {
    sid       = "AllowCloudTrailDescribeKey"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "phi" {
  description             = "Customer-managed key for Acme Health PHI at rest (S3 uploads + DynamoDB submissions)"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.phi_key.json
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi"
  target_key_id = aws_kms_key.phi.key_id
}
