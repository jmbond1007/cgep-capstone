######################################################################
# Layer 1 - GRC baseline (Terraform): GitHub OIDC trust
# Lets the grc-gate.yml pipeline authenticate to AWS without a stored
# access key. Reuses the GitHub OIDC provider already registered in
# this account (Lab 4.3). AWS allows only one identity provider per
# issuer URL per account.
######################################################################

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # StringLike + wildcarded IDs, not an exact repo:org/repo:* match.
    # GitHub's sub claim embeds numeric account/repo IDs
    # (repo:org@<id>/repo@<id>:event). Lesson from Lab 4.3/5.2.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:jmbond1007@*/cgep-capstone@*:*"]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  name               = "${local.name_prefix}-github-actions"
  assume_role_policy = data.aws_iam_policy_document.github_actions_trust.json
}

data "aws_iam_policy_document" "github_actions_permissions" {
  # Broad within the specific services this stack uses, not
  # account-wide admin. See WRITEUP.md for the least-privilege
  # trade-off this represents.
  statement {
    sid    = "WorkloadServices"
    effect = "Allow"
    actions = [
      "ec2:*", "s3:*", "dynamodb:*", "lambda:*",
      "apigateway:*", "kms:*", "cloudtrail:*", "logs:*",
    ]
    resources = ["*"]
  }

  # IAM stays tightly scoped: only roles matching this stack's naming
  # convention, same pattern as the jmbond-cli bootstrap grant.
  statement {
    sid    = "ScopedIamRoleLifecycle"
    effect = "Allow"
    actions = [
      "iam:CreateRole", "iam:GetRole", "iam:DeleteRole",
      "iam:TagRole", "iam:UntagRole", "iam:PassRole",
      "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy",
      "iam:ListRolePolicies", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole",
    ]
    resources = ["arn:aws:iam::890742589439:role/acme-health-intake-*"]
  }

  statement {
    sid       = "ReadOidcProvider"
    effect    = "Allow"
    actions   = ["iam:GetOpenIDConnectProvider"]
    resources = [data.aws_iam_openid_connect_provider.github.arn]
  }

  # Looking up the provider by URL (the data source above) needs the
  # list action too, not just Get. AWS scopes List to the
  # oidc-provider/* resource pattern, not a specific provider ARN.
  statement {
    sid       = "ListOidcProviders"
    effect    = "Allow"
    actions   = ["iam:ListOpenIDConnectProviders"]
    resources = ["arn:aws:iam::890742589439:oidc-provider/*"]
  }

  statement {
    sid       = "ApiGatewayAccountSettings"
    effect    = "Allow"
    actions   = ["apigateway:PATCH", "apigateway:GET"]
    resources = ["arn:aws:apigateway:us-east-1::/account"]
  }
}

resource "aws_iam_role_policy" "github_actions" {
  name   = "grc-pipeline-permissions"
  role   = aws_iam_role.github_actions.id
  policy = data.aws_iam_policy_document.github_actions_permissions.json
}
