resource "aws_iam_role" "lambda_role" {
  name               = "${var.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    principals {
      identifiers = ["lambda.amazonaws.com"]
      type        = "Service"
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy" "acp_health_notifier_role_policy" {
  name   = "${var.function_name}-role-policy"
  role   = aws_iam_role.lambda_role.id
  policy = data.aws_iam_policy_document.acp_health_notifier_policy_document.json
}

data "aws_iam_policy_document" "acp_health_notifier_policy_document" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}:*",
    ]
  }

  statement {
    actions = [
      "ec2:Describe*"
    ] 

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "sns:Publish"
    ] 

    resources = [
      "arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:aws-health_*",
    ]
  }

}
