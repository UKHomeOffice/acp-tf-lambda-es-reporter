data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "/tmp/lambda_zip.zip"
  source_dir  = "${path.module}/lambda/"
}

data "aws_ssm_parameter" "elasticsearch_password" {
  name            = var.elasticsearch_password_parameter_name
  with_decryption = true
}

data "aws_ssm_parameter" "slack_password" {
  name            = var.slack_password_parameter_name
  with_decryption = true
}

resource "aws_lambda_function" "lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  function_name = var.function_name

  handler = "notifier.main"

  runtime = "python3.8"

  memory_size = 256

  role = aws_iam_role.lambda_role.arn

  timeout = var.timeout

  environment {
    variables = {
      AWS_ACCOUNT            = data.aws_caller_identity.current.account_id
      SNS_TOPIC_ARN          = aws_sns_topic.notifier_topic.arn
      ELASTICSEARCH_HOSTNAME = var.elasticsearch_hostname
      ELASTICSEARCH_USERNAME = var.elasticsearch_username
      ELASTICSEARCH_PASSWORD = data.aws_ssm_parameter.elasticsearch_password.value
      TAG_SELECTOR_KEY       = var.tag_selector_key
      TAG_SELECTOR_VALUE     = var.tag_selector_value
      PERIOD_MINUTES         = var.period_minutes
      QUERY_STRING           = var.query_string
      INDEX_PATTERN          = var.index_pattern
      CHECK_EC2              = var.check_ec2
      PERIOD_EVENT_THRESHOLD = var.period_event_threshold
      QUERY_DELAY_MINUTES    = var.query_delay_minutes
      SLACK_WEBHOOK          = var.slack_webhook
      SLACK_CHANNEL_NAME     = var.slack_channel_name
      SLACK_WEBHOOK_USERNAME = var.slack_webhook_username
      SLACK_BOT_TOKEN        = data.aws_ssm_parameter.slack_password.value
    } 
  }


  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

}

resource "aws_security_group" "lambda" {

  name_prefix = "${var.function_name}-lambda-sg"
  description = "${var.function_name} SG"
  vpc_id      = var.vpc_id

  tags = var.tags

}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

resource "aws_security_group_rule" "Egress_to_ES" {
  security_group_id = aws_security_group.lambda.id
  type              = "egress"
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
}
