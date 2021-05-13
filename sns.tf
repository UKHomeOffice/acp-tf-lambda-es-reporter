resource "aws_sns_topic" "notifier_topic" {

  name = var.function_name
}

resource "aws_sns_topic_subscription" "notifier_subscription" {

  for_each = var.email_targets

  topic_arn = aws_sns_topic.notifier_topic.arn
  protocol  = "email"
  endpoint  = each.value
}
