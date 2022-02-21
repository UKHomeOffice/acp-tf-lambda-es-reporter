variable "function_name" {
  default     = "ssh-notifier"
  description = "Lambda function name and prefix in AWS resources"
}

variable "elasticsearch_password_parameter_name" {
  default     = "ssh_notifier_elasticsearch_password"
  description = "Systems Manager Parameter name for ES password"
}

variable "slack_password_parameter_name" {
  default     = "pod_exec_alert_slack_bot_password"
  description = "Systems Manager Parameter name for Slack password"
}

variable "elasticsearch_username" {
  description = "Elasticsearch username"
}

variable "elasticsearch_hostname" {
  description = "Elasticsearch hostname"
}

variable "tag_selector_key" {
  default     = ""
  description = "EC2 Tag Key to filter by"
}

variable "tag_selector_value" {
  default     = ""
  description = "EC2 Tag value to filter by"
}

variable "period_minutes" {
  default     = "5"
  description = "Time between executions in minutes"
}

variable "query_string" {
  description = "Elasticsearch Query"
}

variable "index_pattern" {
  description = "Elasticsearch index pattern for the query"
}

variable "timeout" {
  default     = 300
  description = "Amount of time the Lambda Function has to run in seconds."
}

variable "subnet_ids" {
  description = "Lambda subnet ids"
}

variable "vpc_id" {
  description = "Security group vpc id"
}

variable "email_targets" {
  type        = set(string)
  description = "Email addresses for SNS topic subscriptions to send alerts to"
}

variable "check_ec2" {
  type        = string
  description = "Lambda environment variable, string is casted to a boolean in python. This toggles whether to check if the event came from a node that matches tags var.tag_selector_key and var.tag_selector_value"
}

variable "period_event_threshold" {
  type        = number
  description = "Lambda environment variable, threshold of qualifying events that will trigger an alert"
}

variable "query_delay_minutes" {
  default     = 15
  description = "Lambda environment variable, this is the 'to' part of the ES query returning results up to this time"
}

variable "tags" {
  description = "AWS resource tags"
}

variable "slack_channel_id" {
  default     = ""
  description = "Slack channel id's used to alert the logs via the https://api.slack.com/methods/files.upload API "
}
