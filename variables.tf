variable "function_name" {
  default = "ssh-notifier"
}

variable "elasticsearch_password_parameter_name" {
  default = "ssh_notifier_elasticsearch_password"
}

variable "slack_password_parameter_name" {
  default = "pod_exec_alert_slack_bot_password"
}

variable "elasticsearch_username" {

}

variable "elasticsearch_hostname" {

}

variable "tag_selector_key" {
  default = ""
}

variable "tag_selector_value" {
  default = ""
}

variable "period_minutes" {
  default = "5"
}

variable "query_string" {

}

variable "index_pattern" {

}

variable "timeout" {
  default = 300
}

variable "subnet_ids" {

}

variable "vpc_id" {

}

variable "email_targets" {
  type = set(string)
}

variable "check_ec2" {
  type = string
}

variable "period_event_threshold" {
  type = number
}

variable query_delay_minutes {
  default = 15
}

variable "tags" {
  
}

variable "slack_channel_name" {
  default = ""
}