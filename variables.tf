variable "function_name" {
  default = "ssh-notifier"
}

variable "schedule_expression" {
  default = "rate(5 minutes)"
}

variable "elasticsearch_password_parameter_name" {
  default = "ssh_notifier_elasticsearch_password"
}

variable "elasticsearch_username" {

}

variable "elasticsearch_hostname" {

}

variable "tag_selector_key" {
  default = "k8s.io/cluster-autoscaler/node-template/label/PROJECT-SERVICE"
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

variable "should_check_ec2s" {
  default = "TRUE"
}

variable "period_event_threshold" {
  default = "1"
}

variable "tags" {
  
}
