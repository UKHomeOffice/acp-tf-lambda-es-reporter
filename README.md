# acp-tf-lambda-es-reporter

This lambda sends a configurable query to an elasticsearch cluster and then checks whether the results correspond to a particular set of ec2 instances.

It accomplishes this by checking each log message's `hostname` field against the set of EC2 instances returned by searching for all EC2 instances tagged with the Key:Value combination defined in the `tag_selector_key` and `tag_selector_value` parameters.

In other words, it returns all logs messages which correspond to the instances whose tags match `tag_selector_key`:`tag_selector_value` 

It contains two non-standard library packages - these have been vendored into the repo because they need to be included in the deployment package.

To update the dependencies, amend the `requirements.txt` file accordingly and then run

```
docker run -v $(pwd):/tmp/ python:3.9.2 pip3 install -r /tmp/lambda/requirements.txt --upgrade --target /tmp/lambda/
```

Example instantiation:

```
module "ssh_notifier_lambda" {
  source = "git::https://github.com/UKHomeOffice/acp-tf-lambda-es-reporter?ref=v0.1.3"

  function_name                         = "test-${var.environment}-ssh-notifier"
  check_ec2                             = "TRUE"
  period_event_threshold                = 1
  query_delay_minutes                   = 0
  tag_selector_key                      = "KubernetesCluster"
  tag_selector_value                    = "test.testing.acp.homeoffice.gov.uk"
  period_minutes                        = "5"
  elasticsearch_hostname                = "elasticsearch.testing.acp.homeoffice.gov.uk"
  elasticsearch_username                = "lambda_read_only"
  elasticsearch_password_parameter_name = "ssh_notifier_elasticsearch_password"
  slack_password_parameter_name         = "pod_exec_alert_slack_bot_password"
  email_targets                         = ["willem.veerman@appvia.io"]
  vpc_id                                = var.vpc_id
  subnet_ids                            = data.aws_subnet_ids.private.ids
  query_string                          = "syslog_identifier: sshd"
  index_pattern                         = "journald-acp-test-*"
  tags = {
    TYPE        = var.environment
    ENVIRONMENT = "test"
  }
}

```
