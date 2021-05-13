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
  source = "git::https://github.com/UKHomeOffice/acp-tf-lambda-es-reporter?ref=v0.1.1"

  function_name = "test-func"
  tag_selector_key = "KubernetesCluster"
  tag_selector_value = "test.testing.acp.homeoffice.gov.uk"
  period_minutes = "5"
  schedule_expression = "rate(5 minutes)"
  elasticsearch_hostname = "elasticsearch.testing.acp.homeoffice.gov.uk"
  elasticsearch_username = "lambda_read_only"
  elasticsearch_password_parameter_name = "ssh_notifier_elasticsearch_password"
  email_targets = ["willem.veerman@appvia.io"]
  vpc_id = "vpc-aaa"
  subnet_ids = ["subnet-aaa", "subnet-bbb", "subnet-ccc"]
  query_string = "syslog_identifier: sshd"
  index_pattern = "journald-*"
  tags = {
    "CreatedBy" = "willem.veerman@appvia.io"
  }
}
```