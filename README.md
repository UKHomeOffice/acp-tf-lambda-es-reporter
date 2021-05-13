# acp-tf-lambda-es-reporter

This lambda sends a configurable query to an elasticsearch cluster and then checks whether the results correspond to a particular set of ec2 instances.

It accomplishes this by checking each log message's 