#!/usr/bin/env python
import boto3
import logging
from elasticsearch import Elasticsearch, Urllib3HttpConnection
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class Notifier:

    def __init__(self,
                 region,
                 account,
                 sns_topic_prefix,
                 es_host,
                 es_user,
                 es_password):
        self.region = region
        self.account = account
        self.sns_topic_prefix = sns_topic_prefix

        self.es_client = Elasticsearch([es_host],
                                  connection_class=Urllib3HttpConnection,
                           http_auth=(es_user, es_password),
                           scheme="https",
                           use_ssl=True,
                           verify_certs=False,
                           ssl_show_warn=False,
                           port=443)

        self.session = boto3.Session(region_name=self.region)



    def get_events(self):


        q = Q("multi_match", query='sshd', fields=['syslog_identifier'])

        s = Search(using=self.es_client, index="journald-*").query(q).\
            filter('range',
                   **{'@timestamp': {'gte': '2021-04-17T13:00:00', 'lt': '2021-04-19T16:00:00'}}).\
            sort('-@timestamp')[0:100]

        response = s.execute(ignore_cache=True)

        return response


    def parse_events(self, response):

        ec2_client = self.session.client('ec2')

        for message in response:
            if not message.mesage.startswith('rexec line 2: Deprecated option UsePrivilegeSeparation'):
                instance = ec2_client.describe_instances(DryRun=False,
                                                         Filters=[{
                                                             'Name': 'private-dns-name',
                                                             'Values': [message.hostname]
                                                         }])
                try:
                    tags = instance['Reservations'][0]['Instances'][0]['Tags']
                except IndexError:
                    logging.error(f"ssh event found for {message.hostname} but no corresponding ec2 was found")
                    continue

                for tag in tags:
                    if tag['Key'] == 'COST-CODE':









if __name__ == '__main__':
    n = Notifier(region='eu-west-2',
                 account='670930646103',
                 sns_topic_prefix='a',
                 es_host='https://elasticsearch.testing.acp.homeoffice.gov.uk',
                 es_user='elastic',
                 es_password='chang3m3')

    a = n.get_events()

    for i in a:
        print(i.message, getattr(i, '@timestamp'))

# def main(event):
#
#     notifier = Notifier(region=os.environ['AWS_REGION'],
#                         account=os.environ['AWS_ACCOUNT'],
#                         sns_topic_prefix=os.environ['SNS_TOPIC_PREFIX'],
#                         es_host=os.environ['ELASTICSEARCH_HOSTNAME'],
#                         es_user=os.environ['ELASTICSEARCH_USERNAME'],
#                         es_password=os.environ['ELASTICSEARCH_PASSWORD'])
#
#     notifier.process_event(event)
