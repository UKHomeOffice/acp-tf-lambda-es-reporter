#!/usr/bin/env python
import boto3
import logging
from elasticsearch import Elasticsearch, Urllib3HttpConnection
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q
import operator

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

class Notifier:

    def __init__(self,
                 account,
                 sns_topic_prefix,
                 es_host,
                 es_user,
                 es_password,
                 tag_selector_value,
                 frequency='15m',
                 tag_selector_key='k8s.io/cluster-autoscaler/node-template/label/PROJECT-SERVICE',
                 region='eu-west-2'):

        self.region = region
        self.account = account
        self.sns_topic_prefix = sns_topic_prefix
        self.tag_selector_value = tag_selector_value
        self.frequency = frequency
        self.tag_selector_key = tag_selector_key

        self.es_client = Elasticsearch([es_host],
                                        connection_class=Urllib3HttpConnection,
                                        http_auth=(es_user, es_password),
                                        scheme="https",
                                        use_ssl=True,
                                        verify_certs=False,
                                        ssl_show_warn=False,
                                        port=443)

        self.session = boto3.Session(region_name=self.region)


    def get_logs(self):

        q = Q("multi_match", query='sshd', fields=['syslog_identifier'])

        s = Search(using=self.es_client, index="journald-*").query(q).\
            filter('range',
                   **{'@timestamp': {'gte': f"now-{self.frequency}", 'lt': 'now'}}).\
            sort('@timestamp')[0:200]

        response = s.execute(ignore_cache=True)

        logging.info(f"found {len(response)} events in elasticsearch")

        return response


    def get_instance_from_private_dns_name(self, private_dns_name, client):

        instance_response = client.describe_instances(DryRun=False,
                                                          Filters=[{
                                                              'Name': 'private-dns-name',
                                                              'Values': [private_dns_name]}])

        if not instance_response['Reservations']:
            logging.error(f"No corresponding ec2 was found for {private_dns_name}")
        else:
            tags_unpacked = {tag['Key']: tag['Value'] for tag in
                             instance_response['Reservations'][0]['Instances'][0]['Tags']}

            instance = dict(name=tags_unpacked['Name'],
                            id=instance_response['Reservations'][0]['Instances'][0]['InstanceId'],
                            az=instance_response['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone'],
                            launch_time=instance_response['Reservations'][0]['Instances'][0]['LaunchTime'],
                            hostname=instance_response['Reservations'][0]['Instances'][0]['PrivateDnsName'],
                            tags=tags_unpacked)

            logging.info("Found ec2 matching {private_dns_name}: {instance}".
                         format(private_dns_name=private_dns_name,
                                instance=' - '.join(f"{k} : {v}" for k,v in instance.items())))

            return instance


    def compare_instance_service_with_selector(self, instance):

        if self.tag_selector_key in instance['tags']:
            instance[self.tag_selector_key] = instance['tags'][self.tag_selector_key]
        else:
            logging.info(f"Skipping {instance['hostname']} because it has no {self.tag_selector_key} tag "
                         f"found keys: {instance['tags'].keys()}")
            return False

        logging.info(f"Found '{self.tag_selector_key}' tag value '{instance[self.tag_selector_key]}' applied to {instance['hostname']}")

        if instance[self.tag_selector_key] == self.tag_selector_value:
            logging.info(f"'{instance[self.tag_selector_key]}' tag applied to {instance['hostname']} matches "
                         f"chosen tag selector: '{self.tag_selector_value}'")
            return True
        else:
            logging.info(f"'{instance[self.tag_selector_key]}' tag applied to {instance['hostname']} does not match "
                         f"chosen tag selector: '{self.tag_selector_value}'")
            return False

    def parse_logs(self, response):

        ec2_client = self.session.client('ec2')

        project_service_events = []

        for log in response:
            if not log.message.startswith('rexec line 2: Deprecated option UsePrivilegeSeparation'):
                logging.info(f"Searching for instance with PrivateDnsName {log.hostname} - sshd message: {log.message}")
                instance = self.get_instance_from_private_dns_name(log.hostname, ec2_client)
                if not instance:
                    continue

                if self.compare_instance_service_with_selector(instance):
                    instance['log_message'] = log.message
                    instance['log_event_timestamp'] = getattr(log, '@timestamp')
                    project_service_events.append(instance)

        return project_service_events

    def format_notification(self, events):

        events.sort(key=operator.itemgetter('hostname', 'log_event_timestamp'))

        a = ''

        for event in events:
            for k,v in event.items():
                a = a + '\n'.join(f"{k} : {v}")
            a = a + '---\n'

        print(a)

        # string = """
        # The following SSH events were detected into EC2 instances tagged with the following Key : Value combination
        #
        # {key} : {value}
        # ---
        #
        # {events}
        # """.format(key=self.tag_selector_key,
        #            value=self.tag_selector_value,
        #            events='\n'.join(f"{k} : {v}" for e in events for k,v in e.items()))
        #
        # print(string)

        # def trigger_sns(self, events, topic_arn):
        #
        #     sns_client = boto3.client('sns')
        #
        #     sns_client.publish(TopicArn=topic_arn,
        #                        Subject='ACP Cloud Health Alert',
        #                        Message=event)









if __name__ == '__main__':
    n = Notifier(region='eu-west-2',
                 account='670930646103',
                 sns_topic_prefix='a',
                 es_host='https://elasticsearch.testing.acp.homeoffice.gov.uk',
                 es_user='elastic',
                 es_password='chang3m3',
                 tag_selector_value='test.testing.acp.homeoffice.gov.uk',
                 frequency='8h',
                 tag_selector_key='KubernetesCluster')

    a = n.get_logs()

    if a:
        b = n.parse_logs(a)
        print(b)

    n.format_notification(b)

    #
    # for i in a:
    #     print(i.message, getattr(i, '@timestamp'))

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
