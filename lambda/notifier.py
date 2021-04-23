#!/usr/bin/env python
import boto3
import logging
from elasticsearch import Elasticsearch, Urllib3HttpConnection
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q
import operator
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

class Notifier:

    def __init__(self,
                 account,
                 sns_topic_arn,
                 es_host,
                 es_user,
                 es_password,
                 tag_selector_value,
                 frequency,
                 tag_selector_key,
                 region):

        self.es_host = es_host
        self.region = region
        self.account = account
        self.sns_topic_arn = sns_topic_arn
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
            sort('@timestamp')[0:10000]

        logging.info(f"Searching {self.es_host} from now-{self.frequency} to now for ssh events")

        response = s.execute(ignore_cache=True)

        logging.info(f"Found {len(response)} shh events in {self.es_host}")

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
                            private_ip=instance_response['Reservations'][0]['Instances'][0]['PrivateIpAddress'],
                            subnet=instance_response['Reservations'][0]['Instances'][0]['SubnetId'],
                            launch_time=instance_response['Reservations'][0]['Instances'][0]['LaunchTime'],
                            hostname=instance_response['Reservations'][0]['Instances'][0]['PrivateDnsName'],
                            tags=tags_unpacked)

            logging.info("Found ec2 matching {private_dns_name}: {instance}".
                         format(private_dns_name=private_dns_name,
                                instance=' - '.join(f"{k} : {v}" for k,v in instance.items())))

            return instance


    def compare_instance_service_with_selector(self, instance):

        logging.info(f"Checking instance {instance['hostname']} for chosen tag selector - "
                     f"{self.tag_selector_key}:{self.tag_selector_value}")

        if self.tag_selector_key in instance['tags']:
            instance[self.tag_selector_key] = instance['tags'][self.tag_selector_key]
        else:
            logging.info(f"Skipping {instance['hostname']} because it has no {self.tag_selector_key} tag key")
            return False

        logging.info(f"Instance {instance['hostname']} labelled with tag key '{self.tag_selector_key}' and value "
                     f"'{instance[self.tag_selector_key]}'")

        if instance[self.tag_selector_key] == self.tag_selector_value:
            logging.info(f"Instance {instance['hostname']} tag:key "
                         f"'{self.tag_selector_key}':'{instance[self.tag_selector_key]}' "
                         f"matches chosen selector")
            return True
        else:
            logging.info(f"Instance {instance['hostname']} tag:key '{self.tag_selector_key}':'{instance[self.tag_selector_key]}' "
                         f"does not match chosen tag selector")
            return False

    def parse_logs(self, response):

        logging.info(f"Checking each ssh event's node name against AWS API to obtain instance tags")

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

    def format_events(self, events):

        events.sort(key=operator.itemgetter('hostname', 'log_event_timestamp'))

        logging.info(f"Found {len(events)} qualifying events")

        for event in events:
            logging.info(f"Found qualifying event: {event}")

        events_formatted = []

        for event in events:
            formatted = '----\n'+'\n'.join(f"{k}: {v}" for k,v in event.items())+'\n'
            events_formatted.append(formatted)

        return events_formatted


    def prepare_messages(self, events_formatted):

        header_string = f"""
The following SSH events logged in {self.es_host} were detected from EC2 instances tagged with the following Key : Value combination

{self.tag_selector_key} : {self.tag_selector_value}

"""
        message_array = []
        message_string = header_string
        for event in events_formatted:
            #  SNS messages must be under 256KB, or 262,144 bytes
            if len(message_string.encode('utf-8')) + len(event.encode('utf-8')) <= 262144:
                message_string = message_string + event
            else:
                message_array.append(message_string)
                message_string = header_string
                continue

        message_array.append(message_string)

        logging.info(f"{len(events_formatted)} events split into {len(message_array)} SNS messages: "
                     f"{[str(len(m.encode('utf-8')))+' bytes' for m in message_array]}")

        return message_array

    def trigger_sns(self, messages, topic_arn):

        sns_client = self.session.client('sns')

        for index,message in enumerate(messages):
            logging.info(f"Publishing message {index+1} of {len(messages)} - {len(message.encode('utf-8'))} bytes")
            sns_client.publish(TopicArn=topic_arn,
                               Subject='ACP Node SSH Alert',
                               Message=message)


def main(event):

    notifier = Notifier(region=os.environ['AWS_REGION'],
                        account=os.environ['AWS_ACCOUNT'],
                        sns_topic_arn=os.environ['SNS_TOPIC_ARN'],
                        es_host=os.environ['ELASTICSEARCH_HOSTNAME'],
                        es_user=os.environ['ELASTICSEARCH_USERNAME'],
                        es_password=os.environ['ELASTICSEARCH_PASSWORD'],
                        tag_selector_key=os.environ['TAG_SELECTOR_KEY'],
                        tag_selector_value=os.environ['TAG_SELECTOR_VALUE'],
                        frequency=os.environ['FREQUENCY'])

    ssh_event_logs = notifier.get_logs()

    parsed_logs = notifier.parse_logs(ssh_event_logs)

    formatted_events = notifier.format_events(parsed_logs)

    message_array = notifier.prepare_messages(formatted_events)

    notifier.trigger_sns(message_array, notifier.sns_topic_arn)
