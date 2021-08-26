#!/usr/bin/env python
import boto3
from botocore.exceptions import ClientError
import logging
import datetime as dt
from elasticsearch import Elasticsearch, Urllib3HttpConnection
from elasticsearch.exceptions import ConnectionError as ElasticConnectionError, ElasticsearchException
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q
from elasticsearch_dsl.utils import AttrDict
import operator
import os
import socket
import urllib3
from urllib3.exceptions import HTTPError
import json
import requests

http = urllib3.PoolManager()

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
                 period_minutes,
                 tag_selector_key,
                 region,
                 query_string,
                 index_pattern,
                 check_ec2,
                 period_event_threshold,
                 query_delay_minutes,
                 slack_password,
                 slack_channel_name):

        self.es_host = es_host
        self.region = region
        self.account = account
        self.sns_topic_arn = sns_topic_arn
        self.tag_selector_value = tag_selector_value
        self.period_minutes = period_minutes
        self.tag_selector_key = tag_selector_key
        self.query_string = query_string
        self.index_pattern = index_pattern
        self.check_ec2 = (check_ec2 == 'TRUE')
        self.period_event_threshold = int(period_event_threshold)
        self.query_delay_minutes = int(query_delay_minutes)
        self.slack_password = slack_password
        self.slack_channel_name = slack_channel_name


        self.es_client = Elasticsearch([es_host],
                                        connection_class=Urllib3HttpConnection,
                                        http_auth=(es_user, es_password),
                                        scheme="https",
                                        use_ssl=True,
                                        verify_certs=False,
                                        ssl_show_warn=False,
                                        port=443,
                                        timeout=10,
                                        max_retries=2)

        self.session = boto3.Session(region_name=self.region)

        self.ssm_client = self.session.client('ssm')

        self.current_timestamp = (dt.datetime.utcnow() - dt.timedelta(minutes=self.query_delay_minutes)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        self.previous_timestamp = self.get_past_timestamp(self.ssm_client)

        self.header = f"""
The notifier lambda with the following parameters

ES host: {self.es_host}
Account: {self.account}
Region: {self.region}
Lambda Name: {os.getenv('AWS_LAMBDA_FUNCTION_NAME')}
Query: '{self.query_string}'
Query UTC Time Window: {self.previous_timestamp}  ->  {self.current_timestamp}
Query Delay Minutes: {self.query_delay_minutes}
Index pattern: '{self.index_pattern}'
Event Threshold Trigger Count: {self.period_event_threshold}
Cross-Check Events Against EC2 Toggle: {self.check_ec2}
EC2 Key, Value tag selector: '{self.tag_selector_key}' : '{self.tag_selector_value}'
Slack Channel Name: '{self.slack_channel_name}'



"""

    def get_past_timestamp(self, ssm_client):

        try:
            past_timestamp = ssm_client.get_parameter(Name=f"{os.getenv('AWS_LAMBDA_FUNCTION_NAME')}_timestamp")['Parameter']['Value']
        except ClientError as e:
            now = dt.datetime.utcnow() - dt.timedelta(minutes=int(self.period_minutes) + int(self.query_delay_minutes))
            past_timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            if e.response['Error']['Code'] == 'ParameterNotFound':
                logging.error(f"Parameter {os.getenv('AWS_LAMBDA_FUNCTION_NAME')}_timestamp not found in {self.account}"
                              f"setting past_timestamp to current time minus period = {past_timestamp}")
            else:
                logging.error(f"ClientError: {e.response['Error']} - "
                              f"setting past_timestamp to current time minus period = {past_timestamp}")

        return past_timestamp

    def put_current_timestamp(self, ssm_client, timestamp):

        ssm_client.put_parameter(Name=f"{os.getenv('AWS_LAMBDA_FUNCTION_NAME')}_timestamp",
                                 Value=timestamp,
                                 Type='String',
                                 Overwrite=True)

        ssm_client.add_tags_to_resource(ResourceType='Parameter',
                                        ResourceId=f"{os.getenv('AWS_LAMBDA_FUNCTION_NAME')}_timestamp",
                                        Tags=[
                                            {
                                                'Key': 'AWS_LAMBDA_FUNCTION_NAME',
                                                'Value': os.getenv('AWS_LAMBDA_FUNCTION_NAME')
                                            },
                                            {
                                                'Key': 'CreationMechanism',
                                                'Value': 'Lambda'
                                            }])

    def get_logs(self, gt, lte):

        q = Q("query_string", query=self.query_string)

        s = Search(using=self.es_client, index=self.index_pattern).query(q).\
            filter('range',
                   **{'@timestamp': {'gt': gt, 'lte': lte}}).\
            sort('@timestamp')

        logging.info(f"Searching {self.es_host} from {gt} to {lte} for '{self.query_string}' events")

        response = []

        for hit in s.scan():
            response.append(hit)

        return response

    def check_es_issue(self):

        error_header = self.header + f"encountered an exception:\n\n"

        events = []

        try:
            events = self.get_logs(gt=self.previous_timestamp, lte=self.current_timestamp)
        except (socket.timeout, socket.gaierror, HTTPError, ElasticConnectionError) as e:
            message = f"Connection error for host {self.es_host} - {e}"
            logging.error(message)
            self.trigger_sns([error_header + message])
            return
        except ElasticsearchException as e:
            message = f"Application-level exception returned by {self.es_host} - {e}"
            logging.error(message)
            self.trigger_sns([error_header + message])
            return
        except Exception as e:
            message = f"Exception encountered during query of {self.es_host} - {e}"
            logging.error(message)
            self.trigger_sns([error_header + message])
            return

        self.put_current_timestamp(self.ssm_client, self.current_timestamp)

        logging.info(f"Found {len(events)} events in {self.es_host}")

        return events

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
                            launch_time=instance_response['Reservations'][0]['Instances'][0]['LaunchTime'].strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                            hostname=instance_response['Reservations'][0]['Instances'][0]['PrivateDnsName'],
                            tags=tags_unpacked)

            logging.info("Found ec2 matching {private_dns_name}: {instance}".
                         format(private_dns_name=private_dns_name,
                                instance=' - '.join(f"{k} : {v}" for k, v in instance.items())))

            return instance

    def compare_instance_service_with_selector(self, instance):

        logging.info(f"Checking instance {instance['hostname']} for chosen tag 'Key':'Value' combination - "
                     f"'{self.tag_selector_key}':'{self.tag_selector_value}'")

        if self.tag_selector_key in instance['tags']:
            instance[self.tag_selector_key] = instance['tags'][self.tag_selector_key]
        else:
            logging.info(f"Skipping {instance['hostname']} because it has no '{self.tag_selector_key}' tag key")
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

        logging.info(f"Checking each event's node name against AWS API to obtain instance tags")

        ec2_client = self.session.client('ec2')

        matching_logs = []

        for log in response:
            if getattr(log, 'hostname', None):
                logging.info(f"Searching for instance with PrivateDnsName {log.hostname} - event message: {log.message}")
                instance = self.get_instance_from_private_dns_name(log.hostname, ec2_client)

                if instance:
                    if self.compare_instance_service_with_selector(instance):
                        setattr(log, 'ec2_details', instance)
                        matching_logs.append(log)
            else:
                logging.info(f"{log} has not hostname field, skipping")

        return matching_logs

    def format_events(self, events):

        if self.check_ec2:
            events.sort(key=operator.itemgetter('hostname', '@timestamp'))
        else:
            list(events).sort(key=operator.itemgetter('@timestamp'))

        logging.info(f"Found {len(events)} qualifying events")

        events_formatted = []

        for index, event in enumerate(events):
            logging.info(f"Found qualifying event: {event}")
            formatted_list = []
            for attribute in event:
                if type(getattr(event, attribute)) == AttrDict:
                    attr = f"{attribute}: {json.dumps(getattr(event, attribute).to_dict(), sort_keys=True, indent=4)}"
                else:
                    attr = f"{attribute}: " + str(getattr(event, attribute))
                formatted_list.append(attr + '\n')
            formatted_list.sort()
            formatted_log_entry = f"\n----\nevent {index+1} of {len(events)}\n"
            for item in formatted_list:
                formatted_log_entry += item
            events_formatted.append(formatted_log_entry)

        return events_formatted

    def prepare_messages(self, events_formatted,character_limit):

        event_header = self.header + f"detected {len(events_formatted)} events:\n"

        message_array = []
        if events_formatted:
            message_string = event_header
            for event in events_formatted:
                if len(message_string.encode('utf-8')) + len(event.encode('utf-8')) <= character_limit:
                    message_string = message_string + event
                else:
                    message_array.append(message_string)
                    message_string = event_header + event
                    continue

            message_array.append(message_string)

            logging.info(f"{len(events_formatted)} events split into {len(message_array)} SNS messages: "
                         f"{[str(len(m.encode('utf-8')))+' bytes' for m in message_array]}")

        return message_array

    def trigger_sns(self, messages):

        sns_client = self.session.client('sns')

        for index, message in enumerate(messages):
            logging.info(f"Publishing message {index+1} of {len(messages)} - {len(message.encode('utf-8'))} bytes")
            sns_client.publish(TopicArn=self.sns_topic_arn,
                               Subject=f"ACP Elasticsearch Event Alert: message {index+1} of {len(messages)}",
                               Message=message)

    def trigger_slack(self,messages):
        
        for index, message in enumerate(messages):

            msg = {
                "channel": self.slack_channel_name,
                "text": message
            } 

            encoded_message = json.dumps(msg).encode('utf-8')

            logging.info(f"Publishing message {index+1} of {len(messages)} to Slack channel {self.slack_channel_name} - {len(message.encode('utf-8'))} characters")
            logging.debug(f"Message {index+1} body: {message}")
            file_name = f"/tmp/log-file-{index+1}.json"

            f = open(file_name, "w")
            f.write(encoded_message)
            f.close()

            my_file = {
                'file' : (f'{file_name}', open(f'{file_name}', 'rb'), 'json') 
                }

            payload = {
                "channels": [self.slack_channel_name],
                "filetype": "javascript",
                "initial_comment": 'ALERT :rotating_light:',
                "title": 'POD-EXEC'
            }
            
            requests.post("https://slack.com/api/files.upload", params=payload, files=my_file, auth=(slack_password))


            logging.info(f"Uploaded file to {self.slack_channel_name} channel for message:  {index+1}")

    def run(self):

        ssh_event_logs = self.check_es_issue()

        if ssh_event_logs:
            if self.check_ec2:
                parsed_logs = self.parse_logs(ssh_event_logs)
                formatted_events = self.format_events(parsed_logs)
            else:
                formatted_events = self.format_events(ssh_event_logs)

            if len(formatted_events) >= self.period_event_threshold:
                
                if self.sns_topic_arn: 
                    #  SNS messages must be under 256KB, or 262,144 bytes
                    sns_message_array = self.prepare_messages(formatted_events, character_limit=262144)
                    self.trigger_sns(sns_message_array)
                
                if self.slack_channel_name:
                    #  SNS messages must be under 40000 characters
                    slack_message_array = self.prepare_messages(formatted_events, character_limit=40000)
                    self.trigger_slack(slack_message_array)


def main(event, context):

    notifier = Notifier(region=os.environ['AWS_REGION'],
                        account=os.environ['AWS_ACCOUNT'],
                        sns_topic_arn=os.environ['SNS_TOPIC_ARN'],
                        es_host=os.environ['ELASTICSEARCH_HOSTNAME'],
                        es_user=os.environ['ELASTICSEARCH_USERNAME'],
                        es_password=os.environ['ELASTICSEARCH_PASSWORD'],
                        tag_selector_key=os.environ['TAG_SELECTOR_KEY'],
                        tag_selector_value=os.environ['TAG_SELECTOR_VALUE'],
                        period_minutes=os.environ['PERIOD_MINUTES'],
                        query_string=os.environ['QUERY_STRING'],
                        index_pattern=os.environ['INDEX_PATTERN'],
                        check_ec2=os.environ['CHECK_EC2'],
                        period_event_threshold=os.environ['PERIOD_EVENT_THRESHOLD'],
                        query_delay_minutes=os.environ['QUERY_DELAY_MINUTES'],
                        slack_channel_name = os.environ['SLACK_CHANNEL_NAME'],
                        slack_password = os.environ['SLACK_BOT_TOKEN'])
                    
    notifier.run()
