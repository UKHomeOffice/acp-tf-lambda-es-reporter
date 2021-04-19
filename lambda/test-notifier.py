import unittest
from notifier import Notifier
import json
from unittest import mock

with open('test_cases/no_resources.json') as json_file:
    no_resources_event = json.load(json_file)

with open('test_cases/resources_no_tags.json') as json_file:
    resources_no_tags_event = json.load(json_file)

with open('test_cases/resources_and_tags.json') as json_file:
    resources_and_tags_event = json.load(json_file)


class NotifierTestCase(unittest.TestCase):
    def setUp(self):
        self.notifier = Notifier(region='eu-west-2',
                                 account='123456789012',
                                 sns_topic_prefix='acp_health_status_')

        topic_arn_prefix = f"arn:aws:sns:{self.notifier.region}:{self.notifier.account}:{self.notifier.sns_topic_prefix}"

        self.topic_1_arn = topic_arn_prefix + 'test-service-1'
        self.topic_2_arn = topic_arn_prefix + 'test-service-2'


class TestNotifierGetServices(NotifierTestCase):

    def test_resources_and_tags(self):
        services = self.notifier.get_services(resources_and_tags_event)
        self.assertTrue(services == ['test-service-1', 'test-service-2'])

    def test_no_resources(self):
        services = self.notifier.get_services(no_resources_event)
        self.assertTrue(services == [])

    @mock.patch('boto3.Session.client')
    def test_resources_no_tags(self, mock_client):

        mock_client('resourcegroupstaggingapi').get_resources.side_effect = [{
           "PaginationToken": "",
           "ResourceTagMappingList": [
              {
                 "ResourceARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-abcd1111",
                 "Tags": [
                    {
                       "Key": "Env",
                       "Value": "test"
                    },
                    {
                       "Key": "PROJECT-SERVICE",
                       "Value": "test-service-1"
                    }
                 ]
              }
           ],
           "ResponseMetadata": {}
        },
        {
            "PaginationToken": "",
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-abcd2222",
                    "Tags": [
                        {
                            "Key": "Env",
                            "Value": "test"
                        },
                        {
                            "Key": "PROJECT-SERVICE",
                            "Value": "test-service-2"
                        }
                    ]
                }
            ],
            "ResponseMetadata": {}
        }]

        services = self.notifier.get_services(resources_no_tags_event)

        mock_client.assert_has_calls(
            [mock.call().get_resources(ResourceARNList=['arn:aws:ec2:us-east-1:123456789012:instance/i-abcd1111']),
             mock.call().get_resources(ResourceARNList=['arn:aws:ec2:us-east-1:123456789012:instance/i-abcd2222'])])
        self.assertTrue(services == ['test-service-1', 'test-service-2'])

    @mock.patch('boto3.Session.client')
    def test_resources_no_tags_on_query(self, mock_client):

        mock_client('resourcegroupstaggingapi').get_resources.side_effect = [{
           "PaginationToken": "",
           "ResourceTagMappingList": [
              {
                 "ResourceARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-abcd1111",
                 "Tags": []
              }
           ],
           "ResponseMetadata": {}
        },
        {
            "PaginationToken": "",
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-abcd2222",
                    "Tags": []
                }
            ],
            "ResponseMetadata": {}
        }]

        services = self.notifier.get_services(resources_no_tags_event)

        mock_client.assert_has_calls([mock.call().get_resources(ResourceARNList=['arn:aws:ec2:us-east-1:123456789012:instance/i-abcd1111']),
                                     mock.call().get_resources(ResourceARNList=['arn:aws:ec2:us-east-1:123456789012:instance/i-abcd2222'])])
        self.assertTrue(services == [])


class TestNotifierGetTopics(NotifierTestCase):

    @mock.patch('boto3.Session.client')
    def test_topics_returned(self, mock_client):

        mock_client = mock_client('sns')

        mock_client.list_topics.side_effect = [
        {'Topics': [
            {'TopicArn': f"arn:aws:sns:{self.notifier.region}:{self.notifier.account}:topic1"},
            {'TopicArn': f"arn:aws:sns:{self.notifier.region}:{self.notifier.account}:topic2"},
            {'TopicArn': self.topic_1_arn}
        ],
            'NextToken': '0de58c91-ed93-5c19-974e-d42b0e7f437b',
            'ResponseMetadata':
                {'RequestId': '0de58c91-ed93-5c19-974e-d42b0e7f437b',
                 'HTTPStatusCode': 200,
                 'HTTPHeaders':
                     {},
                 'RetryAttempts': 0}
        },
        {'Topics': [
            {'TopicArn': self.topic_2_arn}
        ],
            'ResponseMetadata':
                {'RequestId': '0de58c91-ed93-5c19-974e-d42b0e7f437b',
                 'HTTPStatusCode': 200,
                 'HTTPHeaders':
                     {},
                 'RetryAttempts': 0}
        }]

        topics = {}
        self.notifier.get_topics(mock_client, topics)

        mock_client.assert_has_calls([mock.call.list_topics(NextToken=''),
                                      mock.call.list_topics(NextToken='0de58c91-ed93-5c19-974e-d42b0e7f437b')])

        self.assertEqual(topics, {
            'test-service-1': self.topic_1_arn,
            'test-service-2': self.topic_2_arn
        })


class TestNotifierParseTopics(NotifierTestCase):

    def test_topic_present(self):

        topics = {
            'test-service-1': self.topic_1_arn,
            'test-service-2': self.topic_2_arn
        }

        topic_arn = self.notifier.parse_topics(topics, 'test-service-1')

        self.assertEqual(topic_arn, self.topic_1_arn)

    def test_topic_absent(self):
        topics = {
            'test-service-1': self.topic_1_arn,
            'test-service-2': self.topic_2_arn
        }

        topic_arn = self.notifier.parse_topics(topics, 'test-service-3')

        self.assertEqual(topic_arn, None)


class TestNotifierTriggerSNS(NotifierTestCase):

    @mock.patch('boto3.Session.client')
    def test_trigger(self, mock_client):

        mock_client = mock_client('sns')

        self.notifier.trigger_sns(topic_arn=self.topic_1_arn,
                                  sns_client=mock_client,
                                  event=resources_and_tags_event)

        mock_client.assert_has_calls([mock.call.publish(TopicArn=self.topic_1_arn,
                                                        Subject='ACP Cloud Health Alert',
                                                        Message=resources_and_tags_event)])


class TestProcessEvent(NotifierTestCase):

    @mock.patch('boto3.Session.client')
    def test_process_resources_and_tags(self, mock_client):

        mock_client = mock_client('sns')

        mock_client.list_topics.side_effect = [
            {'Topics': [
                {'TopicArn': f"arn:aws:sns:{self.notifier.region}:{self.notifier.account}:topic1"},
                {'TopicArn': f"arn:aws:sns:{self.notifier.region}:{self.notifier.account}:topic2"},
                {'TopicArn': self.topic_1_arn}
            ],
                'NextToken': '0de58c91-ed93-5c19-974e-d42b0e7f437b',
            },
            {'Topics': [
                {'TopicArn': self.topic_2_arn}
            ],
        }]

        self.notifier.process_event(resources_and_tags_event)

        mock_client.assert_has_calls([mock.call.list_topics(NextToken=''),
                                      mock.call.list_topics(NextToken='0de58c91-ed93-5c19-974e-d42b0e7f437b')])

        mock_client.assert_has_calls([mock.call.publish(TopicArn=self.topic_1_arn,
                                                        Subject='ACP Cloud Health Alert',
                                                        Message=resources_and_tags_event),
                                      mock.call.publish(TopicArn=self.topic_2_arn,
                                                        Subject='ACP Cloud Health Alert',
                                                        Message=resources_and_tags_event)])

    @mock.patch('boto3.Session.client')
    def test_process_resources_no_tags(self, mock_client):

        mock_client('resourcegroupstaggingapi').get_resources.side_effect = [{
            "PaginationToken": "",
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-abcd1111",
                    "Tags": [
                        {
                            "Key": "Env",
                            "Value": "test"
                        },
                        {
                            "Key": "PROJECT-SERVICE",
                            "Value": "test-service-1"
                        }
                    ]
                }
            ],
            "ResponseMetadata": {}
        },
            {
                "PaginationToken": "",
                "ResourceTagMappingList": [
                    {
                        "ResourceARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-abcd2222",
                        "Tags": [
                            {
                                "Key": "Env",
                                "Value": "test"
                            },
                            {
                                "Key": "PROJECT-SERVICE",
                                "Value": "test-service-2"
                            }
                        ]
                    }
                ],
                "ResponseMetadata": {}
            }]

        mock_client('sns').list_topics.side_effect = [
            {'Topics': [
                {'TopicArn': f"arn:aws:sns:{self.notifier.region}:{self.notifier.account}:topic1"},
                {'TopicArn': f"arn:aws:sns:{self.notifier.region}:{self.notifier.account}:topic2"},
                {'TopicArn': self.topic_1_arn}
            ],
                'NextToken': '0de58c91-ed93-5c19-974e-d42b0e7f437b',
            },
            {'Topics': [
                {'TopicArn': self.topic_2_arn}
            ],
        }]

        self.notifier.process_event(resources_no_tags_event)

        mock_client.assert_has_calls(
            [mock.call().get_resources(ResourceARNList=['arn:aws:ec2:us-east-1:123456789012:instance/i-abcd1111']),
             mock.call().get_resources(ResourceARNList=['arn:aws:ec2:us-east-1:123456789012:instance/i-abcd2222'])])

        mock_client.assert_has_calls([mock.call().list_topics(NextToken=''),
                                      mock.call().list_topics(NextToken='0de58c91-ed93-5c19-974e-d42b0e7f437b')])

        mock_client.assert_has_calls([mock.call().publish(TopicArn=self.topic_1_arn,
                                                        Subject='ACP Cloud Health Alert',
                                                        Message=resources_no_tags_event),
                                      mock.call().publish(TopicArn=self.topic_2_arn,
                                                        Subject='ACP Cloud Health Alert',
                                                        Message=resources_no_tags_event)])
