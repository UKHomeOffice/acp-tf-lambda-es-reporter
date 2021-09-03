import unittest
from notifier import Notifier
from unittest import mock
import socket
import datetime as dt

class NotifierTestCase(unittest.TestCase):
    @mock.patch('boto3.Session.client')
    def setUp(self, mock_boto_client):

        self.notifier = Notifier(region='eu-west-2',
                                account='123456789',
                                sns_topic_arn='dummy-arn',
                                es_host='elastic-local.com',
                                es_user='test',
                                es_password='testpass',
                                tag_selector_key='Name',
                                tag_selector_value='test',
                                period_minutes='1',
                                query_string='syslog_identifier: sshd',
                                index_pattern='*',
                                check_ec2='TRUE',
                                period_event_threshold='0',
                                query_delay_minutes=0,
                                slack_channel_id = "dummy-channel",
                                slack_password = "testpass"
                                )

        self.notifier.previous_timestamp = '1066-10-14T10:11:12.999999Z'

        self.mock_ec2_client_response = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "AmiLaunchIndex": 0,
                            "ImageId": "ami-0551d1417af39acc9",
                            "InstanceId": "i-0212daed6389691d3",
                            "Placement": {
                                "AvailabilityZone": "eu-west-2a",
                                "GroupName": "",
                                "Tenancy": "default"
                            },
                            "PrivateDnsName": "ip-10-250-3-14.eu-west-2.compute.internal",
                            "PrivateIpAddress": "10.250.3.14",
                            "ProductCodes": [

                            ],
                            "PublicDnsName": "",
                            "State": {
                                "Code": 16,
                                "Name": "running"
                            },
                            "SubnetId": "subnet-82a5c1f9",
                            "VpcId": "vpc-da3c49b3",
                            "LaunchTime": dt.datetime(1066, 1, 1, 1, 1, 1, 111111),
                            "Tags": [
                                {
                                    "Key": "Name",
                                    "Value": "test"
                                },
                                {
                                    "Key": "Env",
                                    "Value": "test"
                                },
                                {
                                    "Key": "AcpSHA",
                                    "Value": "a5adc91a3deb7d07a351d89b003fa779d5106df7"
                                },
                                {
                                    "Key": "KubernetesCluster",
                                    "Value": "test.testing.acp.homeoffice.gov.uk"
                                }
                            ],
                        }
                    ],
                    "OwnerId": "670930646103",
                    "RequesterId": "626974355284",
                    "ReservationId": "r-00a8bee9bfdda697a"
                }
            ]
        }

class TestNotifierCheckESIssue(NotifierTestCase):

    @mock.patch('elasticsearch.Elasticsearch.search')
    @mock.patch('notifier.Notifier.get_logs')
    @mock.patch('notifier.Notifier.trigger_sns')
    @mock.patch('notifier.Notifier.put_current_timestamp')
    def test_connection_error(self,
                            mock_put_current_timestamp,
                            mock_trigger_sns,
                            mock_get_logs,
                            mock_es_client):

        error_header = self.notifier.header + f"encountered an exception:\n\n"

        mock_get_logs.side_effect = socket.timeout('exception')

        message = f"Connection error for host {self.notifier.es_host} - exception"

        self.notifier.check_es_issue()

        mock_trigger_sns.assert_called_with([error_header + message])

        mock_put_current_timestamp.assert_not_called()

    @mock.patch('elasticsearch.Elasticsearch.search')
    @mock.patch('notifier.Notifier.get_logs')
    @mock.patch('notifier.Notifier.put_current_timestamp')
    def test_events_returned(self,
                            mock_put_current_timestamp,
                            mock_get_logs,
                            mock_es_client):

        mock_get_logs.return_value = [{'a': 'b'}]

        events = self.notifier.check_es_issue()

        self.assertTrue(events == [{'a': 'b'}])

        mock_put_current_timestamp.assert_called_with(self.notifier.ssm_client, self.notifier.current_timestamp)

    @mock.patch('boto3.Session.client')
    def test_get_instance_from_private_dns_name(self,
                                                mock_boto_client):

        mock_boto_client.describe_instances.return_value = self.mock_ec2_client_response

        instance = self.notifier.get_instance_from_private_dns_name('a', mock_boto_client)

        self.assertTrue(instance['launch_time'] == dt.datetime(1066, 1, 1, 1, 1, 1, 111111).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                        instance['name'] == 'test')

        mock_boto_client.describe_instances.assert_called_once()


    @mock.patch('notifier.Notifier.trigger_sns')
    @mock.patch('boto3.Session.client')
    @mock.patch('elasticsearch_dsl.Search.execute')
    def test_when_threshold_set_and_met(self,
                                    mock_es_search,
                                    mock_ec2_client_ctor,
                                    mock_trigger_sns):

        self.notifier.period_event_threshold = 3
        mock_es_result = mock.MagicMock(hostname='mock.dns.name')
        mock_es_search.return_value = [mock_es_result, mock_es_result, mock_es_result]
        mock_ec2_client_intance = mock.MagicMock()
        mock_ec2_client_ctor.return_value = mock_ec2_client_intance
        mock_ec2_client_intance.describe_instances.return_value = self.mock_ec2_client_response

        self.notifier.run()

        mock_trigger_sns.assert_called_once()

    @mock.patch('notifier.Notifier.prepare_messages')
    @mock.patch('boto3.Session.client')
    @mock.patch('elasticsearch_dsl.Search.execute')
    def test_when_threshold_set_and_not_met(self,
                                    mock_es_search,
                                    mock_ec2_client_ctor,
                                    mock_prepare_messages):

        self.notifier.period_event_threshold = 3
        mock_es_result = mock.MagicMock(hostname='mock.dns.name')
        mock_es_search.return_value = [mock_es_result, mock_es_result]
        mock_ec2_client_instance = mock.MagicMock()
        mock_ec2_client_ctor.return_value = mock_ec2_client_instance
        mock_ec2_client_instance.describe_instances.return_value = self.mock_ec2_client_response

        self.notifier.run()

        mock_prepare_messages.assert_not_called()

    @mock.patch('notifier.Notifier.trigger_sns')
    @mock.patch('boto3.Session.client')
    @mock.patch('elasticsearch_dsl.Search.execute')
    def test_when_threshold_not_set(self,
                                    mock_es_search,
                                    mock_ec2_client_ctor,
                                    mock_trigger_sns):

        self.notifier.period_event_threshold = None
        mock_es_result = mock.MagicMock(hostname='mock.dns.name')
        mock_es_search.return_value = [mock_es_result, mock_es_result]
        mock_ec2_client_intance = mock.MagicMock()
        mock_ec2_client_ctor.return_value = mock_ec2_client_intance
        mock_ec2_client_intance.describe_instances.return_value = self.mock_ec2_client_response

        self.notifier.run()

        mock_trigger_sns.assert_called_once()

    @mock.patch('notifier.Notifier.trigger_sns')
    @mock.patch('boto3.Session.client')
    @mock.patch('elasticsearch_dsl.Search.execute')
    def test_when_ec2_instance_check_set(self,
                                    mock_es_search,
                                    mock_ec2_client_ctor,
                                    mock_trigger_sns):

        self.notifier.period_event_threshold = 1
        mock_es_result = mock.MagicMock(hostname='mock.dns.name')
        mock_es_search.return_value = [mock_es_result, mock_es_result]
        mock_ec2_client_instance = mock.MagicMock()
        mock_ec2_client_ctor.return_value = mock_ec2_client_instance
        mock_ec2_client_instance.describe_instances.return_value = self.mock_ec2_client_response

        self.notifier.run()

        mock_trigger_sns.assert_called_once()

    @mock.patch('notifier.Notifier.trigger_sns')
    @mock.patch('boto3.Session.client')
    @mock.patch('elasticsearch_dsl.Search.execute')
    def test_when_ec2_instance_check_not_set(self,
                                    mock_es_search,
                                    mock_ec2_client_ctor,
                                    mock_trigger_sns):

        self.notifier.check_ec2 = False
        self.notifier.period_event_threshold = None
        mock_es_result = mock.MagicMock(hostname='mock.dns.name')
        mock_es_search.return_value = [mock_es_result, mock_es_result]
        mock_ec2_client_instance = mock.MagicMock()

        self.notifier.run()

        mock_ec2_client_instance.assert_not_called()