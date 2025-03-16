import json
import unittest
from unittest.mock import patch, MagicMock
import security_monitor

class TestSecurityMonitor(unittest.TestCase):
    """Test cases for the security_monitor Lambda function."""

    @patch('security_monitor.sns')
    def test_iam_user_creation_event(self, mock_sns):
        """Test handling of IAM user creation event."""
        # Mock SNS client
        mock_sns.publish.return_value = {'MessageId': '12345'}
        
        # Sample IAM user creation event
        event = {
            "version": "0",
            "id": "12345678-1234-1234-1234-123456789012",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.iam",
            "account": "123456789012",
            "time": "2023-01-01T12:00:00Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDAEXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/Admin",
                    "accountId": "123456789012",
                    "userName": "Admin"
                },
                "eventTime": "2023-01-01T12:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.1",
                "userAgent": "AWS Console",
                "requestParameters": {
                    "userName": "TestUser"
                },
                "responseElements": {
                    "user": {
                        "userName": "TestUser",
                        "userId": "AIDAEXAMPLE2",
                        "arn": "arn:aws:iam::123456789012:user/TestUser",
                        "createDate": "2023-01-01T12:00:00Z"
                    }
                }
            }
        }
        
        # Call the Lambda handler
        response = security_monitor.lambda_handler(event, {})
        
        # Assert that the handler returned a successful response
        self.assertEqual(response['statusCode'], 200)
        
        # Assert that SNS publish was called
        mock_sns.publish.assert_called_once()
        
        # Get the call arguments
        args, kwargs = mock_sns.publish.call_args
        
        # Assert that the message contains the expected information
        message_dict = json.loads(kwargs['Message'])
        self.assertEqual(message_dict['Initiator'], "arn:aws:iam::123456789012:user/Admin")
        self.assertEqual(message_dict['Action'], "Created User")
        self.assertIn("TestUser", message_dict['ResourceARN'])

    @patch('security_monitor.sns')
    def test_security_group_ingress_change_event(self, mock_sns):
        """Test handling of security group ingress rule change event."""
        # Mock SNS client
        mock_sns.publish.return_value = {'MessageId': '12345'}
        
        # Sample security group ingress rule change event
        event = {
            "version": "0",
            "id": "12345678-1234-1234-1234-123456789012",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.ec2",
            "account": "123456789012",
            "time": "2023-01-01T12:00:00Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDAEXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/Admin",
                    "accountId": "123456789012",
                    "userName": "Admin"
                },
                "eventTime": "2023-01-01T12:00:00Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "AuthorizeSecurityGroupIngress",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.1",
                "userAgent": "AWS Console",
                "requestParameters": {
                    "groupId": "sg-12345",
                    "ipPermissions": {
                        "items": [
                            {
                                "ipProtocol": "tcp",
                                "fromPort": 22,
                                "toPort": 22,
                                "ipRanges": {
                                    "items": [
                                        {
                                            "cidrIp": "0.0.0.0/0"
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                },
                "responseElements": {
                    "requestId": "12345678-1234-1234-1234-123456789012",
                    "return": "true"
                }
            }
        }
        
        # Call the Lambda handler
        response = security_monitor.lambda_handler(event, {})
        
        # Assert that the handler returned a successful response
        self.assertEqual(response['statusCode'], 200)
        
        # Assert that SNS publish was called
        mock_sns.publish.assert_called_once()
        
        # Get the call arguments
        args, kwargs = mock_sns.publish.call_args
        
        # Assert that the message contains the expected information
        message_dict = json.loads(kwargs['Message'])
        self.assertEqual(message_dict['Initiator'], "arn:aws:iam::123456789012:user/Admin")
        self.assertEqual(message_dict['Action'], "Authorized SecurityGroupIngress")
        self.assertIn("sg-12345", message_dict['ResourceARN'])

    @patch('security_monitor.sns')
    def test_error_handling(self, mock_sns):
        """Test error handling in the Lambda function."""
        # Mock SNS client to raise an exception
        mock_sns.publish.side_effect = Exception("Test exception")
        
        # Sample event
        event = {
            "version": "0",
            "id": "12345678-1234-1234-1234-123456789012",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.iam",
            "account": "123456789012",
            "time": "2023-01-01T12:00:00Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "eventName": "CreateUser",
                "userIdentity": {
                    "arn": "arn:aws:iam::123456789012:user/Admin"
                },
                "requestParameters": {
                    "userName": "TestUser"
                }
            }
        }
        
        # Call the Lambda handler
        response = security_monitor.lambda_handler(event, {})
        
        # Assert that the handler returned an error response
        self.assertEqual(response['statusCode'], 500)
        self.assertIn("Error processing security event", response['body'])

if __name__ == '__main__':
    unittest.main()
