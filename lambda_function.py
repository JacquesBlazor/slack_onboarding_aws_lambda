from onboarding_tutorial import OnboardingTutorial
from botocore.exceptions import ClientError
from base64 import b64encode, b64decode
from slack_sdk.web import WebClient
from decimal import Decimal
import traceback
import logging
import hashlib
import pickle
import boto3
import hmac
import json
import sys
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)
slack_web_client = WebClient(token=os.getenv('SLACK_BOT_TOKEN'))
dynamodb = boto3.resource('dynamodb', region_name='ap-east-1')
dynamodbTb_hyeonmsgsent = dynamodb.Table('pyqi-msgsent')
logger.debug(os.environ)

def getDynamo_hyeonMsgSentItem(channel, dynamodbTb):
    try:
        response = dynamodbTb.get_item(Key={
            'channel': channel
        })
    except ClientError as e:
        logger.error(e.response['Error']['Message'])
    else:
        return response['Item'] if 'Item' in response else None
        
def putDynamo_hyeonOperation(channel, user_id, payload):
    try:
        userItem = {
            'channel': channel, 
            user_id: b64encode(pickle.dumps(payload)).decode('utf-8')
        }
        logger.debug('正在將小秘書目前的操作 Operation 記錄寫入 DynamoDb 的 dynamodbTb_hyeonmsgsent 表格')
        putDbResponse = dynamodbTb_hyeonmsgsent.put_item(Item=userItem)
    except ClientError as e:
        logger.error('將小秘書的操作 Operation 記錄寫入 DynamoDb 的 dynamodbTb_hyeonmsgsent 表格時發生錯誤: %s' % e.response['Error']['Message'])
    if putDbResponse and putDbResponse['ResponseMetadata']['HTTPStatusCode'] != 200:
        logger.error('將小秘書的操作 Operation 記錄寫入 DynamoDb 的 dynamodbTb_hyeonmsgsent 表格時回應錯誤:' % putDbResponse['ResponseMetadata']['HTTPStatusCode'])

def verify_slack_request(slack_signature, slack_request_timestamp, payload_str):
    slack_signing_secret = os.getenv('SLACK_SIGNING_SECRET')
    basestring = f"v0:{slack_request_timestamp}:{payload_str}".encode('utf-8')
    slack_signing_secret = bytes(slack_signing_secret, 'utf-8')
    hash_signature = 'v0=' + hmac.new(slack_signing_secret, basestring, hashlib.sha256).hexdigest()
    if hmac.compare_digest(hash_signature, slack_signature):
        return True
    logger.warning('Slack signature verification failed: %s' % hash_signature)
    return False

def start_onboarding(user_id: str, user_name: str, real_name: str, channel: str):
    onboarding_tutorial = OnboardingTutorial(user_id, user_name, real_name, channel)
    message = onboarding_tutorial.get_message_payload()
    response = slack_web_client.chat_postMessage(**message)
    onboarding_tutorial.timestamp = response['ts']
    hyeonMsgSentItem = getDynamo_hyeonMsgSentItem(channel, dynamodbTb_hyeonmsgsent)
    if not hyeonMsgSentItem or channel not in hyeonMsgSentItem['channel']:
        putDynamo_hyeonOperation(channel, user_id=user_id, payload=onboarding_tutorial)

def update_emoji(user_id: str, channel: str):
    logger.info('running update_emoji...')
    hyeonMsgSentItem = getDynamo_hyeonMsgSentItem(channel, dynamodbTb_hyeonmsgsent)
    if not hyeonMsgSentItem or channel not in hyeonMsgSentItem['channel']:
        logger.warning('update_emoji no hyeonMsgSentItem...')
        return
    onboarding_tutorial = pickle.loads(b64decode(hyeonMsgSentItem[user_id]))
    onboarding_tutorial.reaction_task_completed = True
    message = onboarding_tutorial.get_message_payload()
    updated_message = slack_web_client.chat_update(**message)
    onboarding_tutorial.timestamp = updated_message["ts"]
    putDynamo_hyeonOperation(channel, user_id=user_id, payload=onboarding_tutorial)

def update_pin(user_id: str, channel: str):
    logger.info('running update_pin...')
    hyeonMsgSentItem = getDynamo_hyeonMsgSentItem(channel, dynamodbTb_hyeonmsgsent)
    if not hyeonMsgSentItem or channel not in hyeonMsgSentItem['channel']:
        logger.warning('update_pin no hyeonMsgSentItem...')
        return
    onboarding_tutorial = pickle.loads(b64decode(hyeonMsgSentItem[user_id]))
    onboarding_tutorial.pin_task_completed = True
    message = onboarding_tutorial.get_message_payload()
    updated_message = slack_web_client.chat_update(**message)
    onboarding_tutorial.timestamp = updated_message["ts"]
    putDynamo_hyeonOperation(channel, user_id=user_id, payload=onboarding_tutorial)
    
def lambda_handler(lambda_event, context):
    logger.debug('lambda_event: %s' % lambda_event)
    try:
        payload_str = lambda_event['body']
        slack_signature = lambda_event['headers']['x-slack-signature']
        slack_request_timestamp = lambda_event['headers']['x-slack-request-timestamp']
        logger.debug('slack_signature: %s, slack_request_timestamp: %s, payload_str: %s' % (slack_signature, slack_request_timestamp, payload_str))
        if not verify_slack_request(slack_signature, slack_request_timestamp, payload_str):
            logger.warning('InvalidSignature! Slack request verification was not passed!')
            return {
                'statusCode': 400,
                'body': json.dumps('InvalidSignature!')
            }
        logger.info('ValidSignature! Slack request verification was passed!')            
        payload = json.loads(payload_str)
        logger.debug('payload: %s, its type: %s' % (payload, type(payload)))
        if 'challenge' in payload:
            challenge = payload['challenge']
            logger.debug('payload challenge: %s' % challenge)
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "challenge": challenge
                })
            }
        elif 'event' in payload:
            event =  payload['event']
            logger.info('event: %s' % event)
            event_type = event['type']
            logger.info('event_type: %s' % event_type)
            if event_type == 'team_join':
                user_id = event['user']['id']
                user_name = event['user']['name']
                real_name = event['user']['real_name']
                logger.info('user_id: %s, user_name: %s, real_name: %s' % (user_id, user_name, real_name))
                response = slack_web_client.conversations_open(users=user_id)
                logger.info('response: %s' % response)
                if response['ok']:
                    channel = response['channel']['id']
                    logger.info('channel: %s' % channel)
                    start_onboarding(user_id, user_name, real_name, channel)
            elif event_type == 'reaction_added':
                channel = event['item']['channel']
                user_id = event['user']
                logger.info('user_id: %s, channel: %s' % (user_id, channel))
                update_emoji(user_id, channel)
            elif event_type == 'pin_added':
                channel = event['channel_id']
                user_id = event['user']
                logger.info('user_id: %s, channel: %s' % (user_id, channel))
                update_pin(user_id, channel)
            elif event_type == 'message':
                if 'subtype' in event:
                    subtype = event['subtype']
                    logger.info('subtype: %s' % subtype)
                    channel = event['channel']
                    logger.info('channel: %s' % channel)
                    channel_type = event['channel_type']
                    logger.info('channel_type: %s' % channel_type)
                    if 'message' in event and 'user' in event['message']:
                        user_id = event['message']['user']
                        logger.info('user_id: %s' % user_id)
                else:
                    channel = event['channel']
                    user_id = event['user']
                    text = event['text']
                    logger.info('channel: %s, user_id: %s, text: %s' % (channel, user_id, text))
                    if text and text.lower() == "start_onboarding":
                        start_onboarding(user_id, user_id, user_id, channel)                    
        else:
            logger.warning('Exception no event!')
    except Exception as e:
        logger.error('error: %s' % e)
        return {
            'statusCode': 400,
            'body': json.dumps(traceback.format_exc())
        }
    else:
        return {
            'statusCode': 200,
            'body': json.dumps('Return from Lambda for nothing!')
        }