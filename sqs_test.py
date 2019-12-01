import boto3

from hashlib import sha256
import binascii
import sys
def test_nonces(offset,stride, byte_string,difficulty):
	for i in range (offset,sys.maxsize,stride):
		result = hash(i,byte_string)
		golden = test_hash(result,difficulty)
		
		if (golden):
			print (result)
			return result,i
		

def test_hash(hash,difficulty):
	for i in range (0,difficulty):
		if (hash[i] != 0):
			return False;
	return True

def hash(nonce, byte_string):
	string_to_hash = byte_string + int_to_bytes(nonce)
	return sha256(sha256(string_to_hash).digest()).digest();

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def_region = "us-east-1"
session = boto3.Session(region_name = def_region)
ec2 = session.resource('ec2')
sqs = session.resource('sqs')
queue_input = sqs.get_queue_by_name(QueueName = "rh16238_input.fifo")
queue_output = sqs.get_queue_by_name(QueueName = "rh16238_output.fifo")

awaiting_input = True
offset = 0
stride=1
string_to_hash = ""
difficulty = 1
while awaiting_input:
	for message in queue_input.receive_messages(MessageAttributeNames=['offset','stride','string_to_hash','difficulty']):
		print(message)
		message.delete()
		if message.message_attributes is not None:
			offset = int(message.message_attributes.get('offset').get('StringValue'))
			stride = int(message.message_attributes.get('stride').get('StringValue'))
			string_to_hash = message.message_attributes.get('string_to_hash').get('StringValue')
			difficulty = int(message.message_attributes.get('difficulty').get('StringValue'))
			awaiting_input = False
			print("offset: " + str(offset) + " stride: " +str(stride) + " hash: " + string_to_hash + " difficulty: " + str(difficulty))

queue_output.send_message(MessageBody='boto3', MessageGroupId = "1",MessageDeduplicationId =string_to_hash, MessageAttributes={
    'hash': {
        'StringValue':"FF",
        'DataType': 'String'
    },
    'nonce': {
        'StringValue': "0",
        'DataType': 'String'
    }
})

