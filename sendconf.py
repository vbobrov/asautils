#!/usr/bin/env python3

import logging
import sys
import requests
import argparse
import urllib3
import logging
import re
import hashlib
import http.client as http_client
import random
from urllib.parse import quote
from base64 import b64encode
from getpass import getpass

def send_exec_command(command):
	global asa_session,asa_base_url
	logging.debug(f"Attempting to execute: {command}")
	# Since the command is specified in the URL, we need to URL escape it
	r=asa_session.get(f"{asa_base_url}/exec/{quote(command,safe='')}",allow_redirects=False)
	r.raise_for_status()
	logging.debug(f"Response received:\n{r.text}")
	return(r.text)

def post_data(url,data):
	global asa_session,asa_base_url
	logging.debug(f"Attempting to post to {url}")
	debug_level=http_client.HTTPConnection.debuglevel
	# Disabling debug to avoid printing contents of large files on the console
	http_client.HTTPConnection.debuglevel = 0
	r=asa_session.post(f"{asa_base_url}/{url}",data=data,allow_redirects=False)
	r.raise_for_status()
	# Restoring debug level
	http_client.HTTPConnection.debuglevel = debug_level
	logging.debug(f"Response received:\n{r.text}")
	return(r.text)

def get_file_md5(asa_file_name):
	verify_output=send_exec_command(f"verify /md5 disk0:/{asa_file_name}")
	try:
		# Looking for a sequence of 32 hex digits, assuming it's the MD5 hash
		return(re.match(r".*([0-9a-z]{32}).*",verify_output,re.S)[1])
	except:
		return("unknown")

parser=argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,allow_abbrev=False,description="ASA Configuration Tool")
parser.add_argument("-m",help="Output Windows and *nix commands to execute tasks manually. Will not attempt to connect to ASA.",action="store_true")
parser.add_argument("-a",metavar="<ASAIP>[:<PORT>]",help="ASA FQDN or IP address. HTTPS Port can be specified optionally",required=True)
parser.add_argument("-u",metavar="<username>",help="ASDM Username. If ommited, an interactive prompt will be displayed.")
parser.add_argument("-p",metavar="<password>",help="ASDM Password. If ommited, an interactive prompt will be displayed.")
parser.add_argument("-t",metavar="<trustpoint>=<pemfile>",help="Root CA Trustpoints and PEM files",nargs="+")
parser.add_argument("-i",metavar="<trustpoint>=<pfxfile>,<password>",help="Identity Trustpoints and PKCS12 files",nargs="+")
parser.add_argument("-f",metavar="<devicefile>=<localfile>",help="Upload files. Device file relative to disk0:/. Eg. sdesktop/data.xml=/tmp/data.xml",nargs="+")
parser.add_argument("-c",metavar="<configfile>",help="Path one or more config files. Configs will be applied in order.",nargs="+")
parser.add_argument("-x",help="Use basic authentication",action="store_true")
parser.add_argument("-d",metavar="<level>",help="Debug level. 1-Warning, 2-Verbose (default), 3-Debug",type=int,default=2,choices=[1,2,3])

args=parser.parse_args()

debug_level=[logging.WARNING,logging.INFO,logging.DEBUG][args.d-1]
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=debug_level)

asa_base_url=f"https://{args.a}/admin"

logging.debug("Validating arguments")

errors=""

# This option tells the tool to output a Windows or Linux commands to execute action.
# When specified the tool will not communicate the the ASA at all.
# Additionally, this option will disable checking if any files such as uploads or certificates exist on disk.
# The tool generates only Linux commands through out the code.
# A simple find/replace is used at the end to translate Linux commands into their Windows alternatives
manual=args.m

# If -x option is specified all requests and generated manual commands use HTTP Basic authentication.
asdm_auth=not args.x

# Parsing identity certificate option -i
# Parsed data is stored in a list. All file data is loaded into a dict to avoid re-reading the same file again.
# When manual option is specified, only file names are stored.
id_certs=[]
if args.i:
	for id_cert in args.i:
		logging.debug(f"Parsing {id_cert}")
		try:
			tp_spec=re.match(r"^(.+)=(.+),(.+)$",id_cert)
			tp_name=tp_spec[1]
			pkcs12_file=tp_spec[2]
			pkcs12_password=tp_spec[3]
			logging.debug(f"Trustpoint name is {tp_name}. PKCS12 file is {pkcs12_file}")
		except:
			errors+=f"Unabled to parse {id_cert}. Expecting <trustpoint>=<pfxfile>,<password>. Example: ssl_cert=cert1.pfx,cisco123\n"
			break
		try:
			if manual:
				id_certs.append({"tp_name":tp_name,"pkcs12_file":pkcs12_file,"pkcs12_password":pkcs12_password})
			else:
				with open(pkcs12_file,"rb") as f:
					pkcs12_data=f.read()
				id_certs.append({"tp_name":tp_name,"pkcs12_data":pkcs12_data,"pkcs12_password":pkcs12_password})
		except:
			errors+=f"Unable to read {pkcs12_file}\n"
			break

# Parsing CA certificate option -t
# Parsed data is stored in a list. All file data is loaded into a dict to avoid re-reading the same file again.
# When manual option is specified, only file names are stored.
ca_certs=[]
if args.t:
	for ca_cert in args.t:
		logging.debug(f"Parsing {ca_cert}")
		try:
			tp_spec=re.match(r"^(.+)=(.+)$",ca_cert)
			tp_name=tp_spec[1]
			ca_file=tp_spec[2]
		except:
			errors+=f"Unabled to parse {ca_cert}. Expecting <trustpoint>=<pemfile>. Example: root_ca=root1.pem\n"
			break
		logging.debug(f"Trustpoint name is {tp_name}. PEM file is {ca_file}")
		try:
			if manual:
				ca_certs.append({"tp_name":tp_name,"ca_file":ca_file})
			else:
				with open(ca_file,"r") as f:
					ca_data=f.read()
					ca_certs.append({"tp_name":tp_name,"ca_data":ca_data})
		except:
			errors+=f"Unable to read {ca_file}\n"
			break

# Parsing upload option -f
# Parsed data is stored in a list. All file data is loaded into a dict to avoid re-reading the same file again.
# When manual option is specified, only file names are stored.
upload_files=[]
if args.f:
	for file in args.f:
		logging.debug(f"Parsing {file}")
		try:
			file_spec=re.match(r"^(.+)=(.+)",file)
			asa_file_name=file_spec[1]
			local_file_name=file_spec[2]
			logging.debug(f"ASA file is {asa_file_name}. Local file is {local_file_name}")
		except:
			errors+=f"Unable to parse {file}\n"
			break
		logging.debug(f"Attempting to open {local_file_name}")
		try:
			if manual:
				upload_files.append({"asa_file_name":asa_file_name,"local_file_name":local_file_name})
			else:
				with open(local_file_name,"rb") as f:
					file_data=f.read()
					upload_files.append({"asa_file_name":asa_file_name,"file_data":file_data})
		except:
			errors+=f"Unable to open {local_file_name}\n"
			break

# Parsing config option -c
# Parsed data is stored in a list. All file data is loaded into a dict to avoid re-reading the same file again.
# When manual option is specified, only file names are stored.
config_files=[]
if args.c:
	for file in args.c:
		try:
			if manual:
				config_files.append({"config_file_name":file})
			else:
				with open(file,"r") as f:
					config_data=f.read()
					config_files.append({"config_file_name":file,"config_data":config_data})
		except:
			errors+=f"Unable to open {file}\n"

if not id_certs and not ca_certs and not upload_files and not config_files:
	errors+="No task was specified\n"

# Throw an exception if errors are found
if errors:
	parser.error(f"\n{errors}")

# Prompt for username and/or password interactively if not specified in arguments
if args.u:
	username=args.u
else:
	username=input("ASDM Username: ")

if args.p:
	password=args.p
else:
	password=getpass("ASDM Password: ")


if manual:
	windows_cli=""
	linux_cli=""
	# When manual operation is specified, any temporary files needed for Windows or Linux commands are stored in system's temp directory using a random suffix.
	# Files are deleted after each operation
	tmp_suffix=random.randint(100000,999999)
	
	if asdm_auth:
		# If ASDM authentication is specified, an initial login to the ASA is required to get an authentication cookie.
		# That cookie is used in all subsequent requests
		linux_cli+=f'''# Login to the ASA
curl -k -X POST -d "username={username}&password={password}&tgroup=DefaultADMINGroup&Login=Login" "https://{args.a}/+webvpn+/index.html" -A "ASDM/"  -b "webvpnlogin=1; tg=0RGVmYXVsdEFETUlOR3JvdXA=" -c /tmp/cj_{tmp_suffix}.txt
'''
		curl_url=args.a
		curl_opt='-A "ASDM/"  -b /tmp/cj_{tmp_suffix}.txt -c /tmp/cj_{tmp_suffix}.txt'
	else:
		# With Basic authentication, the username and password are sent in every request.
		# Basic authentication requires http server basic-auth-client ASDM command on the ASA. This command is present by default.
		curl_url=f"{username}:{password}@{args.a}"
		curl_opt='-A "ASDM"'
else:
	if args.d==3:
		http_client.HTTPConnection.debuglevel = 1
	requests_log=logging.getLogger("requests.packages.urllib3")
	requests_log.setLevel(debug_level)
	requests_log.propagate=True

	# All requests will use a session. This simplifies handling of headers and cookies.
	asa_session=requests.Session()

	# Disable any certificate verification or errors.
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	asa_session.verify=False

	if asdm_auth:
		# ASDM sends a specific cookie ot the ASA to enable for form-based authentication.
		# After a successful authentication, webvpn cookie is return and is then used for subsequent requests
		asa_session.cookies.set("tg","0RGVmYXVsdEFETUlOR3JvdXA=")
		asa_session.cookies.set("webvpnlogin","1")
		asa_session.headers.update({"User-Agent":"ASDM/"})
		logging.debug("Attempting to login")
		asa_session.post(f"https://{args.a}/+webvpn+/index.html",data={"username":username,"password":password,"tgroup":"DefaultADMINGroup","Login":"Login"})
		if not asa_session.cookies.get("webvpn"):
			logging.error("Login failed")
			sys.exit(1)
		
	else:
		# Username and password for Basic authentication
		asa_session.auth=(username,password)
		asa_session.headers.update({"User-Agent":"ASDM"})
		logging.debug("Validating basic credentials")
		r=asa_session.get(f"{asa_base_url}/exec/show+version",allow_redirects=False)
		# ASA returns either 400 or 401 depending on failure.
		# If another code is return, the tool will throw an exception and exit.
		if r.status_code==401:
			logging.error("Basic credentials invalid")
			sys.exit(1)
		if r.status_code==400:
			logging.error("Basic authentication is disabled. Add 'http server basic-auth-client ASDM' command")
			sys.exit(1)
		r.raise_for_status

# PKCS12 files are always stored as binary. ASA can read the data from these files unchanged. 
# In order to send this data to ASA, it has to be converted to "pastable" base64 encoding.
for ca_cert in ca_certs:
	tp_name=ca_cert["tp_name"]
	if manual:
		ca_file=ca_cert["ca_file"]
		# In manual mode, the commands build up a temporary text file with the commands required to import PKCS12 file.
		# All commands are then sent using curl.
		# The temporary file is delete at the end.
		linux_cli+=f'''
# Import CA Cert from {ca_file} into {tp_name}
echo no crypto ca trustpoint {tp_name} noconfirm >/tmp/{tp_name}_{tmp_suffix}.txt
echo crypto ca trustpoint {tp_name} >>/tmp/{tp_name}_{tmp_suffix}.txt
echo enrollment terminal >>/tmp/{tp_name}_{tmp_suffix}.txt
echo crypto ca authenticate {tp_name} nointeractive >>/tmp/{tp_name}_{tmp_suffix}.txt
cat {ca_file} >>/tmp/{tp_name}_{tmp_suffix}.txt
echo quit >>/tmp/{tp_name}_{tmp_suffix}.txt
curl -k "https://{curl_url}/admin/config" {curl_opt} --data-binary @/tmp/{tp_name}_{tmp_suffix}.txt -H "Content-Type: application/unknown"
rm /tmp/{tp_name}_{tmp_suffix}.txt
'''
	else:
		ca_data=ca_cert["ca_data"]
		logging.info(f"Attempting to import CA certificate {tp_name}")
		config_response=post_data("config",f"""no crypto ca trustpoint {tp_name} noconfirm
crypto ca trustpoint {tp_name}
enrollment terminal
crypto ca authenticate {tp_name} nointeractive
{ca_data}
quit
""")
		logging.info(f"Received response:\n{config_response}")

# CA certificates can be stored in base64-encoded PEM files or binary DER files.
# To avoid dependency on modules and tool to convert certificate files, this tool will only work with PEM files.
# DER files need to be converted to PEM. With openssl, it can be done as follows: openssl x509 -inform der -in cert.der -out cert.pem
for id_cert in id_certs:
	tp_name=id_cert["tp_name"]
	pkcs12_password=id_cert["pkcs12_password"]
	if manual:
		pkcs12_file=id_cert["pkcs12_file"]
		# In manual mode, the commands build up a temporary text file with the commands required to import CA file.
		# All commands are then sent using curl.
		# The temporary file is delete at the end.
		linux_cli+=f'''
# Import ID Cert from {pkcs12_file} into {tp_name}
base64 -b 64 -i {pkcs12_file} -o /tmp/{tp_name}_{tmp_suffix}.b64
echo no crypto ca trustpoint {tp_name} noconfirm >/tmp/{tp_name}_{tmp_suffix}.txt
echo crypto key zeroize rsa label {tp_name} noconfirm >>/tmp/{tp_name}_{tmp_suffix}.txt
echo crypto ca import {tp_name} pkcs12 {pkcs12_password} nointeractive >>/tmp/{tp_name}_{tmp_suffix}.txt
cat /tmp/{tp_name}_{tmp_suffix}.b64 >>/tmp/{tp_name}_{tmp_suffix}.txt
echo quit >>/tmp/{tp_name}_{tmp_suffix}.txt
curl -k "https://{curl_url}/admin/config" {curl_opt} --data-binary @/tmp/{tp_name}_{tmp_suffix}.txt -H "Content-Type: application/unknown"
rm /tmp/{tp_name}_{tmp_suffix}.txt /tmp/{tp_name}_{tmp_suffix}.b64
'''
	else:
		pkcs12_data=id_cert["pkcs12_data"]
		pkcs12_b64=b64encode(pkcs12_data).decode()
		# Break a long base64 string into multiple lines, 64-characters each.
		pkcs12_asa=re.sub(r"(.{64})","\\1\n",pkcs12_b64,0,re.DOTALL)
		logging.info(f"Attempting to import PKCS12 identity certificate {tp_name}")
		config_response=post_data("config",f"""no crypto ca trustpoint {tp_name} noconfirm
	crypto key zeroize rsa label {tp_name} noconfirm
	crypto ca import {tp_name} pkcs12 {pkcs12_password} nointeractive
	{pkcs12_asa}
	quit
	""")
		logging.info(f"Received response:\n{config_response}")

# To avoid reuploading the same file multiple times, verify command is run first to get the MD5 has of the file.
# This hash is then compared to the local file. If they're the same, the upload is skipped. MD5 is used to speed up processing.
# In manual mode, there's to command generated to do MD5 comparison.
for upload_file in upload_files:
	asa_file_name=upload_file["asa_file_name"]
	if manual:
		local_file_name=upload_file["local_file_name"]
		linux_cli+=f'''
# Upload local file {local_file_name} to {asa_file_name} on ASA
curl -k "https://{curl_url}/admin/disk0/{asa_file_name}" {curl_opt} --data-binary @{local_file_name} -H "Content-Type: application/unknown"
'''
	else:
		file_data=upload_file["file_data"]
		logging.debug(f"Getting MD5 checksum for {asa_file_name} from ASA")
		# Get MD5 hash of the file from the ASA.
		asa_md5=get_file_md5(asa_file_name)
		# Calculate local MD5 hash.
		local_md5=hashlib.md5(file_data).hexdigest()
		logging.debug(f"ASA MD5 is {asa_md5}. Local MD5 is {local_md5}")
		if local_md5!=asa_md5:
			logging.info(f"Attempting to upload {asa_file_name}")
			upload_result=post_data(f"disk0/{asa_file_name}",file_data)
			logging.info(f"Received Response:\n{upload_result}")
		else:
			logging.info(f"{asa_file_name} is already on the device. Upload skipped.")

# The ASA supports both exec and config commands in these files.
# It is not necessary to supply configure terminal and exit commands.
# There are certain commands on the ASA that take a few seconds to complete. Write memory command may not work in these cases when supplied in the same file.
for config_file in config_files:
	config_file_name=config_file["config_file_name"]
	if manual:
		linux_cli+=f'''
# Applying configuration from {config_file_name}
curl -k "https://{curl_url}/admin/config" {curl_opt} --data-binary @{config_file_name} -H "Content-Type: application/unknown"
'''
	else:
		config_data=config_file["config_data"]
		logging.info(f"Attempting to post configuration from {config_file_name}")
		config_response=post_data("config",config_data)
		logging.info(f"Received response:\n{config_response}")

if manual:
	if asdm_auth:
		linux_cli+=f'''
# Delete Cookie Jar file
rm /tmp/cj_{tmp_suffix}.txt
'''
	# Simple find and replace to convert Linux OS commands to Windows.
	windows_cli=linux_cli.replace("rm /","del /").replace("/tmp/","%TEMP%\\").replace("cat ","type ").\
		replace("base64 -b 64 -i","certutil -encode").replace(" -o "," ").replace("# ","REM ")
	print(f"----------------------------- *nix cli -----------------------------\n{linux_cli}")
	print(f"--------------------------- Windows cli ----------------------------\n{windows_cli}")
