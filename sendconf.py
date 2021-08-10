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
	r=asa_session.get(f"{asa_base_url}/exec/{quote(command,safe='')}")
	r.raise_for_status()
	logging.debug(f"Response received:\n{r.text}")
	return(r.text)

def post_data(url,data):
	global asa_session,asa_base_url
	logging.debug(f"Attempting to post to {url}")
	debug_level=http_client.HTTPConnection.debuglevel
	# Disabling debug to avoid printing contents of large files on the console
	http_client.HTTPConnection.debuglevel = 0
	r=asa_session.post(f"{asa_base_url}/{url}",data=data)
	r.raise_for_status()
	http_client.HTTPConnection.debuglevel = debug_level
	logging.debug(f"Response received:\n{r.text}")
	return(r.text)

def get_file_md5(asa_file_name):
	verify_output=send_exec_command(f"verify /md5 disk0:/{asa_file_name}")
	try:
		return(re.match(r".*([0-9a-z]{32}).*",verify_output,re.S)[1])
	except:
		return("unknown")

parser=argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,allow_abbrev=False,description="ASA Configuration Tool")
parser.add_argument("-m",help="Output Windows and *nix commands to execute actions manually. Will not attempt to connect to ASA.",action="store_true")
parser.add_argument("-a",metavar="<ASAIP>[:<PORT>]",help="ASA FQDN or IP address. HTTPS Port can be specified optionally",required=True)
parser.add_argument("-u",metavar="<username>",help="ASDM Username. If ommited, an interactive prompt will be displayed.")
parser.add_argument("-p",metavar="<password>",help="ASDM Password. If ommited, an interactive prompt will be displayed.")
parser.add_argument("-t",metavar="<trustpoint>=<pemfile>",help="Root CA Trustpoints and PEM files",nargs="+")
parser.add_argument("-i",metavar="<trustpoint>=<pfxfile>,<password>",help="Identity Trustpoints and PKCS12 files",nargs="+")
parser.add_argument("-f",metavar="<devicefile>=<localfile>",help="Upload files. Device file relative to disk0:/. Eg. sdesktop/data.xml=/tmp/data.xml",nargs="+")
parser.add_argument("-c",metavar="<configfile>",help="Path one or more config files. Configs will be applied in order.",nargs="+")
parser.add_argument("-d",metavar="<level>",help="Debug level. 1-Warning, 2-Verbose (default), 3-Debug",type=int,default=2,choices=[1,2,3])

args=parser.parse_args()

debug_level=[logging.WARNING,logging.INFO,logging.DEBUG][args.d-1]
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=debug_level)

asa_base_url=f"https://{args.a}/admin"
logging.debug("Validating arguments")
errors=""
manual=args.m

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
				f=open(pkcs12_file,"rb")
				pkcs12_data=f.read()
				f.close()
				id_certs.append({"tp_name":tp_name,"pkcs12_data":pkcs12_data,"pkcs12_password":pkcs12_password})
		except:
			errors+=f"Unable to read {pkcs12_file}\n"
			break

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
				f=open(ca_file,"r")
				ca_data=f.read()
				f.close()
				ca_certs.append({"tp_name":tp_name,"ca_data":ca_data})
		except:
			errors+=f"Unable to read {ca_file}\n"
			break

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
				f=open(local_file_name,"rb")
				file_data=f.read()
				f.close()
				upload_files.append({"asa_file_name":asa_file_name,"file_data":file_data})
		except:
			errors+=f"Unable to open {local_file_name}\n"
			break

config_files=[]
if args.c:
	for file in args.c:
		try:
			if manual:
				config_files.append({"config_file_name":file})
			else:
				f=open(file,"r")
				config_data=f.read()
				f.close
				config_files.append({"config_file_name":file,"config_data":config_data})
		except:
			errors+=f"Unable to open {file}\n"

if not id_certs and not ca_certs and not upload_files and not config_files:
	errors+="No task was specified\n"

if errors:
	parser.error(f"\n{errors}")

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
	tmp_suffix=random.randint(100000,999999)
	linux_cli+=f'''# Login to the ASA
curl -k -X POST -d "username={username}&password={password}&tgroup=DefaultADMINGroup&Login=Login" "https://{args.a}/+webvpn+/index.html" -A "ASDM/"  -b "webvpnlogin=1; tg=0RGVmYXVsdEFETUlOR3JvdXA=" -c /tmp/cj_{tmp_suffix}.txt
'''
else:
	if args.d==3:
		http_client.HTTPConnection.debuglevel = 1
	requests_log=logging.getLogger("requests.packages.urllib3")
	requests_log.setLevel(debug_level)
	requests_log.propagate=True
	asa_session=requests.Session()

	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	asa_session.verify=False

	asa_session.cookies.set("tg","0RGVmYXVsdEFETUlOR3JvdXA=")
	asa_session.cookies.set("webvpnlogin","1")

	asa_session.headers.update({"User-Agent":"ASDM/"})

	asa_session.post(f"https://{args.a}/+webvpn+/index.html",data={"username":username,"password":password,"tgroup":"DefaultADMINGroup","Login":"Login"})

	if not asa_session.cookies.get("webvpn"):
		logging.error("Login failed")
		sys.exit(1)

for ca_cert in ca_certs:
	tp_name=ca_cert["tp_name"]
	if manual:
		ca_file=ca_cert["ca_file"]
		linux_cli+=f'''
# Import CA Cert from {ca_file} into {tp_name}
echo no crypto ca trustpoint {tp_name} noconfirm >/tmp/{tp_name}_{tmp_suffix}.txt
echo crypto ca trustpoint {tp_name} >>/tmp/{tp_name}_{tmp_suffix}.txt
echo enrollment terminal >>/tmp/{tp_name}_{tmp_suffix}.txt
echo crypto ca authenticate {tp_name} nointeractive >>/tmp/{tp_name}_{tmp_suffix}.txt
cat {ca_file} >>/tmp/{tp_name}_{tmp_suffix}.txt
echo quit >>/tmp/{tp_name}_{tmp_suffix}.txt
curl -k "https://{args.a}/admin/config" -A "ASDM/"  -b /tmp/cj_{tmp_suffix}.txt -c /tmp/cj_{tmp_suffix}.txt --data-binary @/tmp/{tp_name}_{tmp_suffix}.txt -H "Content-Type: application/unknown"
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

for id_cert in id_certs:
	tp_name=id_cert["tp_name"]
	pkcs12_password=id_cert["pkcs12_password"]
	if manual:
		pkcs12_file=id_cert["pkcs12_file"]
		linux_cli+=f'''
# Import ID Cert from {pkcs12_file} into {tp_name}
base64 -b 64 -i {pkcs12_file} -o /tmp/{tp_name}_{tmp_suffix}.b64
echo no crypto ca trustpoint {tp_name} noconfirm >/tmp/{tp_name}_{tmp_suffix}.txt
echo crypto key zeroize rsa label {tp_name} noconfirm >>/tmp/{tp_name}_{tmp_suffix}.txt
echo crypto ca import {tp_name} pkcs12 {pkcs12_password} nointeractive >>/tmp/{tp_name}_{tmp_suffix}.txt
cat /tmp/{tp_name}_{tmp_suffix}.b64 >>/tmp/{tp_name}_{tmp_suffix}.txt
echo quit >>/tmp/{tp_name}_{tmp_suffix}.txt
curl -k "https://{args.a}/admin/config" -A "ASDM/"  -b /tmp/cj_{tmp_suffix}.txt -c /tmp/cj_{tmp_suffix}.txt --data-binary @/tmp/{tp_name}_{tmp_suffix}.txt -H "Content-Type: application/unknown"
rm /tmp/{tp_name}_{tmp_suffix}.txt /tmp/{tp_name}_{tmp_suffix}.b64
'''
	else:
		pkcs12_data=id_cert["pkcs12_data"]
		pkcs12_b64=b64encode(pkcs12_data).decode()
		pkcs12_asa=re.sub(r"(.{64})","\\1\n",pkcs12_b64,0,re.DOTALL)
		logging.info(f"Attempting to import PKCS12 identity certificate {tp_name}")
		config_response=post_data("config",f"""no crypto ca trustpoint {tp_name} noconfirm
	crypto key zeroize rsa label {tp_name} noconfirm
	crypto ca import {tp_name} pkcs12 {pkcs12_password} nointeractive
	{pkcs12_asa}
	quit
	""")
		logging.info(f"Received response:\n{config_response}")

for upload_file in upload_files:
	asa_file_name=upload_file["asa_file_name"]
	if manual:
		local_file_name=upload_file["local_file_name"]
		linux_cli+=f'''
# Upload local file {local_file_name} to {asa_file_name} on ASA
curl -k "https://{args.a}/admin/disk0/{asa_file_name}" -A "ASDM/"  -b /tmp/cj_{tmp_suffix}.txt -c /tmp/cj_{tmp_suffix}.txt --data-binary @{local_file_name} -H "Content-Type: application/unknown"
'''
	else:
		file_data=upload_file["file_data"]
		logging.debug(f"Getting MD5 checksum for {asa_file_name} from ASA")
		asa_md5=get_file_md5(asa_file_name)
		local_md5=hashlib.md5(file_data).hexdigest()
		logging.debug(f"ASA MD5 is {asa_md5}. Local MD5 is {local_md5}")
		if local_md5!=asa_md5:
			logging.info(f"Attempting to upload {asa_file_name}")
			upload_result=post_data(f"disk0/{asa_file_name}",file_data)
			logging.info(f"Received Response:\n{upload_result}")
		else:
			logging.info(f"{asa_file_name} is already on the device. Upload skipped.")

for config_file in config_files:
	config_file_name=config_file["config_file_name"]
	if manual:
		linux_cli+=f'''
# Applying configuration from {config_file_name}
curl -k "https://{args.a}/admin/config" -A "ASDM/"  -b /tmp/cj_{tmp_suffix}.txt -c /tmp/cj_{tmp_suffix}.txt --data-binary @{config_file_name} -H "Content-Type: application/unknown"
'''
	else:
		config_data=config_file["config_data"]
		logging.info(f"Attempting to post configuration from {config_file_name}")
		config_response=post_data("config",config_data)
		logging.info(f"Received response:\n{config_response}")

if manual:
	linux_cli+=f'''
# Delete Cookie Jar file
rm /tmp/cj_{tmp_suffix}.txt
'''
	windows_cli=linux_cli.replace("rm /","del /").replace("/tmp/","%TEMP%\\").replace("cat ","type ").\
		replace("base64 -b 64 -i","certutil -encode").replace(" -o "," ").replace("# ","REM ")
	print(f"----------------------------- *nix cli -----------------------------\n{linux_cli}")
	print(f"--------------------------- Windows cli ----------------------------\n{windows_cli}")
