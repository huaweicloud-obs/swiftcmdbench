from httplib import HTTPSConnection
from urlparse import urlparse, urlunparse, urljoin
import sys,json,ssl
iamurl='https://8.42.37.24:9443/v3/auth/tokens'
parsed = urlparse(iamurl)
path = parsed.path
conn = HTTPSConnection(parsed.netloc,context=ssl._create_stdlib_context())
headers = {'Content-Type': 'application/json;charset=utf8', 'Accept': 'application/json'}
start=int(sys.argv[1])
end=int(sys.argv[2])
file=open('users.dat','w+')
for i in range(start,end):
	userName='UDSIAMSTUBTEST%06d'%(i)
	data='{"auth":{ "identity":{"methods":[ "password"], "password":{"user":{"domain":{"name":"new_vbs_user" },"name":'+userName+',"password":password} }},"scope":{"project":{ "domain":{"name":new_vbs_user},"name":"MOS" }}}}'
	conn.request("POST",path,data, headers)
	resp = conn.getresponse()
	resp_headers = {}
	for header, value in resp.getheaders():
		resp_headers[header.lower()] = value
	token = resp_headers.get('x-subject-token')
	body=resp.read()
	body_json = json.loads(body)
	projectid = body_json["token"]["project"]["id"]
	domainid = body_json["token"]["project"]["domain"]["id"]
	userid =  body_json["token"]["user"]["id"]
	str= userid+','+projectid+','+token+','+domainid+"\n"
	print str
	file.write(str)