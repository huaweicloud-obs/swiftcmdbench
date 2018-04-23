#!/usr/bin/python
# -*- coding:utf-8 -*-
import os
import httplib
import logging
import sys
import json
try:
    import ssl
except ImportError:
    logging.warning('import ssl module error')

IAM_HOST = '8.42.93.60:9443'
ADMIN_DOMAIN = 'op_service'
ADMIN_BSS_USERNAME = 'bssadmin_iam'
ADMIN_BSS_PASSWORD = 'Test1234'
USER_FILE = 'users.dat'


##############################################################################################################
httplib.HTTPSConnection.debuglevel = 0
_GLOBAL_DEFAULT_TIMEOUT=80
Console_LogLevel = None
def initLocalLogging():
    global Console_LogLevel
    global logging
    LogFile_LogLevel = logging.DEBUG
    Console_LogLevel = logging.INFO
    LogFile = str(__file__) +'.log' #logfile path
    logging.basicConfig(level=LogFile_LogLevel,
                format='%(asctime)s %(filename)s[line:%(lineno)d] [%(thread)d] [%(levelname)s] %(message)s',
                filename=LogFile,
                filemode='a')
    logging.error('logging level: %s', logging.getLevelName(LogFile_LogLevel))

class RestRequest:
    def __init__(self):
        self.httpClient = HttpClient(IAM_HOST)

    def BatchCreateUserOrGetToken(self, prefix, numbers, password='Huawei@123', isOwnerUser='True',projectname = 'MOS'):
        self.BSSToken = self.getToken(ADMIN_DOMAIN, ADMIN_BSS_USERNAME, ADMIN_BSS_PASSWORD)
        userTokenList=[]
        for i in range(1,int(numbers)+1):
            domainName = 'domain'+prefix+'%06d'%(i)
            userName = "user"+prefix+'%06d'%(i)
            userTokenList.append(self.CreateUserWithTokenOrRefreshToken(domainName,userName,password,isOwnerUser,projectname=projectname))
        self.recordTokenList(userTokenList)

    def BatchGetVirtualIamToken(self,userStart,userEnd):
        projectname ='MOS'
        password = 'Huawei@123'
        userTokenList=[]
        for i in range(int(userStart),int(userEnd)):
            userName='UDSIAMSTUBTEST%06d'%(i)
            domainName = 'new_vbs_user'
            userTokenList.append(self.getToken(domainName,userName,password=password,projectname=projectname))
        self.recordTokenList(userTokenList)

    def CreateUserWithTokenOrRefreshToken(self, domainName, username, password='Huawei@123', isOwnerUser='True',projectname = 'MOS'):
        domainId= self.queryDomainByName(domainName)
        if domainId is None:
            resp_status, resp_headers, resp_body = self.createDomain(domainName)
            if resp_status == 201:
                domainId = json.loads(resp_body)['id']
            else:
                logging.error("Create domain error, domainName:%s, errorMsg:%s" % (domainName, resp_body))
                return None
        userId = self.queryUserByName(domainId,username)
        if userId is None:
            resp_status, resp_headers, resp_body = self.createUser(domainId, username, password, isOwnerUser)
            if resp_status == 201:
                userId = json.loads(resp_body)['user']['id']
            else:
                logging.error("Create user error, domainName:%s, username:%s, password:%s, errorMsg:%s" % (domainName, username, password, resp_body))
                return None
        return self.getToken(domainName,username,password,projectname)
    def GetUserToken(self,username,domainname=None,password='Huawei@123',projectname='MOS'):
        if domainname is None:
            domainname = str(username).replace('user','domain')
        return self.getToken(domainname,username,password=password,projectname=projectname)
    def createDomain(self, domainName, domainType='TSI', enabled=True):
        headers = self.__geneCommonHeaders__(self.BSSToken)
        body = self.__geneDomainBody__(domainName, xdomainType=domainType, enabled=enabled)
        return self.httpClient.request('POST', "/v3-huawei/domain", body=body, headers=headers)

    def queryDomainByName(self, domainName):
        #return True if the domain exist else return False
        headers = self.__geneCommonHeaders__(self.BSSToken)
        resp_status, resp_headers, resp_body = self.httpClient.request('GET', "/v3-huawei/domain?Name=" + domainName, headers=headers)
        if resp_status ==200:
            return json.loads(resp_body)['domain']['id']
        return None

    def createUser(self, domainId, username, password, isDomainOwner):
        headers = self.__geneCommonHeaders__(self.BSSToken)
        body = self.__geneUserBody__(domainId, username, password, self.__toBool__(isDomainOwner))
        return HttpClient(IAM_HOST).request('POST', "/v3-huawei/users", body=body, headers=headers)

    def queryUserByName(self, domainId, username):
         #return True if the USER exist else return False
        headers = self.__geneCommonHeaders__(self.BSSToken)
        resp_status, resp_headers, resp_body = self.httpClient.request('GET', "/v3-huawei/users?domain_id=%s&name=%s" % (domainId, username), headers=headers)
        if resp_status ==200:
            respjson= json.loads(resp_body)
            if len(respjson.get('users'))>0:
                return respjson['users'][0]['id']
            return None
        return None

#功能单一 只做获取token 并返回的功能？ 把记录结果放到上层?
    def getToken(self, domainName, username, password,projectname=None):
        headers = self.__geneCommonHeaders__()
        body = self.__geneTokenBody__(domainName, username, password,projectname=projectname)
        resp_status, resp_headers, resp_body = HttpClient(IAM_HOST).request('POST', "/v3/auth/tokens", body=body, headers=headers)
        token = dict(resp_headers)['x-subject-token']
        if projectname is None:
            return token
        else:
            body_json=json.loads(resp_body)
            projectid = body_json["token"]["project"]["id"]
            domainid = body_json["token"]["project"]["domain"]["id"]
            userid =  body_json["token"]["user"]["id"]
            return username,projectid,token,domainid

    def recordTokenList(self,userTokenList):
        if USER_FILE == '': return
        userFile = open(USER_FILE, 'w')
        for userTokenInfo in userTokenList:
            userFile.writelines('%s,%s,%s,%s,\n' % (userTokenInfo[0],userTokenInfo[1],userTokenInfo[2],userTokenInfo[3]))
            print "%s,%s,%s,%s" % (userTokenInfo[0],userTokenInfo[1],userTokenInfo[2],userTokenInfo[3])
        userFile.close()

    def recordSingleToken(self,userid,projectid,token,domainid):
        if USER_FILE == '': return
        userFile = open(USER_FILE, 'a')
        userFile.writelines('%s,%s,%s,%s,\n' % (userid,projectid,token,domainid))
        userFile.close()
        print "%s,%s,%s,%s" % (userid,projectid,token,domainid)

    def __geneTokenBody__(self, domainName, username, password,projectname=None):
        if projectname is  None:
            body = {"auth":{"identity":{"methods":["password"],"password":{"user":{"name":username,"password":password,"domain":{"name":domainName}}}},"scope":{"domain":{"name":domainName}}}}
        else:
            body = {"auth":{"identity":{"methods":["password"],"password":{"user":{"name":username,"password":password,"domain":{"name":domainName}}}},"scope":{"project":{"domain":{"name":domainName},"name":projectname}}}}
        return json.dumps(body)

    def __geneDomainBody__(self, domainName, xdomainType='TSI', enabled=True):
        import uuid
        xdomainId = str(uuid.uuid4()).replace('-', '')
        body = {"domain":{"name":domainName, "xdomain_id":xdomainId, "xdomain_type":xdomainType, "enabled":enabled}}
        return json.dumps(body)

    def __geneUserBody__(self, domainId, username, password, isDomainOwner=False, enabled=True):
        body = {"user":{"domain_id":domainId, "name":username, "password":password, "is_domain_owner":isDomainOwner, "enabled":enabled}}
        return json.dumps(body)

    def __geneCommonHeaders__(self, token=None):
        headers = {"Content-Type":"application/json;charset=utf8"}
        if token:
            headers['X-Auth-Token'] = token
        return headers

    def __toBool__(self, boolStr):
        if boolStr.lower() == 'true':
            return True
        else:
            return False


class HttpClient:
    def __init__(self, host):
        self.server = host.split(':')[0]
        self.port = host.split(':')[1]
        self.conn = httplib.HTTPSConnection(self.server, self.port, context=ssl._create_unverified_context())

    def request(self, method, url, body=None, headers={}):
        resp_status = -1
        resp_headers = {}
        resp_body = None
        try:
            self.conn.request(method, url, body, headers)
            response = self.conn.getresponse()
            resp_status = response.status
            resp_headers = response.getheaders()
            resp_body = response.read()
        finally:
            self.conn.close()
        return resp_status, resp_headers, resp_body

def _print_usage_(action=None):
    print script_version
    print 'Usage:'
    UsageList = []
    tmpDict = {}
    if action:
        tmpDict.setdefault(action, ActionDict[action])
    else:
        tmpDict = ActionDict
    for x, y in tmpDict.iteritems():
        opUsg = '    python ' + os.path.basename(__file__) + ' --Action=' + x
        for i in range(1, y[0] + 1):
            opUsg += ' --' + y[i] + '=*'
        for i in range(y[0] + 1, len(y)):
            opUsg += ' [--' + y[i] + '=*]'
        UsageList.append(opUsg)
    UsageList.sort()
    for element in UsageList:
        print(element)
    print "    Tips:"
    print "    1.Batch create 3 users of 3 domains.need configure real IAM ip and port"
    print "      e.x.:python swiftIamTool.py --Action=BatchCreateUserOrGetToken --prefxi=testiam --numbers=3 --password=Huawei@123 --projectname=rg"
    print "      swift if you want get token with catalog and endpoint you need add the real projectname "
    print "      domaintestiam1,2,3 and usertestiam1,2,3 will be create usertoken saved in users.dat"
    print "    2.Batch get 100 users Token from virtual IAM ;need configure virtual IAM IP and port"
    print "      e.x.:python swiftIamTool.py --Action=BatchGetVirtualIamToken --userStart=100 --userEnd=200"
    print "      usertoken saved in users.dat"

ActionDict = {"BatchCreateUserOrGetToken" : [2, "prefix", "numbers", "password", "isOwnerUser","projectname"],
              "BatchGetVirtualIamToken":[2,"userStart","userEnd"]
              }
script_version = '\033[0;33;40m%s\033[0m' % ('****************************************' + os.path.basename(__file__) + ' v20170706 ****************************************')
if __name__ == '__main__':
    # init Logging
    initLocalLogging()
    #rest = RestRequest()
    #rest.BatchCreateUserOrGetToken('abc',3,projectname='rg')
    params = {}
    for arg in sys.argv[1:]:
        if arg.startswith('--') and arg.find('=') != -1:
            params[arg.split('=')[0][2:]] = arg[len(arg.split('=')[0]) + 1:]

    if 'Action' not in params.keys() or params['Action'] not in ActionDict.keys():
        print 'No action specified, exit'
        _print_usage_(None)
        sys.exit()

    options = ActionDict[params['Action']]
    for i in range(1, options[0] + 1):
        if options[i] not in params.keys():
            _print_usage_(params['Action'])
            sys.exit()

    rest = RestRequest()
    actionName = params.pop('Action')
    if actionName == 'BatchCreateUserOrGetToken':
        apply(rest.BatchCreateUserOrGetToken, (), params)
    elif actionName == 'BatchGetVirtualIamToken':
        apply(rest.BatchGetVirtualIamToken, (), params)
    else:
        print "Unknown action name:%s" % actionName
