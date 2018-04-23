#!/usr/bin/python
# -*- coding:utf-8 -*- 
import sys
import os
import time
import math
import random
import logging
import logging.config
import datetime
import hashlib
import base64
import multiprocessing
import results
import Util
import s3PyCmd
import myLib.cloghandler


class User:
    doc = """
        This is user class
    """

    def __init__(self, username, ak, sk):
        self.username = username
        self.ak = ak
        self.sk = sk


def read_config(config_file='config.dat'):
    """
    :rtype : None
    :param config_file: string
    """
    try:
        f = open(config_file, 'r')
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line and line[0] != '#':
                CONFIG[line[:line.find('=')].strip()] = line[line.find('=') + 1:].strip()
            else:
                continue
        f.close()
        CONFIG['OSCs'] = CONFIG['OSCs'].replace(' ', '').replace(',,', ',')
        if CONFIG['OSCs'][-1:] == ',':
            CONFIG['OSCs'] = CONFIG['OSCs'][:-1]
        if CONFIG['IsHTTPs'].lower() == 'true':
            CONFIG['IsHTTPs'] = True
        else:
            CONFIG['IsHTTPs'] = False
        CONFIG['ConnectTimeout'] = int(CONFIG['ConnectTimeout'])
        if int(CONFIG['ConnectTimeout']) < 5:
            CONFIG['ConnectTimeout'] = 5
        if CONFIG['LongConnection'].lower() == 'true':
            CONFIG['LongConnection'] = True
        else:
            CONFIG['LongConnection'] = False
        if CONFIG['UseDomainName'].lower() == 'true':
            CONFIG['UseDomainName'] = True
            # 如果使用域名，则OSCs为域名
            CONFIG['OSCs'] = CONFIG['DomainName']
        else:
            CONFIG['UseDomainName'] = False
        if CONFIG['VirtualHost'].lower() == 'true':
            CONFIG['VirtualHost'] = True
        else:
            CONFIG['VirtualHost'] = False
        if CONFIG['ObjectLexical'].lower() == 'true':
            CONFIG['ObjectLexical'] = True
        else:
            CONFIG['ObjectLexical'] = False
        if CONFIG['CalHashMD5'].lower() == 'true':
            CONFIG['CalHashMD5'] = True
        else:
            CONFIG['CalHashMD5'] = False
        CONFIG['Testcase'] = int(CONFIG['Testcase'])
        CONFIG['Users'] = int(CONFIG['Users'])
        CONFIG['UserStartIndex'] = int(CONFIG['UserStartIndex'])
        CONFIG['ThreadsPerUser'] = int(CONFIG['ThreadsPerUser'])
        CONFIG['Threads'] = CONFIG['Users'] * CONFIG['ThreadsPerUser']
        CONFIG['RequestsPerThread'] = int(CONFIG['RequestsPerThread'])
        CONFIG['BucketsPerUser'] = int(CONFIG['BucketsPerUser'])
        if CONFIG['copyDstObjFiexed'] and '/' not in CONFIG['copyDstObjFiexed']:
            CONFIG['copyDstObjFiexed'] = ''
        if CONFIG['copySrcObjFixed'] and '/' not in CONFIG['copySrcObjFixed']:
            CONFIG['copySrcObjFixed'] = ''
        CONFIG['ObjectsPerBucketPerThread'] = int(CONFIG['ObjectsPerBucketPerThread'])
        CONFIG['DeleteObjectsPerRequest'] = int(CONFIG['DeleteObjectsPerRequest'])
        CONFIG['PartsForEachUploadID'] = int(CONFIG['PartsForEachUploadID'])
        if CONFIG['ConcurrentUpParts'].lower() == 'true':
            CONFIG['ConcurrentUpParts'] = True
            if CONFIG['PartsForEachUploadID'] % CONFIG['ThreadsPerUser']:
                if CONFIG['PartsForEachUploadID'] < CONFIG['ThreadsPerUser']:
                    CONFIG['PartsForEachUploadID'] = CONFIG['ThreadsPerUser']
                else:
                    CONFIG['PartsForEachUploadID'] = int(
                        round(1.0 * CONFIG['PartsForEachUploadID'] / CONFIG['ThreadsPerUser']) * CONFIG[
                            'ThreadsPerUser'])
                logging.info('change PartsForEachUploadID to %d' % CONFIG['PartsForEachUploadID'])
        else:
            CONFIG['ConcurrentUpParts'] = False

        CONFIG['PutTimesForOneObj'] = int(CONFIG['PutTimesForOneObj'])
        CONFIG['MixLoopCount'] = int(CONFIG['MixLoopCount'])
        if CONFIG['RunSeconds']:
            CONFIG['RunSeconds'] = int(CONFIG['RunSeconds'])
        if CONFIG['RecordDetails'].lower() == 'true':
            CONFIG['RecordDetails'] = True
        else:
            CONFIG['RecordDetails'] = False
        CONFIG['StatisticsInterval'] = int(CONFIG['StatisticsInterval'])
        if CONFIG['BadRequestCounted'].lower() == 'true':
            CONFIG['BadRequestCounted'] = True
        else:
            CONFIG['BadRequestCounted'] = False
        if CONFIG['AvoidSinBkOp'].lower() == 'true':
            CONFIG['AvoidSinBkOp'] = True
        else:
            CONFIG['AvoidSinBkOp'] = False
        if CONFIG['PrintProgress'].lower() == 'true':
            CONFIG['PrintProgress'] = True
        else:
            CONFIG['PrintProgress'] = False
        if not ('processID' in CONFIG['ObjectNamePartten'] and 'ObjectNamePrefix' in CONFIG[
            'ObjectNamePartten'] and 'Index' in CONFIG['ObjectNamePartten']):
            raise Exception('both of processID,Index,ObjectNamePartten should be in config ObjectNamePartten')
    except Exception, e:
        print '[ERROR] Read config file %s error: %s' % (config_file, e)
        sys.exit()


def read_users():
    """
    load users.dat 
    """
    global USERS, CONFIG
    index = -1
    try:
        with open('./users.dat', 'r') as fd:
            for line in fd:
                if not line:
                    continue
                index += 1
                if index >= CONFIG['UserStartIndex'] and len(USERS) <= CONFIG['Users']:
                    user_info = line.strip()
                    user = User(user_info.split(',')[0], user_info.split(',')[1], user_info.split(',')[2])
                    USERS.append(user)
            fd.close()
        logging.debug("load user file end")
    except Exception, data:
        print "\033[1;31;40m[ERROR]\033[0m Load users Error, check file users.dat. Use iamPyTool.py to create users [%r]" % (
            data)
        logging.error(
            'Load users Error, check file users.dat. Use iamPyTool.py to create users')
        sys.exit()


def list_user_buckets(process_id, user, conn, result_queue):
    request_type = 'ListUserBuckets'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    i = 0
    while i < CONFIG['RequestsPerThread']:
        i += 1
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
def swiftlist_user_containers(process_id, user, conn, result_queue):
    request_type = 'swiftListUserContainers'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk)
    rest.headers['X-auth-token'] = user.sk
    i = 0
    while i < CONFIG['RequestsPerThread']:
        i += 1
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
def swiftcreate_container(process_id, user, conn, result_queue):
    request_type = 'swiftCreateContainer'
    sendContent = ''
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak = user.ak, sk = user.sk, send_content = sendContent)
    rest.headers['X-auth-token'] = user.sk
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
	    #rest.bucket = '%s.%d' % (CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
def swifthead_container(process_id, user, conn, result_queue):
    request_type = 'swiftHeadContainer'
    sendContent = ''
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak = user.ak, sk = user.sk, send_content = sendContent)
    rest.headers['X-auth-token'] = user.sk
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
def create_bucket(process_id, user, conn, result_queue):
    request_type = 'CreateBucket'
    send_content = ''
    if CONFIG['BucketLocation']:
        send_content = '<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\
        <LocationConstraint>%s</LocationConstraint></CreateBucketConfiguration >' % random.choice(
            CONFIG['BucketLocation'].split(','))
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], send_content=send_content,
                                       virtual_host=CONFIG['VirtualHost'], domain_name=CONFIG['DomainName'],
                                       region=CONFIG['Region'])
    if CONFIG['CreateWithACL']:
        rest.headers['x-amz-acl'] = CONFIG['CreateWithACL']
    if CONFIG['MDCPolicy']:
        rest.headers['x-hws-mdc-storage-policy'] = CONFIG['MDCPolicy']
    if CONFIG['StorageClass']:
        rest.headers['x-default-storage-class'] = CONFIG['StorageClass']
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))

def swiftlist_objects_in_container(process_id, user, conn, result_queue):
    request_type = 'swiftListObjectsInContainer'
    rest = s3PyCmd.S3RequestDescriptor(request_type,  ak = user.ak, sk = user.sk)
    rest.headers['X-auth-token'] = user.sk
    rest.queryArgs['limit'] = CONFIG['Max-keys']
    i = 0
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i = i + 1
	marker = ''
        while marker != None:
            rest.queryArgs['marker'] = marker
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            marker = resp.return_data
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))

def list_objects_in_bucket(process_id, user, conn, result_queue):
    request_type = 'ListObjectsInBucket'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['max-keys'] = CONFIG['Max-keys']
    i = 0
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        marker = ''
        while marker is not None:
            rest.queryArgs['marker'] = marker
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            marker = resp.return_data
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def head_bucket(process_id, user, conn, result_queue):
    request_type = 'HeadBucket'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))

def swiftdelete_container(process_id, user, conn, result_queue):
    request_type = 'swiftDeleteContainer'
    sendContent = ''
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak = user.ak, sk = user.sk, send_content = sendContent)
    rest.headers['X-auth-token'] = user.sk
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
def delete_bucket(process_id, user, conn, result_queue):
    request_type = 'DeleteBucket'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def bucket_delete(process_id, user, conn, result_queue):
    request_type = 'BucketDelete'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['deletebucket'] = None
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        rest.sendContent = '<?xml version="1.0" encoding="UTF-8"?><DeleteBucket><Bucket>' + rest.bucket + '</Bucket></DeleteBucket>'
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def options_bucket(process_id, user, conn, result_queue):
    request_type = 'OPTIONSBucket'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.headers['Access-Control-Request-Method'] = 'GET'
    rest.headers['Origin'] = CONFIG['DomainName']
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def put_bucket_versioning(process_id, user, conn, result_queue):
    request_type = 'PutBucketVersioning'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk, auth_algorithm=CONFIG['AuthAlgorithm'],
                                       virtual_host=CONFIG['VirtualHost'], domain_name=CONFIG['DomainName'],
                                       region=CONFIG['Region'])
    rest.queryArgs['versioning'] = None
    rest.sendContent = '<VersioningConfiguration><Status>%s</Status></VersioningConfiguration>' % CONFIG[
        'VersionStatus']
    rest.headers['Content-MD5'] = base64.b64encode(hashlib.md5(rest.sendContent).digest())
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
            logging.info('bucket:' + rest.bucket)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def get_bucket_versioning(process_id, user, conn, result_queue):
    request_type = 'GetBucketVersioning'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['versioning'] = None
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def put_bucket_website(process_id, user, conn, result_queue):
    request_type = 'PutBucketWebsite'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['website'] = None
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        rest.sendContent = '<WebsiteConfiguration><RedirectAllRequestsTo><HostName>' + CONFIG[
            'RedirectHostName'] + '</HostName></RedirectAllRequestsTo></WebsiteConfiguration>'
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def get_bucket_website(process_id, user, conn, result_queue):
    request_type = 'GetBucketWebsite'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['website'] = None
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def delete_bucket_website(process_id, user, conn, result_queue):
    request_type = 'DeleteBucketWebsite'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['website'] = None
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        rest.sendContent = '<WebsiteConfiguration><RedirectAllRequestsTo><HostName>' + CONFIG[
            'RedirectHostName'] + '</HostName></RedirectAllRequestsTo></WebsiteConfiguration>'
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def put_bucket_cors(process_id, user, conn, result_queue):
    request_type = 'PutBucketCORS'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['cors'] = None
    rest.sendContent = '<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>%s</AllowedOrigin></CORSRule></CORSConfiguration>' % \
                       CONFIG['DomainName']
    rest.headers['Content-MD5'] = base64.b64encode(hashlib.md5(rest.sendContent).digest())
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def get_bucket_cors(process_id, user, conn, result_queue):
    request_type = 'GetBucketCORS'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['cors'] = None
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def delete_bucket_cors(process_id, user, conn, result_queue):
    request_type = 'DeleteBucketCORS'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['cors'] = None
    i = process_id % CONFIG['ThreadsPerUser']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += CONFIG['ThreadsPerUser']
        rest.sendContent = '<WebsiteConfiguration><RedirectAllRequestsTo><HostName>' + CONFIG[
            'RedirectHostName'] + '</HostName></RedirectAllRequestsTo></WebsiteConfiguration>'
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def put_object(process_id, user, conn, result_queue):
    request_type = 'PutObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.headers['content-type'] = 'application/octet-stream'
    if CONFIG['PutWithACL']:
        rest.headers['x-amz-acl'] = CONFIG['PutWithACL']
    fixed_size = False
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
        rest.headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
    elif CONFIG['SrvSideEncryptType'].lower() == 'sse-kms' and CONFIG['SrvSideEncryptAlgorithm'].lower() == 'aws:kms':
        rest.headers['x-amz-server-side-encryption'] = 'aws:kms'
        if CONFIG['SrvSideEncryptAWSKMSKeyId']:
            rest.headers['x-amz-server-side-encryption-aws-kms-key-id'] = CONFIG['SrvSideEncryptAWSKMSKeyId']
        if CONFIG['SrvSideEncryptContext']:
            rest.headers['x-amz-server-side-encryption-context'] = CONFIG['SrvSideEncryptContext']
    elif CONFIG['SrvSideEncryptType'].lower() == 'sse-kms' and CONFIG['SrvSideEncryptAlgorithm'].lower() == 'aes256':
        rest.headers['x-amz-server-side-encryption'] = 'AES256'

    # 如果打开CalHashMD5开关，在对象上传时写入一个自定义元数据，用于标记为本工具put上传的对象。
    if CONFIG['CalHashMD5']:
        rest.headers['x-amz-meta-md5written'] = 'yes'
    # 对象多版本，需要在上传后记录下版本号
    obj_v = ''
    obj_v_file = 'data/objv-%d.dat' % process_id
    open(obj_v_file, 'w').write(obj_v)
    # 错开每个并发起始选桶，避免单桶性能瓶颈。
    range_arr = range(0, CONFIG['BucketsPerUser'])
    if CONFIG['AvoidSinBkOp']:
        range_arr = range(process_id % CONFIG['BucketsPerUser'], CONFIG['BucketsPerUser']) + range(0,
                                                                                                   process_id % CONFIG[
                                                                                                       'BucketsPerUser'])
    for i in range_arr:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                if CONFIG['ObjectLexical']:
                    rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index', str(
                        j)).replace(
                        'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
                else:
                    rest.key = Util.random_string_create(random.randint(300, 1024))
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())
                logging.debug('side-encryption-customer-key: [%r]' % rest.key[-32:].zfill(32))
            j += 1
            put_times_for_one_obj = CONFIG['PutTimesForOneObj']
            while put_times_for_one_obj > 0:
                if not fixed_size:
                    # change size every request for the same obj.
                    rest.contentLength, fixed_size = Util.generate_a_size(CONFIG['ObjectSize'])
                put_times_for_one_obj -= 1
                resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
                result_queue.put(
                    (process_id, user.username, rest.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                     resp.request_id, resp.status))
                if resp.return_data:
                    obj_v += '%s\t%s\t%s\n' % (rest.bucket, rest.key, resp.return_data)
                    # 每1KB，写入对象的versionID到本地文件objv-process_id.dat
                    if len(obj_v) >= 1024:
                        logging.info('write obj_v to file %s' % obj_v_file)
                        open(obj_v_file, 'a').write(obj_v)
                        obj_v = ''
    if obj_v:
        open(obj_v_file, 'a').write(obj_v)

def swiftput_object(process_id, user, conn, result_queue):
    request_type = 'swiftPutObject'
 
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk)
    rest.headers['content-type'] = 'application/octet-stream'
    rest.headers['X-auth-token'] = user.sk
    fixed_size = False
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    # 如果打开CalHashMD5开关，在对象上传时写入一个自定义元数据，用于标记为本工具put上传的对象。
    if CONFIG['CalHashMD5']:
        rest.headers['x-amz-meta-md5written'] = 'yes'
    # 对象多版本，需要在上传后记录下版本号
    obj_v = ''
    obj_v_file = 'data/objv-%d.dat' % process_id
    open(obj_v_file, 'w').write(obj_v)
    # 错开每个并发起始选桶，避免单桶性能瓶颈。
    range_arr = range(0, CONFIG['BucketsPerUser'])
    if CONFIG['AvoidSinBkOp']:
        range_arr = range(process_id % CONFIG['BucketsPerUser'], CONFIG['BucketsPerUser']) + range(0,
                                                                                                   process_id % CONFIG[
                                                                                                       'BucketsPerUser'])

    for i in range_arr:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
#	    rest.bucket = '%s.%d' % (CONFIG['BucketNamePrefix'], i)
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                if CONFIG['ObjectLexical']:
                    rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index', str(
                        j)).replace(
                        'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
                else:
                    rest.key = Util.random_string_create(random.randint(300, 1024))
            j += 1
            put_times_for_one_obj = CONFIG['PutTimesForOneObj']
            while put_times_for_one_obj > 0:
                if not fixed_size:
                    # change size every request for the same obj.
                    rest.contentLength, fixed_size = Util.generate_a_size(CONFIG['ObjectSize'])
                put_times_for_one_obj -= 1
                resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
                result_queue.put(
                    (process_id, user.username, rest.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                     resp.request_id, resp.status))
                if resp.return_data:
                    obj_v += '%s\t%s\t%s\n' % (rest.bucket, rest.key, resp.return_data)
                    # 每1KB，写入对象的versionID到本地文件objv-process_id.dat
                    if len(obj_v) >= 1024:
                        logging.info('write obj_v to file %s' % obj_v_file)
                        open(obj_v_file, 'a').write(obj_v)
                        obj_v = ''
    if obj_v:
        open(obj_v_file, 'a').write(obj_v)

def handle_from_objects(request_type, rest, process_id, user, conn, result_queue):
    """

    :type result_queue: Queue
    """
    global OBJECTS
    objects_per_user = len(OBJECTS) / CONFIG['Threads']
    if objects_per_user == 0:
        if process_id >= len(OBJECTS):
            return
        else:
            start_index = end_index = process_id
    else:
        extra_obj = len(OBJECTS) % CONFIG['Threads']
        if process_id == 0:
            start_index = 0
            end_index = objects_per_user + extra_obj
        else:
            start_index = process_id * objects_per_user + extra_obj
            end_index = start_index + objects_per_user
    while start_index < end_index:
        rest.bucket = OBJECTS[start_index][:OBJECTS[start_index].find('/')]
        rest.key = OBJECTS[start_index][OBJECTS[start_index].find('/') + 1:]
        if CONFIG['Testcase'] in (202,) and CONFIG['Range']:
            rest.headers['Range'] = 'bytes=%s' % random.choice(CONFIG['Range'].split(';')).strip()
        start_index += 1
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
        if CONFIG["Testcase"] in (202,):
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                 resp.request_id, resp.status))
        else:
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def handle_from_obj_v(request_type, obj_v_file, rest, process_id, user, conn, result_queue):
    obj_v_file_read = open(obj_v_file, 'r')
    obj = obj_v_file_read.readline()
    while obj:
        if obj and len(obj.split('\t')) != 3:
            logging.info('obj [%r] format error in file %s' % (obj, obj_v_file))
            continue
        obj = obj[:-1]
        rest.bucket = obj.split('\t')[0]
        rest.key = obj.split('\t')[1]
        if rest.requestType == 'GetObject':
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())
        rest.queryArgs['versionId'] = obj.split('\t')[2]
        obj = obj_v_file_read.readline()
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
             resp.request_id, resp.status))


def get_object(process_id, user, conn, result_queue):
    request_type = 'GetObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
        rest.headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
    if CONFIG['Testcase'] in (202, 900) and CONFIG['Range']:
        rest.headers['Range'] = 'bytes=%s' % random.choice(CONFIG['Range'].split(';')).strip()
    # 如果传入OBJECTS，则直接处理OBJECTS。
    global OBJECTS
    if OBJECTS:
        handle_from_objects(request_type, rest, process_id, user, conn, result_queue)
        return

    # 如果data下有上传记录的对象名和版本，从该文件读。
    obj_v_file = 'data/objv-%d.dat' % process_id
    if os.path.exists(obj_v_file) and os.path.getsize(obj_v_file) > 0:
        handle_from_obj_v(request_type, obj_v_file, rest, process_id, user, conn, result_queue)
        return

    # 从字典序对象名下载。
    if not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return
    i = 0
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if CONFIG['Range']:
                rest.headers['Range'] = 'bytes=%s' % random.choice(CONFIG['Range'].split(';')).strip()
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())

            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(CONFIG['CalHashMD5'])
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                 resp.request_id, resp.status))
def swiftget_object(process_id, user, conn, result_queue):
    request_type = 'swiftGetObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type =request_type, ak = user.ak, sk = user.sk)
    rest.headers['X-auth-token'] = user.sk
    if CONFIG['Testcase'] in (202, 900) and CONFIG['Range']:
        rest.headers['Range'] = 'bytes=%s' % random.choice(CONFIG['Range'].split(';')).strip()
    global OBJECTS
    if OBJECTS:
        handle_from_objects(request_type, rest, process_id, user, conn, result_queue)
        return

    # 如果data下有上传记录的对象名和版本，从该文件读。
    obj_v_file = 'data/objv-%d.dat' % process_id
    if os.path.exists(obj_v_file) and os.path.getsize(obj_v_file) > 0:
        handle_from_obj_v(request_type, obj_v_file, rest, process_id, user, conn, result_queue)
        return

    # 从字典序对象名下载。
    if not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return
    i = 0
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if CONFIG['Range']:
                rest.headers['Range'] = 'bytes=%s' % random.choice(CONFIG['Range'].split(';')).strip()
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())

            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(CONFIG['CalHashMD5'])
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                 resp.request_id, resp.status))

def swifthead_object(process_id, user, conn, result_queue):
    request_type = 'swiftHeadObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk)
    rest.headers['X-auth-token'] = user.sk
    # 如果传入OBJECTS，则直接处理OBJECTS。
    global OBJECTS
    if OBJECTS:
        handle_from_objects(request_type, rest, process_id, user, conn, result_queue)
        return

    elif not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return
    i = 0
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))

def head_object(process_id, user, conn, result_queue):
    request_type = 'HeadObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    # 如果传入OBJECTS，则直接处理OBJECTS。
    global OBJECTS
    if OBJECTS:
        handle_from_objects(request_type, rest, process_id, user, conn, result_queue)
        return

    elif not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return
    i = 0
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
        rest.headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())

            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def delete_object(process_id, user, conn, result_queue):
    request_type = 'DeleteObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])

    # 如果传入OBJECTS，则直接处理OBJECTS。
    global OBJECTS
    if OBJECTS:
        handle_from_objects(request_type, rest, process_id, user, conn, result_queue)
        return

    # 如果data下有上传记录的对象名和版本，从该文件读。
    obj_v_file = 'data/objv-%d.dat' % process_id
    if os.path.exists(obj_v_file) and os.path.getsize(obj_v_file) > 0:
        handle_from_obj_v(request_type, obj_v_file, rest, process_id, user, conn, result_queue)
        return

    elif not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return

    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    range_arr = range(0, CONFIG['BucketsPerUser'])
    # 错开每个并发起始选桶，避免单桶性能瓶颈。
    if CONFIG['AvoidSinBkOp']:
        range_arr = range(process_id % CONFIG['BucketsPerUser'], CONFIG['BucketsPerUser']) + range(0,
                                                                                                   process_id % CONFIG[
                                                                                                       'BucketsPerUser'])
    for i in range_arr:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))

def swiftdelete_object(process_id, user, conn, result_queue):
    request_type = 'swiftDeleteObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk)
    rest.headers['X-auth-token'] = user.sk
    # 如果传入OBJECTS，则直接处理OBJECTS。
    global OBJECTS
    if OBJECTS:
        handle_from_objects(request_type, rest, process_id, user, conn, result_queue)
        return

    # 如果data下有上传记录的对象名和版本，从该文件读。
    obj_v_file = 'data/objv-%d.dat' % process_id
    if os.path.exists(obj_v_file) and os.path.getsize(obj_v_file) > 0:
        handle_from_obj_v(request_type, obj_v_file, rest, process_id, user, conn, result_queue)
        return

    elif not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return

    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    range_arr = range(0, CONFIG['BucketsPerUser'])
    # 错开每个并发起始选桶，避免单桶性能瓶颈。
    if CONFIG['AvoidSinBkOp']:
        range_arr = range(process_id % CONFIG['BucketsPerUser'], CONFIG['BucketsPerUser']) + range(0,
                                                                                                   process_id % CONFIG[
                                                                                                       'BucketsPerUser'])
    for i in range_arr:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
#	    rest.bucket = '%s.%d' % (CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
def restore_object(process_id, user, conn, result_queue):
    request_type = 'RestoreObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])

    # 如果传入OBJECTS，则直接处理OBJECTS。
    global OBJECTS
    if OBJECTS:
        handle_from_objects(request_type, rest, process_id, user, conn, result_queue)
        return

    # 如果data下有上传记录的对象名和版本，从该文件读。
    obj_v_file = 'data/objv-%d.dat' % process_id
    if os.path.exists(obj_v_file) and os.path.getsize(obj_v_file) > 0:
        handle_from_obj_v(request_type, obj_v_file, rest, process_id, user, conn, result_queue)
        return

    elif not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return

    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    rest.queryArgs['restore'] = None
    range_arr = range(0, CONFIG['BucketsPerUser'])
    # 错开每个并发起始选桶，避免单桶性能瓶颈。
    if CONFIG['AvoidSinBkOp']:
        range_arr = range(process_id % CONFIG['BucketsPerUser'], CONFIG['BucketsPerUser']) + range(0,
                                                                                                   process_id % CONFIG[
                                                                                                       'BucketsPerUser'])
    for i in range_arr:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            rest.sendContent = '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-3-01"><Days>%s</Days><GlacierJobParameters><Tier>%s</Tier></GlacierJobParameters></RestoreRequest>' % (
            CONFIG['RestoreDays'], CONFIG['RestoreTier'])
            logging.debug('send content [%s] ' % rest.sendContent)
            rest.headers['Content-MD5'] = base64.b64encode(hashlib.md5(rest.sendContent).digest())
            j += 1
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def delete_multi_objects(process_id, user, conn, result_queue):
    if not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return
    if CONFIG['ObjectsPerBucketPerThread'] <= 0:
        logging.warn('ObjectsPerBucketPerThread <= 0, exit..')
        return
    request_type = 'DeleteMultiObjects'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['delete'] = None
    i = 0
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        delete_times_per_bucket = math.ceil(
            CONFIG['ObjectsPerBucketPerThread'] * 1.0 / CONFIG['DeleteObjectsPerRequest'])
        logging.debug('ObjectsPerBucketPerThread: %d, DeleteObjectsPerRequest: %d, delete_times_per_bucket:%d' % (
            CONFIG['ObjectsPerBucketPerThread'], CONFIG['DeleteObjectsPerRequest'], delete_times_per_bucket))
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            rest.sendContent = '<Delete>'
            k = 0
            while k < CONFIG['DeleteObjectsPerRequest']:
                if j >= CONFIG['ObjectsPerBucketPerThread']:
                    break
                rest.sendContent += '<Object><Key>%s</Key></Object>' % CONFIG['ObjectNamePartten'].replace('processID', str( process_id)).replace(
                    'Index', str(j)).replace('ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
                j += 1
                k += 1
            rest.sendContent += '</Delete>'
            logging.debug('send content [%s] ' % rest.sendContent)
            rest.headers['Content-MD5'] = base64.b64encode(hashlib.md5(rest.sendContent).digest())
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))

def swiftupload_dynamic_big_object(process_id, user, conn, result_queue):
    request_type = 'swiftUploadDynamicBigObject'
    sendContent = ''
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak = user.ak, sk = user.sk, send_content = sendContent)
    rest.headers['X-auth-token'] = user.sk
    fixed_size = False
    rest.headers['content-type'] = 'application/octet-stream'
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.prefixkey = CONFIG['ObjectNameFixed']
    # 如果打开CalHashMD5开关，在对象上传时写入一个自定义元数据，用于标记为本工具put上传的对象。
    if CONFIG['CalHashMD5']:
        rest.headers['x-amz-meta-md5written'] = 'yes'
    # 错开每个并发起始选桶，避免单桶性能瓶颈。
    range_arr = range(0, CONFIG['BucketsPerUser'])
    if CONFIG['AvoidSinBkOp']:
        range_arr = range(process_id % CONFIG['BucketsPerUser'], CONFIG['BucketsPerUser']) + range(0,process_id % CONFIG['BucketsPerUser'])
    for i in range_arr:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                if CONFIG['ObjectLexical']:
                    rest.prefixkey = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index', str(
                        j)).replace('ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
                else:
                    rest.prefixkey = Util.random_string_create(random.randint(300, 1024))
            j += 1
            parts_for_dynamic_big = CONFIG['PartsForEachUploadID']
            for k in range(1,parts_for_dynamic_big+1):
                if not fixed_size:
                    # change size every request for the same obj.
                    rest.contentLength, fixed_size = Util.generate_a_size(CONFIG['PartSize'])
                rest.key = '%s-%d'%(rest.prefixkey,k)
                resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
                result_queue.put(
                    (process_id, user.username, rest.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                     resp.request_id, resp.status))
            rest.key = rest.prefixkey
            rest.headers['x-object-manifest'] = ('%s/%s'%(rest.bucket, rest.key))
            partContentLength = rest.contentLength
            rest.contentLength=0
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
            result_queue.put(
                    (process_id, user.username, rest.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                     resp.request_id, resp.status))
            rest.headers.pop('x-object-manifest')
            rest.contentLength = partContentLength
def swiftdelete_dynamic_big_object(process_id, user, conn, result_queue):
    request_type = 'swiftDeleteDynamicBigObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak = user.ak, sk = user.sk)
    rest.headers['X-auth-token'] = user.sk
    fixed_size = False
    rest.headers['content-type'] = 'application/octet-stream'
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.prefixkey = CONFIG['ObjectNameFixed']
    # 如果打开CalHashMD5开关，在对象上传时写入一个自定义元数据，用于标记为本工具put上传的对象。
    if CONFIG['CalHashMD5']:
        rest.headers['x-amz-meta-md5written'] = 'yes'
    # 错开每个并发起始选桶，避免单桶性能瓶颈。
    range_arr = range(0, CONFIG['BucketsPerUser'])
    if CONFIG['AvoidSinBkOp']:
        range_arr = range(process_id % CONFIG['BucketsPerUser'], CONFIG['BucketsPerUser']) + range(0,process_id % CONFIG['BucketsPerUser'])
    for i in range_arr:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                if CONFIG['ObjectLexical']:
                    rest.prefixkey = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index', str(
                        j)).replace('ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
                else:
                    rest.prefixkey = Util.random_string_create(random.randint(300, 1024))
            j += 1
            parts_for_dynamic_big = CONFIG['PartsForEachUploadID']
            for k in range(1,parts_for_dynamic_big+1):
                rest.key = '%s-%d'%(rest.prefixkey,k)
                resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
                result_queue.put(
                    (process_id, user.username, rest.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                     resp.request_id, resp.status))
            rest.key = rest.prefixkey
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
            result_queue.put(
                    (process_id, user.username, rest.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                     resp.request_id, resp.status))
def copy_object(process_id, user, conn, result_queue):
    if not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return
    request_type = 'CopyObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.headers['x-amz-acl'] = 'public-read-write'
    rest.headers['x-amz-metadata-directive'] = 'COPY'
    if CONFIG['copySrcObjFixed']:
        rest.headers['x-amz-copy-source'] = '/' + CONFIG['copySrcObjFixed']
    if CONFIG['copyDstObjFiexed']:
        rest.bucket = CONFIG['copyDstObjFiexed'].split('/')[0]
        rest.key = CONFIG['copyDstObjFiexed'].split('/')[1]
    elif CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
        rest.headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
    if CONFIG['copySrcSrvSideEncryptType'].lower() == 'sse-c':
        rest.headers['x-amz-copy-source-server-side-encryption-customer-algorithm'] = 'AES256'
    if CONFIG['SrvSideEncryptType'].lower() == 'sse-kms' and CONFIG['SrvSideEncryptAlgorithm'].lower() == 'aws:kms':
        rest.headers['x-amz-server-side-encryption'] = 'aws:kms'
        if CONFIG['SrvSideEncryptAWSKMSKeyId']:
            rest.headers['x-amz-server-side-encryption-aws-kms-key-id'] = CONFIG['SrvSideEncryptAWSKMSKeyId']
        if CONFIG['SrvSideEncryptContext']:
            rest.headers['x-amz-server-side-encryption-context'] = CONFIG['SrvSideEncryptContext']
    elif CONFIG['SrvSideEncryptType'].lower() == 'sse-kms' and CONFIG['SrvSideEncryptAlgorithm'].lower() == 'aes256':
        rest.headers['x-amz-server-side-encryption'] = 'AES256'
    i = 0
    while i < CONFIG['BucketsPerUser']:
        # 如果未配置目的对象和固定桶，设置目的桶为源对象所在的桶
        if not CONFIG['copyDstObjFiexed'] and not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['copyDstObjFiexed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'] + '.copy')
            if not CONFIG['copySrcObjFixed']:
                rest.headers['x-amz-copy-source'] = '/%s/%s' % (
                    rest.bucket, CONFIG['ObjectNamePartten'].replace('processID', str(
                        process_id)).replace('Index', str(j)).replace('ObjectNamePrefix', CONFIG['ObjectNamePrefix']))
            j += 1
            if CONFIG['copySrcSrvSideEncryptType'].lower() == 'sse-c':
                src_en_key = rest.headers['x-amz-copy-source'].split('/')[2][-32:].zfill(32)
                rest.headers['x-amz-copy-source-server-side-encryption-customer-key'] = base64.b64encode(src_en_key)
                rest.headers['x-amz-copy-source-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(src_en_key).digest())
                logging.debug('src encrpt key: %s, src encrypt key md5: %s' % (
                    src_en_key, rest.headers['x-amz-copy-source-server-side-encryption-customer-key-MD5']))
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            # 同拷贝对象，若拷贝段操作先返回200 OK，并不代表拷贝成功。如果返回了200，但没有获取到ETag，将response修改为500错误。
            if resp.status.startswith('200 ') and not resp.return_data:
                logging.info('response 200 OK without ETag, set status code 500 InternalError')
                resp.status = '500 InternalError'
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes,
                 'copySrc:' + rest.headers['x-amz-copy-source'], resp.request_id, resp.status))


def init_multi_upload(process_id, user, conn, result_queue):
    if not CONFIG['ObjectLexical']:
        logging.warn('Object name is not lexical, exit..')
        return
    if CONFIG['ObjectsPerBucketPerThread'] <= 0 or CONFIG['BucketsPerUser'] <= 0:
        logging.warn('ObjectsPerBucketPerThread or BucketsPerUser <= 0, exit..')
        return
    request_type = 'InitMultiUpload'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.queryArgs['uploads'] = None
    if CONFIG['PutWithACL']:
        rest.headers['x-amz-acl'] = CONFIG['PutWithACL']
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.key = CONFIG['ObjectNameFixed']
    if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
        rest.headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
    elif CONFIG['SrvSideEncryptType'].lower() == 'sse-kms' and CONFIG['SrvSideEncryptAlgorithm'].lower() == 'aws:kms':
        rest.headers['x-amz-server-side-encryption'] = 'aws:kms'
        if CONFIG['SrvSideEncryptAWSKMSKeyId']:
            rest.headers['x-amz-server-side-encryption-aws-kms-key-id'] = CONFIG['SrvSideEncryptAWSKMSKeyId']
        if CONFIG['SrvSideEncryptContext']:
            rest.headers['x-amz-server-side-encryption-context'] = CONFIG['SrvSideEncryptContext']
    elif CONFIG['SrvSideEncryptType'].lower() == 'sse-kms' and CONFIG['SrvSideEncryptAlgorithm'].lower() == 'aes256':
        rest.headers['x-amz-server-side-encryption'] = 'AES256'

    upload_ids = ''
    i = 0
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
            # 如果请求成功，记录return_data（UploadId)到本地文件
            if resp.status.startswith('200 '):
                logging.debug('rest.key:%s, rest.returndata:%s' % (rest.key, resp.return_data))
                upload_ids += '%s\t%s\t%s\t%s\n' % (user.username, rest.bucket, rest.key, resp.return_data)
    if upload_ids == '':
        return None
    # 退出前，写统计结果到本地文件
    uploadid_writer = None
    uploadid_file = 'data/upload_id-%d.dat' % process_id
    try:
        uploadid_writer = open(uploadid_file, 'w')
        uploadid_writer.write(upload_ids)
    except Exception, data:
        logging.error('process [%d] write upload_ids error %s' % (process_id, data))
    finally:
        if uploadid_writer:
            try:
                uploadid_writer.close()
            except IOError:
                pass

def upload_part(process_id, user, conn, result_queue):
    # 从本地加载本进程需要做的upload_ids。考虑到单upload_id多并发上传段场景，需要加载其它进程初始化的upload_ids。
    # 如5个用户，每用户2个并发，则每个upload_id可以最大2个并发上传段。
    # upload_id-0(usr0,p0)  upload_id-1(usr0,p1)  upload_id-2(usr1,p2)  upload_id-3(usr1,p3) upload_id-4(usr2,p4)
    # upload_id-5(usr2,p5)  upload_id-6(usr3,p6)  upload_id-7(usr3,p7)  upload_id-8(usr4,p8) upload_id-9(usr4,p9)
    # p0,p1需要顺序加载usr0,p0和usr0,p1
    upload_ids = []
    if not CONFIG['ConcurrentUpParts']:
        id_files = [process_id]
    else:
        id_files = range(process_id / CONFIG['ThreadsPerUser'] * CONFIG['ThreadsPerUser'],
                         (process_id / CONFIG['ThreadsPerUser'] + 1) * CONFIG['ThreadsPerUser'])
    for i in id_files:
        upload_id_file = 'data/upload_id-%d.dat' % i
        try:
            with open(upload_id_file, 'r') as fd:
                for line in fd:
                    if line.strip() == '':
                        continue
                    # 如果非本并发的用户初始化的upload_id，跳过。
                    if not line.startswith(user.username + '\t'):
                        continue
                    if len(line.split('\t')) != 4:
                        logging.warn('upload_ids record error [%s]' % line)
                        continue
                    # 记录upload_id的原并发号i
                    upload_ids.append((str(i) + '.' + line.strip()).split('\t'))
                fd.close()
            logging.info('process %d load upload_ids file %s end' % (process_id, upload_id_file))
        except Exception, data:
            logging.error("load %s for process %d error, [%r], exit" % (upload_id_file, process_id, data))
            continue

    if not upload_ids:
        logging.info("load no upload_id for process %d, from file upload_id-%r exit" % (process_id, idFiles))
        return
    else:
        logging.info("total load %d upload_ids" % len(upload_ids))

    fixed_size = False
    request_type = 'UploadPart'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.headers['content-type'] = 'application/octet-stream'
    if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
        rest.headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'

    for upload_id in upload_ids:
        rest.bucket = upload_id[1]
        rest.key = upload_id[2]
        rest.queryArgs['uploadId'] = upload_id[3]

        # partsRecord += '%d.%s\t%s\t%s\t%s\t' % (tup[0],user.username,tup[1],tup[2],tup[3])
        parts_record = ''
        # 如果开启了并发上传段，本并发只处理部分段。
        if not CONFIG['ConcurrentUpParts']:
            part_ids = range(1, CONFIG['PartsForEachUploadID'] + 1)
        else:
            part_ids = range(process_id % CONFIG['ThreadsPerUser'] + 1, CONFIG['PartsForEachUploadID'] + 1,
                             CONFIG['ThreadsPerUser'])
        logging.debug('process %d handle parts: %r' % (process_id, part_ids))
        if not part_ids:
            logging.info(
                'process %d has no parts to do for upload_id %s, break' % (process_id, rest.queryArgs['uploadId']))
            continue
        for i in part_ids:
            rest.queryArgs['partNumber'] = str(i)
            if not fixed_size:
                rest.contentLength, fixed_size = Util.generate_a_size(CONFIG['PartSize'])
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())

            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
            if resp.status.startswith('200 '):
                parts_record += '%d:%s,' % (i, resp.return_data)
        upload_id.append(parts_record)
    # 记录各段信息到本地文件 ，parts_etag-x.dat，格式：桶名\t对象名\tupload_id\tpartNo:Etag,partNo:Etag,...
    part_record_file = 'data/parts_etag-%d.dat' % process_id
    parts_record_writer = None
    parts_records = ''
    for upload_id in upload_ids:
        parts_records += '\t'.join(upload_id) + '\n'
    try:
        parts_record_writer = open(part_record_file, 'w')
        parts_record_writer.write(parts_records)
    except Exception, data:
        logging.error('process [%d] write file %s error, %s' % (process_id, part_record_file, data))
    finally:
        if parts_record_writer:
            try:
                parts_record_writer.close()
            except IOError:
                pass


def swiftupload_static_big_object(process_id, user, conn, result_queue):
    # 从本地加载本进程需要做的upload_ids。考虑到单upload_id多并发上传段场景，需要加载其它进程初始化的upload_ids。
    # 如5个用户，每用户2个并发，则每个upload_id可以最大2个并发上传段。
    # upload_id-0(usr0,p0)  upload_id-1(usr0,p1)  upload_id-2(usr1,p2)  upload_id-3(usr1,p3) upload_id-4(usr2,p4)
    # upload_id-5(usr2,p5)  upload_id-6(usr3,p6)  upload_id-7(usr3,p7)  upload_id-8(usr4,p8) upload_id-9(usr4,p9)
    # p0,p1需要顺序加载usr0,p0和usr0,p1
    fixed_size = False
    request_type = 'swiftUploadStaticBigObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk)
    rest.headers['content-type'] = 'application/octet-stream'
    rest.headers['X-auth-token'] = user.sk
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.prefixkey = CONFIG['ObjectNameFixed']
    range_arr = range(0, CONFIG['BucketsPerUser'])
    # 错开每个并发起始选桶，避免单桶性能瓶颈。
    if CONFIG['AvoidSinBkOp']:
        range_arr = range(process_id % CONFIG['BucketsPerUser'], CONFIG['BucketsPerUser']) + range(0,process_id % CONFIG['BucketsPerUser'])
    for i in range_arr:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                rest.prefixkey = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            fixed_size = False
            parts_for_static_big = CONFIG['PartsForEachUploadID']
            k=1
            manifest=''
            rest.queryArgs={}
            rest.sendContent=''
            for k in range(1,parts_for_static_big+1):
                if not fixed_size:
                    # change size every request for the same obj.
                    rest.contentLength, fixed_size = Util.generate_a_size(CONFIG['PartSize'])
                rest.key = '%s-%d'%(rest.prefixkey,k)
                resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
                result_queue.put(
                    (process_id, user.username, rest.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, 'MD5:' + str(resp.content_md5),
                     resp.request_id, resp.status))
                # 如果请求成功，记录return_data（UploadId)到本地文件
                onemanifest =''
                if resp.status.startswith('20'):
                    onemanifest =  '"path":"'+rest.bucket+'/'+rest.key+'",'
                    onemanifest += '"etag":"'+resp.return_data+'",'
                    onemanifest += '"size_bytes":'+str(rest.contentLength)
                    manifest +='{'+onemanifest+'},'
            manifest = manifest[:-1]
            manifest = '['+manifest+']'
            rest.queryArgs['multipart-manifest'] ="PUT"
            rest.key = rest.prefixkey
            rest.sendContent=manifest
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))

def swiftdelete_static_big_object(process_id, user, conn, result_queue):
    request_type = 'swiftDeleteStaticBigObject'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk)
    rest.headers['content-type'] = 'application/octet-stream'
    rest.headers['X-auth-token'] = user.sk
    if CONFIG['BucketNameFixed']:
        rest.bucket = CONFIG['BucketNameFixed']
    if CONFIG['ObjectNameFixed']:
        rest.prefixkey = CONFIG['ObjectNameFixed']
    range_arr = range(0, CONFIG['BucketsPerUser'])
    # 错开每个并发起始选桶，避免单桶性能瓶颈。
    if CONFIG['AvoidSinBkOp']:
        range_arr = range(process_id % CONFIG['BucketsPerUser'], CONFIG['BucketsPerUser']) + range(0,process_id % CONFIG['BucketsPerUser'])
    for i in range_arr:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            rest.queryArgs['multipart-manifest'] ="DELETE"
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
def copy_part(process_id, user, conn, result_queue):
    # 必须传入OBJECTS，否则无法拷贝。
    global OBJECTS
    if not OBJECTS:
        logging.error("can not find source object, exit")
        return

    # 从本地加载本进程需要做的upload_ids。考虑到单upload_id多并发上传段场景，需要加载其它进程初始化的upload_ids。
    # 如5个用户，每用户2个并发，则每个upload_id可以最大2个并发上传段。
    # upload_id-0(usr0,p0)  upload_id-1(usr0,p1)  upload_id-2(usr1,p2)  upload_id-3(usr1,p3) upload_id-4(usr2,p4)
    # upload_id-5(usr2,p5)  upload_id-6(usr3,p6)  upload_id-7(usr3,p7)  upload_id-8(usr4,p8) upload_id-9(usr4,p9)
    # p0,p1需要顺序加载usr0,p0和usr0,p1
    upload_ids = []
    if not CONFIG['ConcurrentUpParts']:
        id_files = [process_id]
    else:
        id_files = range(process_id / CONFIG['ThreadsPerUser'] * CONFIG['ThreadsPerUser'],
                         (process_id / CONFIG['ThreadsPerUser'] + 1) * CONFIG['ThreadsPerUser'])

    for i in id_files:
        upload_id_file = 'data/upload_id-%d.dat' % i
        try:
            with open(upload_id_file, 'r') as fd:
                for line in fd:
                    if line.strip() == '':
                        continue
                    # 如果非本并发的用户初始化的upload_id，跳过。
                    if not line.startswith(user.username + '\t'):
                        continue
                    if len(line.split('\t')) != 4:
                        logging.warn('upload_ids record error [%s]' % line)
                        continue
                    # 记录upload_id的原并发号i
                    upload_ids.append((str(i) + '.' + line.strip()).split('\t'))
                fd.close()
            logging.info('process %d load upload_ids file %s end' % (process_id, upload_id_file))
        except Exception, data:
            logging.error("load %s for process %d error, [%r], exit" % (upload_id_file, process_id, data))
            continue

    if not upload_ids:
        logging.info("load no upload_id for process %d, exit" % process_id)
        return

    fixed_size = False
    request_type = 'CopyPart'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
        rest.headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
    if CONFIG['copySrcSrvSideEncryptType'].lower() == 'sse-c':
        rest.headers['x-amz-copy-source-server-side-encryption-customer-algorithm'] = 'AES256'

    parts_record = ''
    for upload_id in upload_ids:
        rest.bucket = upload_id[1]
        rest.key = upload_id[2]
        rest.queryArgs['uploadId'] = upload_id[3]
        # 如果开启了并发上传段，本并发只处理部分段。
        if not CONFIG['ConcurrentUpParts']:
            part_ids = range(1, CONFIG['PartsForEachUploadID'] + 1)
        else:
            part_ids = range(process_id % CONFIG['ThreadsPerUser'] + 1, CONFIG['PartsForEachUploadID'] + 1,
                             CONFIG['ThreadsPerUser'])
        logging.debug('process %d handle parts: %r' % (process_id, part_ids))
        if not part_ids:
            logging.info(
                'process %d has no parts to do for upload_id %s, break' % (process_id, rest.queryArgs['uploadId']))
            continue
        for i in part_ids:
            rest.queryArgs['partNumber'] = str(i)
            if not fixed_size:
                range_size, fixed_size = Util.generate_a_size(CONFIG['PartSize'])
            rest.headers['x-amz-copy-source'] = '/%s' % random.choice(OBJECTS)
            range_start_index = random.randint(0, range_size * (CONFIG['PartsForEachUploadID'] - 1))
            logging.debug('range_start_index:%d' % range_start_index)
            rest.headers['x-amz-copy-source-range'] = 'bytes=%d-%d' % (
                range_start_index, range_start_index + range_size - 1)
            logging.debug('x-amz-copy-source-range:[%s]' % rest.headers['x-amz-copy-source-range'])
            # 增加服务器端加密头域
            if CONFIG['copySrcSrvSideEncryptType'].lower() == 'sse-c':
                src_en_key = rest.headers['x-amz-copy-source'].split('/')[2][-32:].zfill(32)
                rest.headers['x-amz-copy-source-server-side-encryption-customer-key'] = base64.b64encode(src_en_key)
                rest.headers['x-amz-copy-source-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(src_en_key).digest())
                logging.debug('src encrpt key: %s, src encrypt key md5: %s' % (
                    src_en_key, rest.headers['x-amz-copy-source-server-side-encryption-customer-key-MD5']))
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())

            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            # 同拷贝对象，若拷贝段操作先返回200 OK，并不代表拷贝成功。如果返回了200，但没有获取到ETag，将response修改为500错误。
            if resp.status.startswith('200 ') and not resp.return_data:
                logging.info('response 200 OK without ETag, set status code 500 InternalError')
                resp.status = '500 InternalError'
            result_queue.put(
                (process_id, user.username, rest.url, request_type, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes,
                 'src:' + rest.headers['x-amz-copy-source'] + ':' + rest.headers[
                     'x-amz-copy-source-range'], resp.request_id, resp.status))
            if resp.status.startswith('200 '):
                parts_record += '%d:%s,' % (i, resp.return_data)
        upload_id.append(parts_record)
    # 记录各段信息到本地文件 ，parts_etag-x.dat，格式：桶名\t对象名\tupload_id\tpartNo:Etag,partNo:Etag,...
    part_record_file = 'data/parts_etag-%d.dat' % process_id
    parts_record_writer = None
    parts_records = ''
    for upload_id in upload_ids:
        parts_records += '\t'.join(upload_id) + '\n'
    try:
        parts_record_writer = open(part_record_file, 'w')
        parts_record_writer.write(parts_records)
    except Exception, data:
        logging.error('process [%d] write file %s error, %s' % (process_id, part_record_file, data))
    finally:
        if parts_record_writer:
            try:
                parts_record_writer.close()
            except IOError:
                pass


def complete_multi_upload(process_id, user, conn, result_queue):
    # 从本地parts_etag-x.dat中加载本进程需要做的upload_ids。考虑到单upload_id多并发上传段场景，需要加载其它进程上传的段信息。
    # 如3个用户，每用户3个并发，每个upload_id上传6个段，则每个upload_id 3个并发上传段，每个并发对每个upload_id上传2个段。
    # parts_etag-0(usr0,p0,part1/4)  parts_etag-1(usr0,p1,part2/5)  parts_etag-2(usr1,p2,part3/6)
    # parts_etag-3(usr1,p3,part1/4)  parts_etag-4(usr0,p4,part2/5)  parts_etag-5(usr1,p5,part3/6)
    # parts_etag-0(usr2,p6,part1/4)  parts_etag-1(usr0,p7,part2/5)  parts_etag-2(usr1,p8,part3/6)

    # p0,p1,p2需要顺序加载parts_etag-0, parts_etag-1, parts_etag-2,取里面属于自已的对象。

    part_etags = {}
    if not CONFIG['ConcurrentUpParts']:
        part_files = [process_id]
    else:
        part_files = range(process_id / CONFIG['ThreadsPerUser'] * CONFIG['ThreadsPerUser'],
                           (process_id / CONFIG['ThreadsPerUser'] + 1) * CONFIG['ThreadsPerUser'])

    for i in part_files:
        part_record_file = 'data/parts_etag-%d.dat' % i
        try:
            with open(part_record_file, 'r') as fd:
                for line in fd:
                    if line.strip() == '':
                        continue
                    if not line.startswith('%d.%s\t' % (process_id, user.username)):
                        continue
                    line_array = line.strip().split('\t')
                    if len(line_array) != 5 or not line_array[4]:
                        logging.warn('partEtag record error [%s]' % line)
                        continue
                    # 用户名\t桶名\t对象名\tupoadID\tpartNo:etag,partN0:etag,..
                    # 合并相同的upload_id多并发上传的段信息
                    if line_array[3] in part_etags:
                        part_etags[line_array[3]] = (
                            line_array[1], line_array[2], line_array[4] + part_etags[line_array[3]][2])
                    else:
                        part_etags[line_array[3]] = (line_array[1], line_array[2], line_array[4])
                fd.close()
            logging.debug('process %d load parts_etag file %s end' % (process_id, part_record_file))
        except Exception, data:
            logging.info(
                "load parts_etag from file %s for process %d error, [%r], exit" % (part_record_file, process_id, data))
            continue
    if not part_etags:
        logging.error('process %d load nothing from files %r ' % (process_id, part_files))
        return
    request_type = 'CompleteMultiUpload'
    rest = s3PyCmd.S3RequestDescriptor(request_type, ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.headers['content-type'] = 'application/xml'
    for key, value in part_etags.items():
        rest.bucket = value[0]
        rest.key = value[1]
        rest.queryArgs['uploadId'] = key
        # 将parts信息排序
        parts_dict = {}
        for item in value[2].split(','):
            if ':' in item:
                parts_dict[int(item.split(':')[0])] = item.split(':')[1]
        # 组装xml body
        if not parts_dict:
            continue
        rest.sendContent = '<CompleteMultipartUpload>'
        for part_index in sorted(parts_dict):
            if not parts_dict[part_index]:
                continue
            rest.sendContent += '<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>' % (
                part_index, parts_dict[part_index])
        rest.sendContent += '</CompleteMultipartUpload>'
        resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
        result_queue.put(
            (process_id, user.username, rest.url, request_type, resp.start_time,
             resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


def multi_parts_upload(process_id, user, conn, result_queue):
    rest = s3PyCmd.S3RequestDescriptor(request_type='', ak=user.ak, sk=user.sk,
                                       auth_algorithm=CONFIG['AuthAlgorithm'], virtual_host=CONFIG['VirtualHost'],
                                       domain_name=CONFIG['DomainName'], region=CONFIG['Region'])
    rest.bucket = CONFIG['BucketNameFixed']
    rest.key = CONFIG['ObjectNameFixed']
    i = 0
    while i < CONFIG['BucketsPerUser']:
        if not CONFIG['BucketNameFixed']:
            rest.bucket = '%s.%s.%d' % (user.ak.lower(), CONFIG['BucketNamePrefix'], i)
        i += 1
        j = 0
        while j < CONFIG['ObjectsPerBucketPerThread']:
            if not CONFIG['ObjectNameFixed']:
                rest.key = CONFIG['ObjectNamePartten'].replace('processID', str(process_id)).replace('Index',
                                                                                                     str(j)).replace(
                    'ObjectNamePrefix', CONFIG['ObjectNamePrefix'])
            j += 1
            # 1. 初始化对象多段上传任务。
            rest.requestType = 'InitMultiUpload'
            rest.method = 'POST'
            rest.headers = {}
            rest.queryArgs = {}
            rest.sendContent = ''
            rest.queryArgs['uploads'] = None
            if CONFIG['PutWithACL']:
                rest.headers['x-amz-acl'] = CONFIG['PutWithACL']
            if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                rest.headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
                rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(rest.key[-32:].zfill(32))
                rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                    hashlib.md5(rest.key[-32:].zfill(32)).digest())
            elif CONFIG['SrvSideEncryptType'].lower() == 'sse-kms' and CONFIG[
                'SrvSideEncryptAlgorithm'].lower() == 'aws:kms':
                rest.headers['x-amz-server-side-encryption'] = 'aws:kms'
                if CONFIG['SrvSideEncryptAWSKMSKeyId']:
                    rest.headers['x-amz-server-side-encryption-aws-kms-key-id'] = CONFIG['SrvSideEncryptAWSKMSKeyId']
                if CONFIG['SrvSideEncryptContext']:
                    rest.headers['x-amz-server-side-encryption-context'] = CONFIG['SrvSideEncryptContext']
            elif CONFIG['SrvSideEncryptType'].lower() == 'sse-kms' and CONFIG[
                'SrvSideEncryptAlgorithm'].lower() == 'aes256':
                rest.headers['x-amz-server-side-encryption'] = 'AES256'
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, rest.requestType, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
            upload_id = resp.return_data
            logging.info("upload id: %s" % upload_id)
            # 2. 串行上传多段
            rest.requestType = 'UploadPart'
            rest.method = 'PUT'
            rest.headers = {}
            rest.queryArgs = {}
            rest.sendContent = ''
            rest.headers['content-type'] = 'application/octet-stream'
            rest.queryArgs['uploadId'] = upload_id
            part_number = 1
            fixed_size = False
            part_etags = {}
            while part_number <= CONFIG['PartsForEachUploadID']:
                rest.queryArgs['partNumber'] = str(part_number)
                if CONFIG['SrvSideEncryptType'].lower() == 'sse-c':
                    rest.headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
                    rest.headers['x-amz-server-side-encryption-customer-key'] = base64.b64encode(
                        rest.key[-32:].zfill(32))
                    rest.headers['x-amz-server-side-encryption-customer-key-MD5'] = base64.b64encode(
                        hashlib.md5(rest.key[-32:].zfill(32)).digest())
                if not fixed_size:
                    rest.contentLength, fixed_size = Util.generate_a_size(CONFIG['PartSize'])
                resp = s3PyCmd.S3RequestHandler(rest, conn).make_request(cal_md5=CONFIG['CalHashMD5'])
                result_queue.put(
                    (process_id, user.username, rest.url, rest.requestType, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))
                if resp.status.startswith('200 '):
                    part_etags[part_number] = resp.return_data
                part_number += 1
            # 3. 合并段
            rest.requestType = 'CompleteMultiUpload'
            rest.method = 'POST'
            rest.headers = {}
            rest.queryArgs = {}
            rest.headers['content-type'] = 'application/xml'
            rest.queryArgs['uploadId'] = upload_id
            rest.sendContent = '<CompleteMultipartUpload>'
            for part_index in sorted(part_etags):
                rest.sendContent += '<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>' % (
                    part_index, part_etags[part_index])
            rest.sendContent += '</CompleteMultipartUpload>'
            resp = s3PyCmd.S3RequestHandler(rest, conn).make_request()
            result_queue.put(
                (process_id, user.username, rest.url, rest.requestType, resp.start_time,
                 resp.end_time, resp.send_bytes, resp.recv_bytes, '', resp.request_id, resp.status))


# 并发进程入口
def start_process(process_id, user, test_case, results_queue, valid_start_time, valid_end_time, current_threads, lock,
                  conn=None, call_itself=False):
    global OBJECTS, CONFIG
    # 如果混合操作自身调用，不增用户，不等待。
    if not call_itself:
        lock.acquire()
        current_threads.value += 1
        lock.release()
        # 等待所有用户启动
        while True:
            # 如果时间已经被其它进程刷新，直接跳过。
            if valid_start_time.value == float(sys.maxint):
                # 若所有用户均启动，记为合法的有效开始时间
                if current_threads.value == CONFIG['Threads']:
                    valid_start_time.value = time.time() + 2
                else:
                    time.sleep(.06)
            else:
                break

        time.sleep(2)
    # 若长连接分配连接。考虑混合操作重复执行场景，若已有连接，不分配连接
    if not conn:
        conn = s3PyCmd.MyHTTPConnection(host=CONFIG['OSCs'], is_secure=CONFIG['IsHTTPs'],
                                        ssl_version=CONFIG['sslVersion'], timeout=CONFIG['ConnectTimeout'],
                                        serial_no=process_id, long_connection=CONFIG['LongConnection'],
                                        conn_header=CONFIG['ConnectionHeader'])
    from swiftIamTool import RestRequest
    rest = RestRequest()
    if test_case != 900:
        try:
            method_to_call = globals()[TESTCASES[test_case].split(';')[1]]
            logging.debug('method %s called ' % method_to_call)
            method_to_call(process_id, user, conn, results_queue)
        except KeyboardInterrupt:
            pass
        except Exception, e:
            logging.error('Call method for test case %d except: %s' % (test_case, e))
    elif test_case == 900:
        test_cases = [int(case) for case in CONFIG['MixOperations'].split(',')]
        tmp = 0
        while tmp < CONFIG['MixLoopCount']:
            t1,t2,t3,t4=rest.GetUserToken(username=user.username)
            print "t1================================================================================="+t1+"|"+t3
            logging.debug("loop count: %d " % tmp)
            tmp += 1
            for case in test_cases:
                logging.debug("case %d in mix loop called " % case)
                start_process(process_id, user, case, results_queue, valid_start_time,
                              valid_end_time, current_threads, lock, conn, True)
    # 如果混合操作自身调用，则直接返回，不断连接，不减用户。
    if call_itself:
        return

    # close connection for this thread
    if conn:
        conn.close_connection()

    # 执行完业务后，当前用户是第一个退出的用户，记为合法的结束时间
    if current_threads.value == CONFIG['Threads']:
        valid_end_time.value = time.time()
        logging.info('thread [' + str(process_id) + '], exit, set valid_end_time = ' + str(valid_end_time.value))
    # 退出
    lock.acquire()
    current_threads.value -= 1
    lock.release()
    logging.info('process_id [%d] exit, set current_threads.value = %d' % (process_id, current_threads.value))


def get_total_requests():
    global OBJECTS, CONFIG
    if CONFIG['Testcase'] == 100:
        return CONFIG['RequestsPerThread'] * CONFIG['Threads']
    elif CONFIG['Testcase'] in (101, 103, 104, 105, 106, 111, 112, 141, 142, 143, 151, 152, 153):
        return CONFIG['BucketsPerUser'] * CONFIG['Users']
    elif CONFIG['Testcase'] in (201,):
        return CONFIG['ObjectsPerBucketPerThread'] * CONFIG['BucketsPerUser'] * CONFIG['Threads'] * CONFIG[
            'PutTimesForOneObj']
    elif CONFIG['Testcase'] in (202, 203, 204, 206, 207, 211):
        if len(OBJECTS) > 0:
            return len(OBJECTS)
        # 如果从data下加载到对象版本数据，则不清楚总数。
        if CONFIG['Testcase'] in (202, 204):
            for i in range(CONFIG['Threads']):
                obj_v_file = 'data/objv-%d.dat' % i
                if os.path.exists(obj_v_file) and os.path.getsize(obj_v_file) > 0:
                    return -1
        return CONFIG['ObjectsPerBucketPerThread'] * CONFIG['BucketsPerUser'] * CONFIG['Threads']
    elif CONFIG['Testcase'] in (205,):
        return int((CONFIG['ObjectsPerBucketPerThread'] + CONFIG['DeleteObjectsPerRequest'] - 1) / CONFIG[
            'DeleteObjectsPerRequest']) * CONFIG['BucketsPerUser'] * CONFIG['Threads']
    elif CONFIG['Testcase'] in (216,):
        return CONFIG['ObjectsPerBucketPerThread'] * CONFIG['BucketsPerUser'] * CONFIG['Threads'] * (
            2 + CONFIG['PartsForEachUploadID'])

    # 对于某些请求无法计算请求总量，返回-1
    else:
        return -1


# return True: pass, False: failed
def precondition():
    global CONFIG, TESTCASES
    # 检查当前用户是否root用户
    import getpass
    import platform

    if 'root' != getpass.getuser() and platform.system().lower().startswith('linux'):
        return False, "\033[1;31;40m%s\033[0m Please run with root account other than '%s'" % (
            "[ERROR]", getpass.getuser())

    # 检查测试用例是否支持
    if CONFIG['Testcase'] not in TESTCASES:
        return False, "\033[1;31;40m%s\033[0m Test Case [%d] not supported" % ("[ERROR]", CONFIG['Testcase'])

    # 如果开启服务器端加密功能，必须使用https+AWSV4
    if CONFIG['SrvSideEncryptType']:
        if not CONFIG['IsHTTPs']:
            CONFIG['IsHTTPs'] = True
            logging.info('change IsHTTPs to True while use SrvSideEncryptType')
        if CONFIG['AuthAlgorithm'] != 'AWSV4':
            CONFIG['AuthAlgorithm'] = 'AWSV4'
            logging.info('change AuthAlgorithm to AWSV4 while use SrvSideEncryptType')

    # 加载用户,检查user是否满足要求
    logging.info('loading users...')
    read_users()
    if CONFIG['Users'] > len(USERS):
        return False, "\033[1;31;40m%s\033[0m Not enough users in users.dat after index %d: %d < [Users=%d]" % (
            "[ERROR]", CONFIG['UserStartIndex'], len(USERS), CONFIG['Users'])

    # 测试网络连接
    if CONFIG['IsHTTPs']:
        try:
            import ssl as ssl

            if not CONFIG['sslVersion']:
                CONFIG['sslVersion'] = 'SSLv23'
            logging.info('import ssl module done, config ssl Version: %s' % CONFIG['sslVersion'])
        except ImportError:
            logging.info('import ssl module error')
            return False, 'Python version %s ,import ssl module error'
    oscs = CONFIG['OSCs'].split(',')
    for end_point in oscs:
        print 'Testing connection to %s\t' % end_point.ljust(20),
        sys.stdout.flush()
        test_conn = None
        try:
            test_conn = s3PyCmd.MyHTTPConnection(host=end_point, is_secure=CONFIG['IsHTTPs'],
                                                 ssl_version=CONFIG['sslVersion'], timeout=60, serial_no=0,
                                                 long_connection=True)
            test_conn.connect_connection()
            ssl_ver = ''
            if CONFIG['IsHTTPs']:
                if Util.compareVersion(sys.version.split()[0], '2.7.9') < 0:
                    ssl_ver = test_conn.connection.sock._sslobj.cipher()[1]
                else:
                    ssl_ver = test_conn.connection.sock._sslobj.version()
                rst = '\033[1;32;40mSUCCESS  %s\033[0m'.ljust(10) % ssl_ver
            else:
                rst = '\033[1;32;40mSUCCESS\033[0m'.ljust(10)
            print rst
            logging.info(
                'connect %s success, python version: %s,  ssl_ver: %s' % (
                    end_point, sys.version.replace('\n', ' '), ssl_ver))
        except Exception, data:
            logging.error('Caught exception when testing connection with %s, except: %s' % (end_point, data))
            print '\033[1;31;40m%s *%s*\033[0m' % (' Failed'.ljust(8), data)
            return False, 'Check connection failed'
        finally:
            if test_conn:
                test_conn.close_connection()

    # 创建data目录
    if not os.path.exists('data'):
        os.mkdir('data')

    return True, 'check passed'


def get_objects_from_file(file_name):
    global OBJECTS
    if not os.path.exists(file_name):
        print 'ERROR，the file configed %s in config.dat  not exist' % file_name
        sys.exit(0)
    try:
        with open(file_name, 'r') as fd:
            for line in fd:
                if line.strip() == '':
                    continue
                if len(line.split(',')) != 12:
                    continue
                if line.split(',')[2][1:].find('/') == -1:
                    continue
                if line.split(',')[11].strip().startswith('200 OK'):
                    OBJECTS.append(line.split(',')[2][1:])
            fd.close()
        logging.info('load file %s end, get objects [%d]' % (file_name, len(OBJECTS)))
    except Exception, data:
        msg = 'load file %s except, %s' % (file_name, data)
        logging.error(msg)
        print msg
        sys.exit()
    if len(OBJECTS) == 0:
        print 'get no objects in file %s' % file_name
        sys.exit()


# running config
CONFIG = {}
# test users
USERS = []
OBJECTS = []
TESTCASES_SWIFT = {100: 'swiftListUserContainers;swiftlist_user_containers',
             101: 'swiftCreateContainer;swiftcreate_container',
             102: 'swiftListObjectsInContainer;swiftlist_objects_in_container',
             103: 'swiftHeadContainer;swifthead_container',
             104: 'swiftDeleteContainer;swiftdelete_container',
             201: 'swiftPutObject;swiftput_object',
             202: 'swiftGetObject;swiftget_object',
             203: 'swiftHeadObject;swifthead_object',
             204: 'swiftDeleteObject;swiftdelete_object',
             217: 'swiftUploadDynamicBigObject;swiftupload_dynamic_big_object',
             218: 'swiftUploadStaticBigObject;swiftupload_static_big_object',
             219: 'swiftDeleteDynamicBigObject;swiftdelete_dynamic_big_object',
             220: 'swiftDeleteStaticBigObject;swiftdelete_static_big_object',
             900: 'MixOperation;',
             }
TESTCASES = {100: 'ListUserBuckets;list_user_buckets',
             101: 'CreateBucket;create_bucket',
             102: 'ListObjectsInBucket;list_objects_in_bucket',
             103: 'HeadBucket;head_bucket',
             104: 'DeleteBucket;delete_bucket',
             105: 'BucketDelete;bucket_delete',
             106: 'OptionsBucket;options_bucket',
             111: 'PutBucketVersiong;put_bucket_versioning',
             112: 'GetBucketVersioning;get_bucket_versioning',
             141: 'PutBucketWebsite;put_bucket_website',
             142: 'GetBucketWebsite;get_bucket_website',
             143: 'DeleteBucketWebsite;delete_bucket_website',
             151: 'PutBucketCors;put_bucket_cors',
             152: 'GetBucketCors;get_bucket_cors',
             153: 'DeleteBucketCors;delete_bucket_cors',
             161: 'PutBucketTag;put_bucket_tag',
             162: 'GetBucketTag;get_bucket_tag',
             163: 'DeleteBucketTag;delete_bucket_tag',
             201: 'PutObject;put_object',
             202: 'GetObject;get_object',
             203: 'HeadObject;head_object',
             204: 'DeleteObject;delete_object',
             205: 'DeleteMultiObjects;delete_multi_objects',
             206: 'CopyObject;copy_object',
             207: 'RestoreObject;restore_object',
             211: 'InitMultiUpload;init_multi_upload',
             212: 'UploadPart;upload_part',
             213: 'CopyPart;copy_part',
             214: 'CompleteMultiUpload;complete_multi_upload',
             215: 'AbortMultiUpload;abort_multi_upload',
             216: 'MultiPartsUpload;multi_parts_upload',
             900: 'MixOperation;'
             }
TESTCASES=TESTCASES_SWIFT
if __name__ == '__main__':
    if not os.path.exists('log'):
        os.mkdir('log')
    logging.config.fileConfig('logging.conf')
    version = '----------------s3PyTool: v20170215, Python: %s----------------' % sys.version.split(' ')[0]
    logging.info(version)
    print version
    # 加载指定配置文件
    logging.info('loading config...')
    config_file = 'config.dat'
    if len(sys.argv[1:]) > 2:
        config_file = sys.argv[1:][2]
    read_config(config_file)

    print 'Config loaded'
    print str(CONFIG).replace('\'', '')
    logging.info(CONFIG)
    # 如果携带参数，则使用参数，覆盖配置文件。
    if len(sys.argv[1:]) > 0:
        CONFIG['Testcase'] = int(sys.argv[1:][0])
    if len(sys.argv[1:]) > 1:
        CONFIG['Users'] = int(sys.argv[1:][1])
        CONFIG['Threads'] = CONFIG['Users'] * CONFIG['ThreadsPerUser']
    # 启动前检查
    check_result, msg = precondition()
    if not check_result:
        print 'Check error, [%s] \nExit...' % msg
        sys.exit()

    if CONFIG['objectDesFile']:
        # 判断操作类型，其它操作不预读文件，即使配置了objectDesFile
        obj_op = ['202', '203', '204', '213']
        if str(CONFIG['Testcase']) in obj_op or (
                        CONFIG['Testcase'] == 900 and (set(CONFIG['MixOperations'].split(',')) & set(obj_op))):
            print 'begin to read object file %s' % CONFIG['objectDesFile']
            get_objects_from_file(CONFIG['objectDesFile'])
            print 'finish, get %d objects' % len(OBJECTS)
    start_wait = False
    if start_wait:
        tip = '''
     --------------------------------------------------------------------------------
      Important: This is the way how we can run multi-clients at the same time.
      Assuming all the client nodes are sync with the time server.
      If now 02:10:00, enter 12 to change the minute, then it will start at 02:12:00
     --------------------------------------------------------------------------------
    '''
        print '\033[1;32;40m%s\033[0m' % tip
        import threading


        def input_func(input_data):
            input_data['data'] = raw_input()


        while False:
            n = datetime.datetime.now()
            print 'Now it\'s %2d:\033[1;32;40m%2d\033[0m:%2d, please input to change the minute' % (
                n.hour, n.minute, n.second),
            print '(Press \'Enter\' or wait 30 sec to run, \'q\' to exit): ',
            try:
                input_data = {'data': 'default'}
                t = threading.Thread(target=input_func, args=(input_data,))
                t.daemon = True
                t.start()
                t.join(30)  # 等待30秒
                if input_data['data'] == 'q':
                    sys.exit()
                elif '' == input_data['data'] or 'default' == input_data['data']:
                    break
                try:
                    input_data['data'] = int(input_data['data'])
                except ValueError:
                    print '[ERROR] I only receive numbers (*>﹏<*)'
                    continue
                n = datetime.datetime.now()
                diff = input_data['data'] * 60 - (n.minute * 60 + n.second)
                if diff > 0:
                    print 'Wait for %d seconds...' % diff
                    time.sleep(diff)
                    break
                else:
                    break
            except KeyboardInterrupt:
                print '\nSystem exit...'
                sys.exit()
    n = datetime.datetime.now()
    msg = 'Start at %s, pid:%d. Press Ctr+C to stop. Screen Refresh Interval: 3 sec' % (
        time.strftime('%X %x %Z'), os.getpid())
    print msg
    logging.info(msg)
    # valid_start_time: 所有并发均启动。
    # valid_end_time: 第一个并发退出时刻。
    # current_threads：当前运行的并发数。-2表示手动退出，-1表示正常退出。
    valid_start_time = multiprocessing.Value('d', float(sys.maxint))
    valid_end_time = multiprocessing.Value('d', float(sys.maxint))
    current_threads = multiprocessing.Value('i', 0)
    # results_queue, 请求记录保存队列。多进程公用。
    results_queue = multiprocessing.Queue(0)

    # 启动统计计算结果的进程 。用于从队列取请求记录，保存到本地，并同时刷新实时结果。
    results_writer = results.ResultWriter(CONFIG, TESTCASES[CONFIG['Testcase']].split(';')[0].split(';')[0],
                                          results_queue, get_total_requests(),
                                          valid_start_time, valid_end_time, current_threads)
    results_writer.daemon = True
    results_writer.name = 'resultsWriter'
    results_writer.start()
    print 'resultWriter started, pid: %d' % results_writer.pid
    # 增加该进程的优先级
    os.system('renice -19 -p ' + str(results_writer.pid) + ' >/dev/null 2>&1')
    time.sleep(.2)

    # 顺序启动多个业务进程
    process_list = []
    # 多进程公用锁
    lock = multiprocessing.Lock()
    esc = chr(27)  # escape key
    i = 0
    while i < CONFIG['Threads']:
        p = multiprocessing.Process(target=start_process, args=(
            i, USERS[i / CONFIG['ThreadsPerUser']], CONFIG['Testcase'], results_queue, valid_start_time, valid_end_time,
            current_threads,
            lock, None,
            False))
        i += 1
        p.daemon = True
        p.name = 'worker-%d' % i
        p.start()
        # 将各工作进程的优先级提高1
        os.system('renice -1 -p ' + str(p.pid) + ' >/dev/null 2>&1')
        process_list.append(p)

    logging.info('All %d threads started, valid_start_time: %.3f' % (len(process_list), valid_start_time.value))

    # 请求未完成退出
    def exit_force(signal_num, e):
        msg = "\n\n\033[5;33;40m[WARN]Terminate Signal %d Received. Terminating... please wait\033[0m" % signal_num
        logging.warn('%r' % msg)
        print msg, '\nWaiting for all the threads exit....'
        lock.acquire()
        current_threads.value = -2
        lock.release()
        time.sleep(.1)
        tmpi = 0
        for j in process_list:
            if j.is_alive():
                if tmpi >= 100:
                    logging.info('force to terminate process %s' % j.name)
                    j.terminate()
                else:
                    time.sleep(.1)
                    tmpi += 1
                    break

        print "\033[1;32;40mWorkers exited.\033[0m Waiting results_writer exit...",
        sys.stdout.flush()
        while results_writer.is_alive():
            current_threads.value = -2
            tmpi += 1
            if tmpi > 1000:
                logging.warn('retry too many time, shutdown results_writer using terminate()')
                results_writer.terminate()
            time.sleep(.01)
        print "\n\033[1;33;40m[WARN] Terminated\033[0m\n"
        print version
        sys.exit()


    import signal

    signal.signal(signal.SIGINT, exit_force)
    signal.signal(signal.SIGTERM, exit_force)

    time.sleep(1)
    # 正常退出
    stop_mark = False
    while not stop_mark:
        time.sleep(.3)
        if CONFIG['RunSeconds'] and (time.time() - valid_start_time.value >= CONFIG['RunSeconds']):
            logging.info('time is up, exit')
            exit_force(99, None)
        for j in process_list:
            if j.is_alive():
                break
            stop_mark = True
    for j in process_list:
        j.join()
    # 等待结果进程退出。
    logging.info('Waiting results_writer to exit...')
    while results_writer.is_alive():
        current_threads.value = -1  # inform results_writer
        time.sleep(.3)
    print "\n\033[1;33;40m[WARN] Terminated after all requests\033[0m\n"
    print version
