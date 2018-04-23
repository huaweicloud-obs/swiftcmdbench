# import urllib2
#
# request = urllib2.Request('https://8.42.115.15/v1/AUTH_31b9014a400e456e971a8af7ada52d49/abc/test?temp_url_sig=92e018fa1c9824b5d236a85eda8d30d4bdb822f3&temp_url_expires=1510970226')
# #headers={"Content-type": "application/json","x-auth-token":'305e67f6a0554827a19198d800f02e5f'}
# #request = urllib2.Request('https://8.42.104.138:35357/v2.0/users',headers=headers)
# #request.add_header('x-auth-token', 'MIIEHQYJKoZIhvcNAQcCoIIEDjCCBAoCAQExDTALBglghkgBZQMEAgEwggJrBgkqhkiG9w0BBwGgggJcBIICWHsidG9rZW4iOnsiZXhwaXJlc19hdCI6IjIwMTctMTAtMDlUMTg6MjY6NTIuMDAwMDAwWiIsImlzc3VlZF9hdCI6IjIwMTctMTAtMDhUMTg6MjY6NTIuMDAwMDAwWiIsIm1ldGhvZHMiOlsiaHdfYWNjZXNzX2tleSJdLCJwcm9qZWN0Ijp7Im5hbWUiOiJNT1MiLCJpZCI6Ijhwcm9qZWN0aWRwcm9qZWN0aWRwcm9qZWN0MDAxMDAwIiwiZG9tYWluIjp7Im5hbWUiOiJkb21haW5uYW1lZG9tMDAxMDAwIiwiaWQiOiJkb21haW5pZGRvbWFpbmlkZG9tYWluaWRkbzAwMTAwMCIsInhkb21haW5fdHlwZSI6IkNOIiwieGRvbWFpbl9pZCI6IjEyMzQ1Njc4OTBfMCJ9fSwidXNlciI6eyJkb21haW4iOnsibmFtZSI6ImRvbWFpbm5hbWVkb20wMDEwMDAiLCJpZCI6ImRvbWFpbmlkZG9tYWluaWRkb21haW5pZGRvMDAxMDAwIiwieGRvbWFpbl90eXBlIjoiQ04iLCJ4ZG9tYWluX2lkIjoiMTIzNDU2Nzg5MF8wIn0sImlkIjoidXNlcmlkdXNlcmlkdXNlcmlkdXNlcmlkdXMwMDEwMDAiLCJuYW1lIjoidXNybmFtZTAwMTAwMCJ9LCJjYXRhbG9nIjpbXSwicm9sZXMiOlt7Im5hbWUiOiJ0ZV9hZG1pbiIsImlkIjoiMzdmZWNmNjVkN2RhNDllMjgzNjdjODI5ZWEzYzNhMTcifV19fTGCAYUwggGBAgEBMFwwVzELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVVuc2V0MQ4wDAYDVQQHDAVVbnNldDEOMAwGA1UECgwFVW5zZXQxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbQIBATALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEABIfPHvjj6bGKeuMtlxaS3Uo6MNEwxhXQs5yXGig1TEL8zjiAovI4TIuM3-gGB1+1s6i9YFWTm7MB7LwF7g4NJfUbPnZIHCm0JnhpaAxT2A+3iPTGndTy-a1D3A+XwRRl1L8NuxJd5C9BnAtLCbsK1-UmXVGz1jcQLmcZuQwJ8+iQF+H8fFZYXydUadKfqa4DUc80AdPzV9p+rGZE0yUxE0YojiIxynkqMdzd-suZH9Y+AFKG2eqnzDjvKjWIFZtcVKgbGXQJXCfPtJqLW1MO-BPHD7N1wHD+EDcU+jjg28DragSRL3DjhuDfixmtYJBYqaumqZEd8eU5npf5YxVV+w==')
# capath='D:\\419\\ca.crt'
# response = urllib2.urlopen(request,cafile='ca.crt',capath=capath)
# abc=response.read()
# print abc
import urllib2
#
headers={"Content-type": "application/json","Date":"Wed, 06 Dec 2017 03:03:17 +0000","Authorization":"AWS UDSIAMSTUBTEST000045:VNkRDARcs9ns5k5yY8+/ZzhICBU="}
request = urllib2.Request('http://8.43.11.12/bucketname',headers=headers)
response = urllib2.urlopen(request,cafile='ca.crt')#,capath='/etc/ssl/certs')
abc=response.read()
print abc
#data='{"auth":{"tenantName": "adminTenant","passwordCredentials":{"username": "zhuser3","password": "123456"}}}'
