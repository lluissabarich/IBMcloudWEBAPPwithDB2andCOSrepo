import os
import json
from flask import Flask, jsonify,redirect,request,session,render_template
import requests
import base64
from requests.auth import HTTPBasicAuth
WebAppStrategy={}
WebAppStrategy['DEFAULT_SCOPE'] = "appid_default";
WebAppStrategy['ORIGINAL_URL'] = "APPID_ORIGINAL_URL";
WebAppStrategy['AUTH_CONTEXT'] = "APPID_AUTH_CONTEXT";

import logging
logging.basicConfig(filename='example.log',level=logging.DEBUG)


execfile("modals/serviceConfig.py")
execfile("utils/token-utils.py")

import random
import pandas as pd
import os
app = Flask(__name__)

# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jm3]LWX/,?RT'# for session
AUTHORIZATION_PATH = "/authorization"
TOKEN_PATH = "/token"
INTROSPECTION_PATH="/introspect"

#import the VCAP_SERVICES_VARIABLES
serviceConfig=ServiceConfig()
db2_auth=serviceConfig.db2_auth

import ibm_db
conn = ibm_db.connect(db2_auth, "", "")

#import boto
#import boto.s3.connection

import ibm_boto3
from ibm_botocore.client import Config

#https://github.com/IBM/ibm-cos-sdk-python/blob/master/README.md
#cos = ibm_boto3.resource('s3',
#                      ibm_api_key_id=api_key,
#                      ibm_service_instance_id=service_instance_id,
#                      ibm_auth_endpoint=auth_endpoint,
#                      config=Config(signature_version='oauth'),
#                      endpoint_url=service_endpoint)

api_key = ServiceConfig.cos_apikey
service_instance_id = serviceConfig.cos_service_id
auth_endpoint = serviceConfig.cos_auth_endpoint
service_endpoint = serviceConfig.cos_host

cos = ibm_boto3.resource('s3',
                      ibm_api_key_id=api_key,
                      ibm_service_instance_id=service_instance_id,
                      ibm_auth_endpoint=auth_endpoint,
                      config=Config(signature_version='oauth'),
                      endpoint_url=service_endpoint)

access_key=serviceConfig.cos_access_key
secret_key=serviceConfig.cos_secret_key
bucketname = "sabalcbucketname"
host = serviceConfig.cos_host
# CON MODULO 'BOTO' connCos = boto.connect_s3( aws_access_key_id=access_key, aws_secret_access_key=secret_key, host=host, calling_format= boto.s3.connection.OrdinaryCallingFormat(),)




sql = "SELECT COUNT (EMP_NUMBER) FROM SABALC.DEMO"
stmt = ibm_db.exec_immediate(conn, sql)
result = ibm_db.fetch_both(stmt)
#print result

port = int(os.getenv('PORT', 8000))


@app.route('/input')
def protected():
    logging.warning('pre-tokens:')
    tokens = session.get(WebAppStrategy['AUTH_CONTEXT'])
    #logging.warning('tokens:', tokens)
    logging.warning("<tokens>", tokens)
    #if (type(tokens) is str):
	#if ('trick' in tokens):
         #  return 'Appid working successfully thanks to an awesome trick'
    if (tokens):
        serviceConfig = ServiceConfig()
    	clientId = serviceConfig.clientId
        secret = serviceConfig.secret
        idToken = tokens.get('id_token')
        accessToken = tokens.get('access_token')
        idTokenPayload = getTokenPayload(idToken)
	accessTokenPayLoad = getTokenPayload(accessToken)
        if (not idToken or not accessToken):
            return startAuthorization()
        else:
            ans  = validateTokenWithIntrospection(idToken ,clientId,secret)
            if(ans==True):
             	return render_template('input.html')
 	    elif(ans==False): #token is expired
                return startAuthorization()
            else: #token is  not valid
		return startAuthorization()
    else:
        return startAuthorization()

@app.route('/startAuthorization')
def startAuthorization():
    serviceConfig=ServiceConfig()
    clientId = serviceConfig.clientId

    authorizationEndpoint = serviceConfig.serverUrl + AUTHORIZATION_PATH
    redirectUri = serviceConfig.redirectUri
    return redirect("{}?client_id={}&response_type=code&redirect_uri={}&scope=openid".format(authorizationEndpoint,clientId,redirectUri))


@app.route('/afterauth')
def afterauth():
    error = request.args.get('error')
    code = request.args.get('code')
    logging.warning(code)
    if error:
        return error
    elif code:
        return handleCallback(code)
    else:
        return '?'

#Taken from appId alcarria credentials-1
def retriveTokens(grantCode):
    serviceConfig=ServiceConfig()
    clientId = serviceConfig.clientId
    secret = serviceConfig.secret
    tokenEndpoint =  serviceConfig.serverUrl + TOKEN_PATH
    redirectUri = serviceConfig.redirectUri
#    requests.post(url, data={}, auth=('user', 'pass'))
    r = requests.post(tokenEndpoint, data={"grant_type": "authorization_code","redirect_uri": redirectUri,"code": grantCode}, auth=HTTPBasicAuth(clientId, secret))
    logging.debug(r.url)
    print(r.status_code, r.reason)
    logging.debug(r)
    logging.info(r.status_code)
    logging.warning(r.reason)
    if (r.status_code is not 200):
        return 'fail retrive'
    else:
        return r.json()

def handleCallback(grantCode):
    tokens = retriveTokens(grantCode)
    logging.debug('grant code')
    logging.debug(grantCode)
    if (type(tokens) is str):
        return tokens#it's error
	 #   return protected()
    else:
        if (tokens['access_token']):
            session[WebAppStrategy['AUTH_CONTEXT']] = tokens
            return protected()
        else:
            return 'fail callback'

def validateTokenWithIntrospection(token,client_id,client_secret):
    serviceConfig = ServiceConfig()
    url = serviceConfig.serverUrl + INTROSPECTION_PATH
    payload = token
    headers = {
        'content-type': "application/x-www-form-urlencoded",
        'authorization': "Basic " + base64.b64encode(client_id+':'+client_secret),
        'cache-control': "no-cache",
    }
    response = requests.request("POST", url, data="token=" +payload, headers=headers)
    print(response.text)
    if(response.status_code == 200):
        if(json.loads(response.text)['active']==True):
            return True
        if(json.loads(response.text)['active'] == False):
            return False;
    else:
        return response.text

@app.route('/randomInput')
def randomInput():
	rand = random.randint(900,10000)
	sql = "INSERT INTO SABALC.DEMO VALUES ("+str(rand)+",'ANGEL','ALCARRIA');"
	stmt = ibm_db.exec_immediate(conn, sql)
	print stmt
	return str(rand)

@app.route('/input2')
def input():
	return render_template("input.html")

@app.route('/')
def helloworld():
	return ("App Up -- modificacion para la demo de hoy en Almirall")

@app.route('/result',methods = ['POST'])
def result():
	sql = "SELECT * FROM SABALC.DEMO WHERE EMP_NUMBER = " +  request.form.get('number')
	stmt = ibm_db.exec_immediate(conn, sql)
	result = ibm_db.fetch_both(stmt)
	print result
	#return result
	if result == False:
	    # antes con BOTO --> #for bucket in connCos.get_all_buckets():
	    # antes con BOTO --> #    print "{name}\t{created}".format(name = bucket.name, created = bucket.creation_date,)
	    # antes con BOTO --> #mybucket = connCos.get_bucket(bucketname,validate=False)
	    # antes con BOTO --> #exists = connCos.lookup(bucketname)
	    # antes con BOTO --> #print bucket
	    # antes con BOTO --> #for key in mybucket.list():
	    # antes con BOTO --> #    print "{name}\t{size}\t{modified}".format(name = key.name, size = key.size, modified=key.last_modified,)
            # antes con BOTO --> key = bucket.get_key("data.csv")
	    # antes con BOTO --> key.get_contents_to_filename("data.csv")
	    cos.Bucket(bucketname).download_file('data.csv','data.csv')
	    df = pd.read_csv('data.csv',delimiter=',')
            find = df.loc[df['EMP_NUMBER'] == int(request.form.get('number'))]
            print find
            result = find
	return render_template("result.html",result = result)

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port= port)
