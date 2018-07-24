import os
import json

class ServiceConfig():

    REDIRECT_URI = "redirectUri"
    def getParamFromVcap(parsedVcap,serviceName,field):
	if ('access_key' in field):
            return parsedVcap.get(serviceName)[0]['credentials']['cos_hmac_keys'][field]
	elif ('name' in field):
	    return parsedVcap.get(serviceName)[0][field]
        else:
	    return parsedVcap.get(serviceName)[0]['credentials'][field]
    def getParamFromVcap_k8s(parsedVcap,serviceName,field):
	return parsedVcap.get()[field]
    def getRedirectUri():
        redirectUri=os.environ.get('REDIRECT_URI')
        if not redirectUri:
            vcapApplication=os.environ.get('VCAP_APPLICATION')
            if vcapApplication:
                vcapApplication=json.loads(vcapApplication)
                redirectUri = "https://{}/afterauth".format(vcapApplication["application_uris"][0]);
            else:
                redirectUri='http://localhost:8000/afterauth'
        return redirectUri
    serverUrl='https://appid-oauth.eu-de.bluemix.net/oauth/v3/bdf69d1a-bb09-4476-8ba6-9b2de2a60943'
    VCAP_SERVICES=os.environ.get('VCAP_SERVICES')
    if VCAP_SERVICES:
        parsedVcap = json.loads(VCAP_SERVICES)
        serviceName=None
        if (parsedVcap.get('AppID')):
            serviceName='AppID'
	    serverUrl=getParamFromVcap(parsedVcap,serviceName,'oauthServerUrl')
            secret=getParamFromVcap(parsedVcap,serviceName,'secret')
            clientId=getParamFromVcap(parsedVcap,serviceName,'clientId')
            redirectUri=getRedirectUri()
 	if (parsedVcap.get('cloud-object-storage')):
            serviceName='cloud-object-storage'
            cos_access_key=getParamFromVcap(parsedVcap,serviceName,'access_key_id')
            cos_secret_key=getParamFromVcap(parsedVcap,serviceName,'secret_access_key')
            cos_host="https://s3.eu-geo.objectstorage.softlayer.net"
            cos_apikey=getParamFromVcap(parsedVcap,serviceName,'apikey')
            cos_service_id=getParamFromVcap(parsedVcap,serviceName,'name')
            cos_auth_endpoint='https://iam.bluemix.net/oidc/token'
 	if (parsedVcap.get('dashDB For Transactions')):
            serviceName='dashDB For Transactions'
	    db2_auth=getParamFromVcap(parsedVcap,serviceName,'ssldsn')
    else:
    	VCAP_SERVICES=os.environ.get('VCAP_SERVICES_Appid')
	redirectUri= 'https://webappfordb2andcos.eu-de.containers.appdomain.cloud/afterauth'
	if VCAP_SERVICES:
            parsedVcap = json.loads(VCAP_SERVICES)
	    serverUrl=parsedVcap['oauthServerUrl']
            secret=parsedVcap['secret']
            clientId=parsedVcap['clientId']
	    redirectUri= 'https://webappfordb2andcos.eu-de.containers.appdomain.cloud/afterauth'
    	VCAP_SERVICES=os.environ.get('VCAP_SERVICES_COS')
	if VCAP_SERVICES:
            parsedVcap = json.loads(VCAP_SERVICES)
            cos_access_key=parsedVcap['cos_hmac_keys']['access_key_id']
            cos_secret_key=parsedVcap['cos_hmac_keys']['secret_access_key']
            cos_host="https://s3.eu-geo.objectstorage.softlayer.net"
            cos_apikey=parsedVcap['apikey']
            cos_service_id=parsedVcap['name']
            cos_auth_endpoint='https://iam.bluemix.net/oidc/token'
    	VCAP_SERVICES=os.environ.get('VCAP_SERVICES_DB2')
	if VCAP_SERVICES:
            parsedVcap = json.loads(VCAP_SERVICES)
	    db2_auth=parsedVcap['ssldsn']

    if (not serverUrl):
        raise 'please choose server url'


    @property
    #metodo que rescata contenido variable return <variable>
    def get_cos_apikey(self):
        return cos_apikey

    @property
    def get_cos_service_id(self):
        return cos_service_id

    @property
    def get_cos_auth_endpoint(self):
        return cos_auth_endpoint

    @property
    def get_clientId(self):
        return 'clientId'

    @property
    def get_cos_access_key(self):
        return cos_access_key

    @property
    def get_cos_secret_key(self):
        return cos_secret_key

    @property
    def get_cos_host(self):
        return cos_host

    @property
    def get_db2_auth(self):
        return db2_auth

    @property
    def get_secret(self):
        return secret

    @property
    def get_serverUrl(self):
        return serverUrl

    def get_redirectUri(self):
        return redirectUri

    def __repr__(self):
        print ('{} {} {} {} '.format(clientId,secret,tokenEndpoint,redirectUri))
	return '<serviceConfig %r>' % (self.client_id)
