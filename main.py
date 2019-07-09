import os
import config
import json
import datetime

from functools import wraps
from flask import Flask, request, abort
from utils.rest import OktaUtil


"""
GLOBAL VARIABLES ########################################################################################################
"""
app = Flask(__name__)
app.secret_key = "6w_#w*~AVts3!*yd&C]jP0(x_1ssd]MVgzfAw8%fF+c@|ih0s1H&yZQC&-u~O[--"  # For the session


"""
UTILS ###################################################################################################################
"""
def default_date_to_string_converter(date_time):
    """ Helper for easily serializing json objects with date times """
    if isinstance(date_time, datetime.datetime):
        return date_time.__str__()


def authorize_read_access(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        """ Decorator fucntion to make endpoint authorization checks easier for read only scopes defined in Okta """
        print("authorize_read_access()")
        authorization_header = None
        has_access = False
        # If 
        if "Authorization" in request.headers:
            authorization_header = request.headers["Authorization"]
            authorization_token = authorization_header.replace("Bearer ", "") # Just get the access toke for introspection
            okta_util = OktaUtil(request.headers, config.okta)
            introspection_response = okta_util.introspect_oauth_token(authorization_token)
            # print "introspection_response: {0}".format(json.dumps(introspection_response, indent=4, sort_keys=True))
            if "active" in introspection_response:
                if introspection_response["scope"] == "read_only":
                    has_access = True
        
        # print "authorization_header: {0}".format(authorization_header)
        
        if has_access:
            return f(*args, **kws)
        else:
            print("Unauthorized")
            json_response = {
                "status": "failed"
            }
            
            return json.dumps(json_response, default=default_date_to_string_converter)
            
    return decorated_function


"""
ROUTES ##################################################################################################################
"""
@app.route('/public_api')
def public_api():
    """ handler for the public_api endpoint can be access publically with no protection"""
    print("public_api()")
    
    json_response = {
        "status": "success",
        "timestamp": datetime.datetime.now()
    }
    
    return json.dumps(json_response, default=default_date_to_string_converter)


@app.route('/read_api')
@authorize_read_access
def read_api():
    """ handler for the read_api endpoint can be access with read_only claim, can return extra custom scope"""
    print("read_api()")
    
    json_response = {
        "status": "success",
        "default_value": "Read Only",
        "timestamp": datetime.datetime.now()
    }
    
    return json.dumps(json_response, default=default_date_to_string_converter)


"""
CLIENT ROUTES #########################################################################################################
"""
@app.route('/call_read_api')
def call_read_api():
    """ Calls the read_api endpoint as a client server/app would"""
    print("call_read_api()")
    # Get Okta OAuth Token
    access_token = None
    json_response = {
            "status": "false",
            "timestamp": datetime.datetime.now()
        }
    okta_util = OktaUtil(request.headers, config.okta)
    oauth_url = "{0}/oauth2/{1}/v1/token?clientId={2}&grant_type=client_credentials&scope=read_only".format(
        config.okta["org_host"],
        config.okta["auth_server_id"],
        config.okta["oidc_client_id"])
    
    oauth_response = okta_util.execute_post(oauth_url, {}, okta_util.OKTA_OAUTH_HEADERS)
    print("oauth_response: {0}".format(json.dumps(oauth_response, indent=4, sort_keys=True)))
    if "access_token" in oauth_response:
        access_token = oauth_response["access_token"]
        # print "access_token: {0}".format(access_token)
        # Use OAuth token in header and request read_api endpoint
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(access_token)
        }
        json_response = okta_util.execute_get("{0}/read_api".format(config.okta["app_host"]), {}, headers)
        print("json_response: {0}".format(json.dumps(json_response, default=default_date_to_string_converter)))
    
    return json.dumps(json_response, default=default_date_to_string_converter)


"""
MAIN ##################################################################################################################
"""
if __name__ == "__main__":
    # This is to run on c9.io.. you may need to change or make your own runner
    
    config.okta["org_host"] = os.getenv("ORG_HOST", "")
    config.okta["api_token"] = os.getenv("API_TOKEN", "")
    config.okta["app_host"] = os.getenv("APP_HOST", "")
    config.okta["oidc_client_id"] = os.getenv("OIDC_CLIENT_ID", "")
    config.okta["oidc_client_secret"] = os.getenv("OIDC_CLIENT_SECRET", "")
    config.okta["auth_server_id"] = os.getenv("AUTH_SERVER_ID", "")
    
    print("okta_config: {0}".format(json.dumps(config.okta, indent=4, sort_keys=True)))
    
    
    app.run(threaded=True, host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)))