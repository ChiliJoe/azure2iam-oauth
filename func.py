import io
import json
import logging
import requests
from requests.auth import HTTPBasicAuth

from fdk import response

from jwt_validator import AzureToken_Validator
from oci_vault import OCIVault

import datetime
from datetime import timedelta

def loadConfigDict(config: dict) -> dict:
    oauth_apps = {}
    try:
        logging.getLogger().info('initContext: Initializing context')

        if 'VAULT_REGION' in config:
            ociVault = OCIVault(region=config['VAULT_REGION'])
        else:
            ociVault = OCIVault()

        oauth_apps['idcs'] = {'token_endpoint': config['IDCS_TOKEN_ENDPOINT'],
                              'client_id': config['IDCS_APP_CLIENT_ID'],
                              'client_secret': ociVault.getSecret(config['IDCS_APP_CLIENT_SECRET_OCID']),
                              'scope': config['OIC_SCOPE']}
        oauth_apps['ad'] = {'jwks_url': config['AD_JWKS_URL'],
                            'issuer': config['AD_ISSUER'],
                            'audience': config['AD_AUDIENCE']}
        return oauth_apps
    
    except Exception as ex:
        logging.getLogger().error(f"initContext: Failed to get config or secrets {ex}")
        print('ERROR [initContext]: Failed to get the configs', ex, flush=True)
        raise


def getBackEndAuthToken(token_endpoint: str, client_id: str, client_secret: str, scope: str):
    payload = {'grant_type': 'client_credentials',
               'scope': scope}
    headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}

    try:
        backend_token = json.loads(requests.post(url=token_endpoint,
                                                 data=payload,
                                                 headers=headers,
                                                 auth=HTTPBasicAuth(client_id, client_secret)).text)

    except Exception as ex:
        logging.getLogger().error(f"getBackEndAuthToken: Failed to get IDCS token {ex}")
        raise

    return backend_token


def getAuthContext(token: str, client_apps: dict) -> dict:
    auth_context = {}
    azure_token = token[len('Bearer '):]

    validator = AzureToken_Validator(jwks_url=client_apps['ad']['jwks_url'],
                                     issuer=client_apps['ad']['issuer'],
                                     audience=client_apps['ad']['audience'])
    
    if validator.validate_token(azure_token):
        # expiry doesn't matter since this is only valid for this request
        expiresAt = (datetime.datetime.utcnow() + timedelta(seconds=60)).replace(tzinfo=datetime.timezone.utc).astimezone().replace(microsecond=0).isoformat()
        auth_context['active'] = True
        auth_context['expiresAt'] = expiresAt
        auth_context['principal'] = validator.payload['sub']
        auth_context['scope'] = client_apps['idcs']['scope']

        # retrive the backend token
        backend_token = getBackEndAuthToken(token_endpoint=client_apps['idcs']['token_endpoint'],
                                             client_id=client_apps['idcs']['client_id'],
                                             client_secret=client_apps['idcs']['client_secret'],
                                             scope=client_apps['idcs']['scope'])

        auth_context['context'] = {'backend_token': f"Bearer {backend_token['access_token']}"}

    else:
        # Azure token is not valid
        auth_context['active'] = False
        auth_context['wwwAuthenticate'] = f'Bearer realm="https://login.microsoftonline.com", oauth_error="{validator.error_message}"'
    
    return auth_context


def handler(ctx, data: io.BytesIO = None):
    oauth_apps = loadConfigDict(dict(ctx.Config()))
    logging.getLogger().info(data.getvalue())
    
    try:
        gateway_auth = json.loads(data.getvalue())

        auth_context = getAuthContext(token=gateway_auth['token'], client_apps=oauth_apps)

        if (auth_context['active']):
            logging.getLogger().info('Token is valid...')
            return response.Response(
                ctx,
                response_data=json.dumps(auth_context),
                status_code=200,
                headers={"Content-Type": "application/json"}
                )
        else:
            logging.getLogger().info('Token is invalid...')
            return response.Response(
                ctx,
                response_data=json.dumps(auth_context),
                status_code=401,
                headers={"Content-Type": "application/json"}
                )

    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))

        return response.Response(
            ctx, response_data=json.dumps(
                {"message": "Error parsing json payload"}),
            headers={"Content-Type": "application/json"}
        )
