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
    """
    Loads the configuration dictionary for OAuth applications.
    Args:
        config (dict): The configuration dictionary containing the necessary parameters.
    Returns:
        dict: The dictionary containing the OAuth application configurations.
    Raises:
        Exception: If there is an error in getting the configuration or secrets.
    """
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
    """
    Retrieves a backend authentication token from the specified token endpoint.
    Args:
        token_endpoint (str): The URL of the token endpoint.
        client_id (str): The client ID used for authentication.
        client_secret (str): The client secret used for authentication.
        scope (str): The scope of the token.
    Returns:
        dict: The backend authentication token.
    Raises:
        Exception: If there is an error while retrieving the token.
    """
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
    """
    Retrieves the authentication context based on the provided token and client applications.
    Args:
        token (str): The authentication token.
        client_apps (dict): A dictionary containing the client application details.
    Returns:
        dict: The authentication context containing the active status, expiration time, principal, scope, and backend token.
    Raises:
        None
    Example:
        token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        client_apps = {
            'ad': {
                'jwks_url': 'https://example.com/jwks',
                'issuer': 'https://example.com',
                'audience': 'https://example.com/api'
            },
            'idcs': {
                'token_endpoint': 'https://example.com/token',
                'client_id': '1234567890',
                'client_secret': 'abcdefg',
                'scope': 'https://01234567891234560123456789123456.integration.ocp.oraclecloud.com:443urn:opc:resource:consumer::all'
            }
        }
        auth_context = getAuthContext(token, client_apps)
    """
    # Function implementation goes here
    pass
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

        auth_context['context'] = {'back_end_token': f"Bearer {backend_token['access_token']}"}

    else:
        # Azure token is not valid
        auth_context['active'] = False
        auth_context['wwwAuthenticate'] = f'Bearer realm="https://login.microsoftonline.com", oauth_error="{validator.error_message}"'
    
    return auth_context


def handler(ctx, data: io.BytesIO = None):
    """
    Handler function for processing OAuth authentication.
    Parameters:
    - ctx: The OCI Functions context object.
    - data: Optional parameter for input data as a BytesIO object.
    Returns:
    - A response object with the authentication result.
    Raises:
    - ValueError: If there is an error parsing the JSON payload.
    - Exception: If there is any other exception during the authentication process.
    """
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
