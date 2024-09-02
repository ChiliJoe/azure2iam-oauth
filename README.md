# Azure token validator for OCI API Gateway

This OCI Functions API Gateway authenticator is based on the approach descibed in [Authenticating Oracle Integration flows using OAuth token from 3rd party provider](https://blogs.oracle.com/integration/post/authenticating-oic-flows-through-third-party-bearer-token).

Code presented in the article has been refactored. The Azure token validation has been changed to use remote JWKS JWT validation. The basic userinfo endpoint validation doesn't work in all cases.

## Configuration variables
### General
* LOG_LEVEL (optional)
  * Log level for logging service. Defaults to WARNING. Valid values are DEBUG, INFO, WARNING, ERROR and CRITICAL.
* VAULT_REGION (optional)
  * Region of OCI vault where secret was created. Defaults to us-phoenix-1
### IAM
* IDCS_TOKEN_ENDPOINT
  * IAM token endpoint
* IDCS_APP_CLIENT_ID
  * IAM confidential application Client ID
* IDCS_APP_CLIENT_SECRET_OCID
  * Vault secret OCID containing the IAM confidential application Client Secret
* OIC_SCOPE
  * Scope of target application in the IAM confidential application
### Azure AD
* AD_JWKS_URL
  * Azure JWKS URI endpoint. This can be retrieved from https://login.microsoftonline.com/{ad-tenant}/.well-known/openid-configuration
* AD_ISSUER
  * Azure token issuer (iss)
* AD_AUDIENCE
  * Azure token target audience (aud)

## Output
If validation is successful, IAM token is retrieved and stored as `Bearer {token}` in the output context `back_end_token`. In OCI API Gateway, this can be used on the request header transformation as `${request.auth[back_end_token]}`.