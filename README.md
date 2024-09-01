# Azure token validator for OCI API Gateway

This OCI Functions API Gateway authenticator is based on the approach descibed in [Authenticating Oracle Integration flows using OAuth token from 3rd party provider](https://blogs.oracle.com/integration/post/authenticating-oic-flows-through-third-party-bearer-token).

Code presented in the article has been refactored. The Azure token validation has been changed to use remote JWKS JWT validation. The basic userinfo endpoint validation doesn't work in all cases.