import jwt
from jwt import PyJWKClient
from abc import ABC, abstractmethod

class JWT_Validator(ABC):
    def __init__(self):
        self.payload = None
        self.error_message = None

    @abstractmethod
    def validate_token(self, token: str) -> bool:
        pass

class AzureToken_Validator(JWT_Validator):
    def __init__(self, jwks_url: str, issuer: str, audience: str):
        super().__init__()
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.audience = audience
        self.jwks_client = PyJWKClient(self.jwks_url)

    def validate_token(self, token: str) -> bool:
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)

        self.payload = None
        self.error_message = None
        try:
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"verify_exp": True}
            )
            self.payload = payload
            return True
        except jwt.ExpiredSignatureError:
            self.error_message = "Token has expired"
            return False
        except jwt.InvalidTokenError:
            self.error_message = "Invalid token"
            return False