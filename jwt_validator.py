import jwt
from jwt import PyJWKClient
from abc import ABC, abstractmethod

class JWT_Validator(ABC):
    """
    Abstract base class for JWT validators.
    Attributes:
        payload (Any): The payload of the JWT.
        error_message (str): The error message if validation fails.
    Methods:
        validate_token(token: str) -> bool:
            Validates the given JWT token.
    """
    def __init__(self):
        self.payload = None
        self.error_message = None

    @abstractmethod
    def validate_token(self, token: str) -> bool:
        """
        Validates the given JWT token.
        Args:
            token (str): The JWT token to be validated.
        Returns:
            bool: True if the token is valid, False otherwise.
        """
        pass

class AzureToken_Validator(JWT_Validator):
    """
    Validates Azure tokens using JSON Web Key Set (JWKS).
    Args:
        jwks_url (str): The URL of the JWKS endpoint.
        issuer (str): The expected issuer of the token.
        audience (str): The expected audience of the token.
    Attributes:
        jwks_url (str): The URL of the JWKS endpoint.
        issuer (str): The expected issuer of the token.
        audience (str): The expected audience of the token.
        jwks_client (PyJWKClient): The client for retrieving JWKS.
        payload (dict): The decoded payload of the token.
        error_message (str): The error message if token validation fails.
    Methods:
        validate_token(token: str) -> bool:
            Validates the given token.
    """
    def __init__(self, jwks_url: str, issuer: str, audience: str):
        super().__init__()
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.audience = audience
        self.jwks_client = PyJWKClient(self.jwks_url)

    def validate_token(self, token: str) -> bool:
        """
        Validates the given token.
        Args:
            token (str): The token to be validated.
        Returns:
            bool: True if the token is valid, False otherwise.
        """
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