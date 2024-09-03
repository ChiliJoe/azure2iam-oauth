import oci
import base64
import logging

class OCIVault:
    """
    A class representing an OCI Vault.
    Args:
        region (str, optional): The OCI region. Defaults to 'us-phoenix-1'.
        use_instance_principal (bool, optional): Whether to use instance principal for authentication. Defaults to True.
    Methods:
        getSecret(ocid: str) -> str:
            Retrieves the secret content from the OCI Vault.
            Args:
                ocid (str): The OCID of the secret.
            Returns:
                str: The decrypted secret content.
            Raises:
                Exception: If there is an error retrieving the secret.
    """
    def __init__(self, region: str = 'us-phoenix-1', use_instance_principal: bool = True):
        self.region = region
        self.use_instance_principal = use_instance_principal

    def getSecret(self, ocid: str):
        """
        Retrieves a secret from the Oracle Cloud Infrastructure (OCI) Vault.

        Args:
            ocid (str): The OCID (Oracle Cloud Identifier) of the secret to retrieve.

        Returns:
            str: The decrypted content of the secret.

        Raises:
            Exception: If there is an error retrieving the secret.
        """
        if self.use_instance_principal:
            signer = oci.auth.signers.get_resource_principals_signer()
        try:
            if self.use_instance_principal:
                client = oci.secrets.SecretsClient({}, signer=signer)
            else:
                client = oci.secrets.SecretsClient(oci.config.from_file())
            client.base_client.set_region(self.region)
            secret_content = client.get_secret_bundle(ocid).data.secret_bundle_content.content.encode('utf-8')
            decrypted_secret_content = base64.b64decode(secret_content).decode('utf-8')
        except Exception as ex:
            logging.getLogger().error(f"getSecret: Failed to get Secret: {ex}")
            print('Error [getSecret]: Failed to retrieve', str(ex), flush=True)
            raise
        return decrypted_secret_content
