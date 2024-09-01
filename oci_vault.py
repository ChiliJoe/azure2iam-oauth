import oci
import base64
import logging

class OCIVault:
    def __init__(self, region: str = 'us-phoenix-1', use_instance_principal: bool = True):
        self.region = region
        self.use_instance_principal = use_instance_principal

    def getSecret(self, ocid):
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