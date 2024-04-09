import base64
import logging
import os

import hvac

from django.conf import settings

logger = logging.getLogger()


def get_secret(prefix, path, secret):
    if settings.USE_VAULT_SECRETS:
        vault_client = get_client()
        if not vault_client.is_authenticated() or vault_client.sys.is_sealed():
            logger.error("Could not authenticate to vault, exiting")
            exit(0)

        secret_data = vault_client.secrets.kv.v2.read_secret_version(mount_point=prefix, path=path)["data"]

        vault_client.auth.token.revoke_self()

        return secret_data["data"]

    return os.getenv(secret)


def write_secret(prefix, path, data, patch=False):
    vault_client = get_client()
    if not vault_client.is_authenticated() or vault_client.sys.is_sealed():
        logger.error("Could not authenticate to vault, exiting")
        exit(0)

    if patch:
        vault_client.secrets.kv.v2.patch(mount_point=prefix, path=path, secret=data)
    else:
        vault_client.secrets.kv.v2.create_or_update_secret(mount_point=prefix, path=path, secret=data)

    vault_client.auth.token.revoke_self()


def vault_decrypt(encrypted, kn, decode=False):
    if settings.USE_VAULT_SECRETS:
        vault_client = get_client()
        if not vault_client.is_authenticated() or vault_client.sys.is_sealed():
            logger.error("Could not authenticate to vault, exiting")
            exit(0)

        decrypted = vault_client.secrets.transit.decrypt_data(kn, encrypted)
        vault_client.auth.token.revoke_self()
        if not decode:
            return decrypted["data"]["plaintext"]

        return base64.b64decode(decrypted["data"]["plaintext"]).decode("utf-8")

    return encrypted


def vault_encrypt(decrypted, kn):
    if settings.USE_VAULT_SECRETS:
        vault_client = get_client()
        if not vault_client.is_authenticated() or vault_client.sys.is_sealed():
            logger.error("Could not authenticate to vault, exiting")
            exit(0)

        encrypted = vault_client.secrets.transit.encrypt_data(
            kn, plaintext=base64.urlsafe_b64encode(decrypted.encode()).decode("ascii")
        )
        # vault_client.revoke_self_token()
        vault_client.auth.token.revoke_self()

    return encrypted["data"]["ciphertext"]


def get_client():
    vault_client = hvac.Client(url=settings.VAULT_ADDR, token=os.getenv("VAULT_TOKEN"))

    approle_path = vault_client.secrets.kv.v2.read_secret_version(mount_point="socialpal_config", path="auth_settings")[
        "data"
    ]["data"]["approle_path"]

    approle_id = vault_client.auth.approle.read_role_id(approle_path)["data"]["role_id"]

    approle_secret = vault_client.auth.approle.generate_secret_id(approle_path)["data"]["secret_id"]

    vault_client.auth.approle.login(role_id=approle_id, secret_id=approle_secret)
    # rsp = vault_client.auth_approle(SID1, secret_id=SID2, use_token=True)
    if not vault_client.is_authenticated() or vault_client.sys.is_sealed():
        # try to get new secret
        # vault_client.auth.approle.
        logger.error("Could not authenticate to vault, exiting")
        exit(0)

    return vault_client
