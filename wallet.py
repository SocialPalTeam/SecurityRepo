
import hashlib
import json
import logging
import traceback

from Crypto.Cipher import AES
from web3 import Web3
from web3.exceptions import ContractLogicError

from django.db import transaction
from django.utils import timezone
from SocialNetworks.models import SocialInteractions, SocialNetworks
from SocialNetworks.Telegram.utils import common
from SocialPal.security import vault
from Users.models import User, UserRequests, UserWallets
from WalletManager.lib import evm
from WalletManager.models import Chains

logger = logging.getLogger()


def create_wallet(
    chain: str,
    source: SocialNetworks,
    source_interaction: SocialInteractions | None,
    uname: str,
    uid: int,
):
    with transaction.atomic():
        r_chain = None
        try:
            r_chain = Chains.objects.get(name=chain)
        except Exception:
            error = "Invalid Chain"
            logger.warning(error)
            return {"status": False, "msg": error}

        if r_chain.protocol == 0:
            r_user = None
            created = False

            r_user, created = User.objects.create_social_user({"username": uname, "uid": uid, "network": source})

            if created is False:
                if r_user is not None:
                    error = "User Already registered!"
                else:
                    error = "User not created"
                logger.warning(error)
                return {"status": False, "msg": error, "reply": True}

            res = evm.create_wallet(r_chain)
            if res["status"] is False:
                try:
                    r_user.delete()
                    error = "This shouldn't happen ever"
                    logger.warning(error)
                except Exception:
                    logger.error("CREATE_WALLET_FALSE: " + traceback.format_exc())

                return {"status": False, "msg": error}

            uw = UserWallets()
            uw.chain = r_chain
            uw.primary_address = res["addr"]
            uw.passphrase = res["pk"]
            uw.active = 1
            uw.user = r_user
            uw.save()
            # prefix = settings.VAULT_PREFIX
            sdata = {
                "addr": res["addr"],
                "addrpk": res["pk"],
                "chain": r_chain.name,
                "seed": res["seed"],
            }
            jdata = json.dumps(sdata)
            hdata = hashlib.sha256(jdata.encode())
            k1 = hdata.hexdigest()[0:8]
            k2 = hashlib.sha256(str(r_user.id).encode()).hexdigest()[0:8]
            wkey = (k1 + k2).encode()

            cipher = AES.new(wkey, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(jdata.encode())
            cdata = {
                "data": ciphertext.hex(),
                "nonce": nonce.hex(),
                "tag": tag.hex(),
                "k": hdata.hexdigest(),
            }

            vault.write_secret("socialpal_seeds", res["addr"], cdata)
            rid = UserRequests(
                social_network=source,
                social_interaction=source_interaction,
                request_origin="api" if source_interaction is None else source_interaction.interaction_type,
                request_type="register",
                request_data="!register",
                user=r_user,
                processed=1,
                error_data=None,
                inserted_at=timezone.now(),
                processed_at=timezone.now(),
            )
            rid.save()
            res["msg"] = (
                common.get_messageTemplate(msg="USER_REGISTRATION", lang=r_user.language)["message"]
                .replace("#ADDR", res["addr"])
                .replace("#UNAME", source.name.capitalize())
            )

            return {
                "status": True,
                "msg": res["msg"],
                "reply": True,
                "fullres": res,
                "user": r_user,
            }
            
def get_vault_user_data(user: User):
    try:
        uw = UserWallets.objects.get(user=user, active=1)
        secret = vault.get_secret("socialpal_seeds", uw.primary_address, "data")
        k1 = secret["k"][0:8]
        k2 = hashlib.sha256(str(user.id).encode()).hexdigest()[0:8]
        decypher = AES.new((k1 + k2).encode(), AES.MODE_EAX, nonce=bytes.fromhex(secret["nonce"]))
        pdata = json.loads(decypher.decrypt(bytes.fromhex(secret["data"])))
        return pdata
    except Exception:
        error = traceback.format_exc()
        logger.error("GET_VAULT_USER_DATA: " + error)
        return False