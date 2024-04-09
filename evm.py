import logging
import traceback
import uuid

from bip44 import Wallet
from bip44.utils import get_eth_addr
from coincurve import PrivateKey
from eth_account import Account
from mnemonic import Mnemonic
from web3 import Web3

from django.conf import settings
from WalletManager.models import Chains, Settings

logger = logging.getLogger()


def create_wallet(r_chain: Chains):
    try:
        valid = False
        while not valid:
            mnemonic = Mnemonic("english")
            userSeed = mnemonic.generate(strength=256)

            wallet = Wallet(userSeed)
            sk, pk = wallet.derive_account("eth", account=0)
            sk = PrivateKey(sk)
            sk.public_key.format() == pk
            private_key = sk.to_hex()
            addr = get_eth_addr(pk)
            if bool(int(Settings.objects.get(key="NEW_ADDR_VALIDATE").value)):
                w3 = Web3(Web3.HTTPProvider(r_chain.node_url))
                Account.enable_unaudited_hdwallet_features()
                acc = w3.eth.account.from_key(sk.to_hex())
                tx_count = w3.eth.get_transaction_count(acc.address)
                if tx_count == 0:
                    valid = True
            else:
                valid = True

            private_key += "+" + str(uuid.uuid4())
            if valid:
                return {
                    "pk": private_key,
                    "addr": addr,
                    "seed": userSeed,
                    "status": True,
                }

            return {
                "msg": "An error ocurred while creating the new address, please try again!",
                "status": False,
            }
    except Exception:
        err = traceback.format_exc()
        logger.error("CREATE_WALLET: " + err)
        return {"msg": err, "status": False}

