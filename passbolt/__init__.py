#!/tools/python/python
# coding: utf-8
# pyright: reportMissingImports=false
# pyright: reportOptionalOperand=false
# pyright: reportOptionalSubscript=false
# pylint: disable=import-error
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-public-methods

"""Passbolt"""

import json
import os
import warnings
from datetime import datetime, timedelta
import uuid
import gnupg
import requests
from pgpy import PGPKey, PGPMessage

warnings.filterwarnings(
    "ignore",
    ".*deprecated.*",
)


# https://pgpy.readthedocs.io/en/latest/examples.html


class PassboltAPI:
    """Passbolt API Class"""

    def __init__(
        self,
        dict_config=None,
    ):

        self.load_config(
            dict_config=dict_config,
        )

        # Load key
        self.passphrase = str(self.config.get("passphrase", None))
        self.base_url = self.config.get("base_url")
        self.user_id = self.config.get("user_id")
        if self.config.get("gpg_library", "PGPy") == "gnupg":
            self.gpg = gnupg.GPG(gpgbinary=self.config.get("gpgbinary", "gpg"))
            self.key = self.gpg.import_keys(key_data=self.config.get('private_key'), passphrase=self.passphrase)
            self.fingerprint = self.key.fingerprints[0].replace(" ", "")
            self.server_pub_key = self.gpg.import_keys(self.get_verify(self.base_url))
            self.server_pub_fingerprint = self.server_pub_key.fingerprints[0].replace(" ", "")
        else:
            self.key, _ = PGPKey.from_blob(self.config.get("private_key"))
            self.fingerprint = self.key.fingerprint.replace(" ", "")
            self.server_pub_key = self.gpg.import_keys(self.get_verify(self.base_url))
            self.server_pub_fingerprint = self.server_pub_key.fingerprints[0].replace(" ", "")



        self.login_url = f"{self.base_url}/auth/login.json"
        self.users_url = f"{self.base_url}/users.json"
        self.me_url = f"{self.base_url}/users/me.json"
        self.groups_url = f"{self.base_url}/groups.json"
        self.verify = self.config.get("verify", True)
        self.timeout = float(self.config.get("timeout", 5.0))

        # vars definition
        self.authenticated = False

        self.pgp_message = None
        self.jwt_token = None



        self.jwt_token = self.get_jwt_token(base_url=self.base_url, user_id=self.user_id, passphrase=self.passphrase)
        print("Test")

        # resource types
        self.resource_types = self.get_resource_type_ids()

    def load_config(
        self,
        dict_config=None,
    ):
        """Load Config"""

        if dict_config:
            self.config = dict_config
        else:
            self.config = {
                "gpg_binary": os.environ.get("PASSBOLT_GPG_BINARY", "gpg"),
                "gpg_library": os.environ.get("PASSBOLT_GPG_LIBRARY", "PGPy"),
                "base_url": os.environ.get("PASSBOLT_BASE_URL", "https://undefined"),
                "private_key": os.environ.get("PASSBOLT_PRIVATE_KEY", "undefined"),
                "passphrase": os.environ.get("PASSBOLT_PASSPHRASE", "undefined"),
                "fingerprint": os.environ.get("PASSBOLT_FINGERPRINT", "undefined"),
                "verify": os.environ.get("PASSBOLT_VERIFY", True),
                "timeout": os.environ.get("PASSBOLT_TIMEOUT", 5.0),
            }

    def decrypt(self, message):
        """Decrypt"""

        if self.config.get("gpg_library", "PGPy") == "gnupg":
            decrypt = self.gpg.decrypt(message)
            return decrypt

        pgp_message = PGPMessage.from_blob(message)
        with self.key.unlock(self.config.get("passphrase")):
            return self.key.decrypt(pgp_message).message

    def encrypt(self, message, public_key):
        """
        Encrypt a message for a given public key

        :param message: message to encrypt
        :type message: str
        :public_key: passbolt gpgkey object
        :type public_key: dict
        :returns: Encrypted message
        :rtype: str
        """
        if isinstance(message, dict):
            message = json.dumps(message)
        if self.config.get("gpg_library", "PGPy") == "gnupg":
            self.gpg.import_keys(public_key["armored_key"])
            encrypt = self.gpg.encrypt(
                message,
                public_key["fingerprint"],
                always_trust=True,
                sign=self.fingerprint,
            )
            return str(encrypt)

        pubkey, _ = PGPKey.from_blob(public_key["armored_key"])
        pgp_message = PGPMessage.new(message)
        with self.key.unlock(self.config.get("passphrase")):
            pgp_message |= self.key.sign(pgp_message)
        return str(pubkey.encrypt(pgp_message))

    def get_jwt_token(self, base_url: str, user_id: str, passphrase: str) -> requests.Response:
        """Authenticate against Passbolt by exchanging a signed JWT challenge.

        :param base_url: Base URL of the Passbolt instance.
        :param user_id: UUID assigned to the Passbolt user.
        :param passphrase: Passphrase protecting the private key.
        :returns: HTTP response object returned by the JWT login endpoint.
        :raises RuntimeError: If the GPG encryption step fails.
        """
        json_payload = {
            "version": "1.0.0",
            "domain": base_url,
            "verify_token": str(uuid.uuid4()),
            "verify_token_expiry": int((datetime.now() + timedelta(minutes=2)).timestamp()),
        }

        encrypted_data = self.gpg.encrypt(
            json.dumps(json_payload),
            recipients=[self.server_pub_fingerprint],
            sign=self.fingerprint,
            always_trust=True,
            passphrase=self.passphrase,
        )

        if not encrypted_data.ok:
            raise RuntimeError(f"Encryption failed: {encrypted_data.status}")

        url = f"{base_url}/auth/jwt/login.json"
        payload = {
            "user_id": user_id,
            "challenge": str(encrypted_data),
        }

        response = requests.post(url, json=payload, verify=False)
        data = json.loads(response.text)
        if(data['header']['code'] == 200):
            decrypted_challange = self.gpg.decrypt(data["body"]["challenge"])
            self.authenticated = True

            return json.loads(decrypted_challange.data)
        else:
            return None

    def get_verify(self, domain: str) -> str:
        """Retrieve the verification key block from the Passbolt server.

        :param domain: Base URL of the Passbolt instance.
        :returns: Armored public key block as a string.
        :raises requests.HTTPError: If the verification endpoint returns an error.
        """
        url = f"{domain}/auth/verify.json"
        response = requests.get(url, verify=False)
        response.raise_for_status()
        return json.loads(response.text)["body"]["keydata"]

    def get_users(self):
        """Get Users"""

        response = requests.get(
            url=self.users_url,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
            )
        decoded_response = json.loads(response.text)
        return decoded_response["body"]

    def get_groups(self):
        """Get Groups"""

        response = requests.get(
            url=self.groups_url,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )
        decoded_response = json.loads(response.text)
        return decoded_response["body"]

    def get_user_by_email(self, email):
        """Get Users By Email"""

        users = self.get_users()
        for user in users:
            if user["username"] == email:
                return user

        return None

    def get_user_by_id(self, user_id):
        """Get Users By Id"""
        users = self.get_users()
        for user in users:
            if user["id"] == user_id:
                return user

        return None

    def get_group_by_name(self, group_name):
        """Get Group By Name"""

        groups = self.get_groups()
        for group in groups:
            if group["name"] == group_name:
                return group

        return None

    def create_group(self, group_name):
        """Create Group"""

        post = {
            "name": group_name,
            "groups_users": [{"user_id": self.user_id, "is_admin": True}],
        }

        response = requests.post(
            url=self.groups_url,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
            json=post
        )

        return response

    def remove_group(self, group_name):
        """Remove Group"""

        post = {
            "name": group_name,
            "groups_users": [{"user_id": self.user_id, "is_admin": True}],
        }

        response = requests.delete(
            url=self.groups_url,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
            json=post
        )

        return response

    def put_user_on_group(self, group_id, user_id, admin=False):
        """Put User On Group"""

        post = {
            "id": group_id,
            "groups_users": [{"user_id": user_id, "is_admin": admin}],
        }
        url = f"{self.base_url}/groups/{group_id}/dry-run.json"
        response = requests.put(
            url=url,
            json=post,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )
        if response.status_code == 200:
            user_key = self.get_user_public_key(user_id)
            secrets = json.loads(response.text)["body"]["dry-run"]["Secrets"]

            secrets_list = []
            for secret in secrets:
                decrypted = self.decrypt(secret["Secret"][0]["data"])
                reencrypted = self.encrypt(str(decrypted), user_key)

                secrets_list.append(
                    {
                        "resource_id": secret["Secret"][0]["resource_id"],
                        "user_id": user_id,
                        "data": str(reencrypted),
                    }
                )

            post = {
                "id": group_id,
                "groups_users": [{"user_id": user_id, "is_admin": admin}],
                "secrets": secrets_list,
            }

            url = f"{self.base_url}/groups/{group_id}.json"
            response = requests.put(
                url=url,
                json=post,
                headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
                verify=False,
            )
        else:
            print(response.headers)
            print()
            print(response.text)
            print()

        return response

    def remove_user_from_group(self, user_id, group_id):
        """Remove User from Group"""
        user_to_delete =self.get_user_by_id(user_id=user_id)
        for group in user_to_delete['groups_users']:
            if(group['group_id'] == group_id):
                groups_users_relationship_uuid = group['id']
        post = {
            "id": group_id,
            "groups_users": [{"id": groups_users_relationship_uuid, "delete": True}],
        }
        url = f"{self.base_url}/groups/{group_id}/dry-run.json"
        responde_dry_run = requests.put(
            url=url,
            json=post,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )
        if responde_dry_run.status_code == 200:
            user_key = self.get_user_public_key(user_id)
            secrets = json.loads(responde_dry_run.text)["body"]["dry-run"]["Secrets"]

            secrets_list = []
            for secret in secrets:
                decrypted = self.decrypt(secret["Secret"][0]["data"])
                reencrypted = self.encrypt(str(decrypted), user_key)

                secrets_list.append(
                    {
                        "resource_id": secret["Secret"][0]["resource_id"],
                        "user_id": user_id,
                        "data": str(reencrypted),
                    }
                )

            post = {
                "id": group_id,
                "groups_users": [{"id": groups_users_relationship_uuid, "delete": True}]

            }

            url = f"{self.base_url}/groups/{group_id}.json"
            response = requests.put(
                url=url,
                json=post,
                headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
                verify=False,
            )
        else:
            print(responde_dry_run.headers)
            print()
            print(responde_dry_run.text)
            print()

        return response

    def get_group_by_id(self, group_id):
        """Get Group By Id"""

        groups = self.get_groups()
        for group in groups:
            if group["id"] == group_id:
                return group

        return None

    def get_group_user_id(self, group_id, user_id):
        """Get Group User Id"""

        user = self.get_user_by_id(user_id)
        for group in user["groups_users"]:
            if group["group_id"] == group_id:
                return group["id"]

        return None

    def update_user_to_group_admin(self, group_id, user_id):
        """Update User To Group Admin"""

        group_user_id = self.get_group_user_id(group_id, user_id)

        post = {
            "id": group_id,
            "groups_users": [{"id": group_user_id, "is_admin": True}],
        }
        url = f"{self.base_url}/groups/{group_id}/dry-run.json"
        response = requests.put(
            url=url,
            json=post,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )
        if response.status_code == 200:
            url = f"{self.base_url}/groups/{group_id}.json"
            response = requests.put(
                url=url,
                json=post,
                headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
                verify=False,
            )
        else:
            print(response.headers)
            print()
            print(response.text)
            print()

        return response

    def get_user_public_key(self, user_id):
        """
        Return a gpgkey dictionary based on passbolt user_id parameter

        {'armored_key': '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n'
                        'Version: OpenPGP.js v4.10.9\r\n'
                        'Comment: https:\\/\\/openpgpjs.org\r\n'
                        '\r\n'
                        '-----END PGP PUBLIC KEY BLOCK-----\r\n',
         'bits': 2048,
         'created': '2022-01-14T10:19:30+00:00',
         'deleted': False,
         'expires': None,
         'fingerprint': '1321159AE7BEE9EF9C4BBC7ECBAD2FB0C22FE70C',
         'id': '9a339ea9-ce31-40cc-8b66-f592e3d5acfa',
         'key_created': '2022-01-14T10:19:24+00:00',
         'key_id': 'C22FE70C',
         'modified': '2022-01-14T10:19:30+00:00',
         'type': 'RSA',
         'uid': 'John Doe <johndoe@domain.tld>',
         'user_id': 'd9143b6d-82bb-4093-9272-6471e222e990'}

        :param user_id: The passbolt user_id we want to retrieve
        :type user_id: str
        :returns: gpgkey dictionary
        :rtype: dict
        """

        url = f"{self.base_url}/users/{user_id}.json"
        response = requests.get(
            url=url,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )

        user = json.loads(response.text)["body"]
        return user["gpgkey"]

    def get_resource_secret(self, resource_id):
        """Get Resource Secret"""

        url = f"{self.base_url}/secrets/resource/{resource_id}.json"
        response = requests.get(
            url=url,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )

        secrete_data = json.loads(response.text)["body"]["data"]
        return secrete_data

    def get_resources(self):
        """Get Resources"""

        url = f"{self.base_url}/resources.json"
        response = requests.get(
            url=url,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )

        secrete_data = json.loads(response.text)["body"]
        return secrete_data

    def get_resource_per_uuid(self, uuid):
        """Get Resource Per UUID"""

        url = f"{self.base_url}/resources/{uuid}.json"
        response = requests.get(
            url=url,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )

        secrete_data = json.loads(response.text)["body"]
        return secrete_data

    def create_resource(self, resource):
        """Create Resource"""

        return requests.post(
            url=f"{self.base_url}/resources.json",
            json=resource,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )

    def get_resource_types(self):
        """
        Returns all available resource types. Currently 2 resources types available:
        * password-string
        * password-and-description

        :returns: available resources types
        :rtype: dict
        """

        response = requests.get(
            url=f"{self.base_url}/resource-types.json",
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}", },
            verify=False,
        )
        decoded_response = json.loads(response.text)
        return decoded_response["body"]

    def get_resource_type_ids(self, per="slug"):
        """Get Resource Type Ids"""

        res = {}
        for item in self.get_resource_types():
            res[item[per]] = item["id"]
        return res

    def create_user(self, username: str, first_name: str, last_name: str):
        """Create a new Passbolt user with the provided profile details."""
        payload = {
            "username": username,
            "profile": {
                "first_name": first_name,
                "last_name": last_name,
            },
        }
        response = requests.post(
            self.users_url,
            headers={"Authorization": f"Bearer {self.jwt_token['access_token']}"},
            json=payload,
            verify=False,
        )
        response.raise_for_status()
        return response.json()



