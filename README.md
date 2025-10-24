# Passbolt API Client

## Description

This project is a Python client implementation for interacting with the [Passbolt](https://www.passbolt.com/) API, an open-source password manager for teams.

## Features

- Authentication with a GPG key, utilized JTW.
- Retrieve users and groups
- Creating users
- Create and delete groups, manage users
- Encrypt and decrypt messages using GPG
- Retrieve and manage Passbolt resources

## Prerequisites

- Python 3.x
- Passbolt installed and accessible via API
- A valid GPG key

## Installation

```sh
pip install passbolt-py
```

## Configuration

Configuration can be loaded from a dictionary or environment variables:

```sh
export PASSBOLT_GPG_BINARY=gpg
export PASSBOLT_GPG_LIBRARY=gnupg
export PASSBOLT_BASE_URL=https://passbolt.local
export PASSBOLT_PRIVATE_KEY=<passbolt_private_key>
export PASSBOLT_PASSPHRASE=<passphrase>
export PASSBOLT_VERIFY=False
export PASSBOLT_TIMEOUT=5.0
export PASSBOLT_USER_ID=<user_id>

```

## Usage

### Initializing the client

```python
from passbolt import PassboltAPI

# Initialization with configuration
config = {
    "gpg_binary": "gpg",
    "gpg_library": "gnupg",
    "base_url": "https://your-passbolt-instance.com",
    "private_key": "your-private-key",
    "passphrase": "your-passphrase",
    "verify": True,
    "timeout": 5.0,
    "user_id": "USER-ID-get-it-from-you-passbolt-instance",
}


client = PassboltAPI(dict_config=config)
```

### Retrieving users

```python
users = client.get_users()
print(users)
```

### Retrieving a user by email

```python
user = client.get_user_by_email("user@example.com")
print(user)
```

### Creating a group

```python
response = client.create_group("My Group")
print(response)
```

### Encrypting a message

```python
encrypted_message = client.encrypt("my secret password", public_key)
print(encrypted_message)
```

### Decrypting a message

```python
decrypted_message = client.decrypt(encrypted_message)
print(decrypted_message)
```

## Contributions

Contributions are welcome. Please follow best development practices and submit a pull request with your changes.

## License

This project is licensed under the MIT-0 License.
