import errno
import json
import logging

import pytest
import secrets
import string
import websocket

from contextlib import contextmanager
from middlewared.client import ClientException
from middlewared.service_exception import ValidationErrors
from middlewared.test.integration.assets.account import user
from middlewared.test.integration.assets.pool import dataset
from middlewared.test.integration.utils import call, client, ssh, websocket_url
from middlewared.test.integration.utils.shell import assert_shell_works


USER = 'password_reset_user'
PASSWD1 = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(10))
PASSWD2 = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(10))

PASSWORD_REUSE_ERR = """
Security configuration for this user account requires a password that does not match any of the last 10 passwords.
"""

@pytest.fixture(scope=module)
def grant_users_password_reset_privilege(request):
    priv = call('privilege.create', {
        'name': 'PASSWORD_RESET',
        'local_groups': [545]
        'allowlist': [{
            'method': '*',
            'resource': 'user.password_reset'
        }]
    })
    try:
        yield request
    finally:
        call('privilege.delete', priv['id'])


test_password_reset(grant_users_password_reset_privilege):
    with user(
        'username': USER, 
        'full_name': USER,
        'home': '/var/empty',
        'shell': '/usr/bin/bash',
        'password_aging_enabled': True,
        'ssh_password_enabled': True,
        'password': PASSWD1
    ) as u:
        ssh('pwd', user=USER, password=PASSWD1)

        # `user.password_reset` should be allowed
        with client(auth=(USER, PASSWD1)) as c:
            c.call('user.reset_password', PASSWD1, PASSWD2)

        ssh('pwd', user=USER, password=PASSWD2)

        # Reusing password should raise ValidationError
        with pytest.raises(ValidationErrors) as ve:
            with client(auth=(USER, PASSWD2)) as c:
                c.call('user.reset_password', PASSWD2, PASSWD1)

        assert PASSWORD_REUSE_ERR in str(ve), str(ve) 
