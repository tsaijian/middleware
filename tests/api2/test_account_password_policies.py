import pytest
import secrets
import string

from middlewared.service_exception import ValidationErrors
from middlewared.test.integration.assets.account import user
from middlewared.test.integration.utils import call, client, ssh


USER = 'password_reset_user'
PASSWD1 = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(10))
PASSWD2 = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(10))
PASSWD3 = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(10))

PASSWORD_REUSE_ERR = """
Security configuration for this user account requires a password that does not match any of the last 10 passwords.
"""

PASSWORD_TOO_RECENTLY_CHANGED_ERR = """
Password was changed too recently
"""


@pytest.fixture(scope='module')
def grant_users_password_reset_privilege(request):
    priv = call('privilege.create', {
        'name': 'PASSWORD_RESET',
        'local_groups': [545],
        'allowlist': [{
            'method': '*',
            'resource': 'user.reset_password'
        }],
        'web_shell': False
    })
    try:
        yield request
    finally:
        call('privilege.delete', priv['id'])


def test_password_reset(grant_users_password_reset_privilege):
    with user({
        'username': USER,
        'full_name': USER,
        'group_create': True,
        'home': '/var/empty',
        'shell': '/usr/bin/bash',
        'password_aging_enabled': True,
        'ssh_password_enabled': True,
        'password': PASSWD1
    }) as u:
        ssh('pwd', user=USER, password=PASSWD1)

        # `user.password_reset` should be allowed
        with client(auth=(USER, PASSWD1)) as c:
            c.call('user.reset_password', PASSWD1, PASSWD2)

        ssh('pwd', user=USER, password=PASSWD2)

        # Reusing password should raise ValidationError
        with client(auth=(USER, PASSWD2)) as c:
            c.call('user.reset_password', PASSWD2, PASSWD1)

        with pytest.raises(ValidationErrors) as ve:
            with client(auth=(USER, PASSWD1)) as c:
                c.call('user.reset_password', PASSWD1, PASSWD2)

        #assert PASSWORD_REUSE_ERR in str(ve.errors[0]), str(ve.errors[0])

        # Make sure we can change back to password with nonsense
        # turned off
        call('user.update', u['id'], {'password_aging_enabled': False})
        with client(auth=(USER, PASSWD1)) as c:
            c.call('user.reset_password', PASSWD1, PASSWD2)

        call('user.update', u['id'], {
            'password_aging_enabled': True,
            'min_password_age': 1,
        })

        # Trying to change password too quickly should raise an error
        with pytest.raises(ValidationErrors) as ve:
            with client(auth=(USER, PASSWD2)) as c:
                c.call('user.reset_password', PASSWD2, PASSWD3)

        #assert PASSWORD_TOO_RECENTLY_CHANGED_ERR in str(ve), str(ve)
