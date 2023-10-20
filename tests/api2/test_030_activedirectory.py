#!/usr/bin/env python3

import os
import ipaddress
import json
import sys
import pytest
from pytest_dependency import depends
from time import sleep
apifolder = os.getcwd()
sys.path.append(apifolder)
from assets.REST.directory_services import active_directory, override_nameservers
from assets.REST.pool import dataset
from auto_config import pool_name, ip, user, password, ha
from functions import GET, POST, PUT, DELETE, SSH_TEST, cmd_test, make_ws_request, wait_on_job
from protocols import smb_connection, smb_share

from middlewared.test.integration.assets.privilege import privilege
from middlewared.test.integration.utils import call, client

if ha and "hostname_virtual" in os.environ:
    hostname = os.environ["hostname_virtual"]
else:
    from auto_config import hostname

try:
    from config import AD_DOMAIN, ADPASSWORD, ADUSERNAME, ADNameServer, AD_COMPUTER_OU
    AD_USER = fr"AD02\{ADUSERNAME.lower()}"
except ImportError:
    Reason = 'ADNameServer AD_DOMAIN, ADPASSWORD, or/and ADUSERNAME are missing in config.py"'
    pytestmark = pytest.mark.skip(reason=Reason)


SMB_NAME = "TestADShare"


def remove_dns_entries(payload):
    res = make_ws_request(ip, {
        'msg': 'method',
        'method': 'dns.nsupdate',
        'params': [{'ops': payload}]
    })
    error = res.get('error')
    assert error is None, str(error)


def cleanup_forward_zone():
    res = make_ws_request(ip, {
        'msg': 'method',
        'method': 'dnsclient.forward_lookup',
        'params': [{'names': [f'{hostname}.{AD_DOMAIN}']}]
    })
    error = res.get('error')

    if error and error['trace']['class'] == 'NXDOMAIN':
        # No entry, nothing to do
        return

    assert error is None, str(error)
    ips_to_remove = [rdata['address'] for rdata in res['result']]

    payload = []
    for i in ips_to_remove:
        addr = ipaddress.ip_address(i)
        payload.append({
            'command': 'DELETE',
            'name': f'{hostname}.{AD_DOMAIN}.',
            'address': str(addr),
            'type': 'A' if addr.version == 4 else 'AAAA'
        })

    remove_dns_entries(payload)


def cleanup_reverse_zone():
    res = make_ws_request(ip, {
        'msg': 'method',
        'method': 'activedirectory.ipaddresses_to_register',
        'params': [
            {'hostname': f'{hostname}.{AD_DOMAIN}.', 'clustered': False, 'bindip': []},
            False
        ],
    })
    error = res.get('error')
    assert error is None, str(error)
    ptr_table = {f'{ipaddress.ip_address(i).reverse_pointer}.': i for i in res['result']}

    res = make_ws_request(ip, {
        'msg': 'method',
        'method': 'dnsclient.reverse_lookup',
        'params': [{'addresses': list(ptr_table.values())}],
    })
    error = res.get('error')
    if error and error['trace']['class'] == 'NXDOMAIN':
        # No entry, nothing to do
        return

    assert error is None, str(error)

    payload = []
    for host in res['result']:
        reverse_pointer = host["name"]
        assert reverse_pointer in ptr_table, str(ptr_table)
        addr = ipaddress.ip_address(ptr_table[reverse_pointer])
        payload.append({
            'command': 'DELETE',
            'name': host['target'],
            'address': str(addr),
            'type': 'A' if addr.version == 4 else 'AAAA'
        })

    remove_dns_entries(payload)


@pytest.fixture(scope="module")
def set_ad_nameserver(request):
    with override_nameservers(ADNameServer) as ns:
        yield (request, ns)


def test_01_set_nameserver_for_ad(set_ad_nameserver):
    assert set_ad_nameserver[1]['nameserver1'] == ADNameServer


def test_02_cleanup_nameserver(request):
    results = POST("/activedirectory/domain_info/", AD_DOMAIN)
    assert results.status_code == 200, results.text
    domain_info = results.json()

    res = make_ws_request(ip, {
        'msg': 'method',
        'method': 'kerberos.get_cred',
        'params': [{
            'dstype': 'DS_TYPE_ACTIVEDIRECTORY',
            'conf': {
                'bindname': ADUSERNAME,
                'bindpw': ADPASSWORD,
                'domainname': AD_DOMAIN,
            }
        }],
    })
    error = res.get('error')
    assert error is None, str(error)
    cred = res['result']

    res = make_ws_request(ip, {
        'msg': 'method',
        'method': 'kerberos.do_kinit',
        'params': [{
            'krb5_cred': cred,
            'kinit-options': {
                'kdc_override': {
                    'domain': AD_DOMAIN.upper(),
                    'kdc': domain_info['KDC server']
                },
            }
        }],
    })
    error = res.get('error')
    assert error is None, str(error)

    # Now that we have proper kinit as domain admin
    # we can nuke stale DNS entries from orbit.
    #
    cleanup_forward_zone()
    cleanup_reverse_zone()


def test_03_get_activedirectory_data(request):
    global results
    results = GET('/activedirectory/')
    assert results.status_code == 200, results.text


def test_05_get_activedirectory_state(request):
    results = GET('/activedirectory/get_state/')
    assert results.status_code == 200, results.text
    assert results.json() == 'DISABLED', results.text


def test_06_get_activedirectory_started_before_starting_activedirectory(request):
    results = GET('/activedirectory/started/')
    assert results.status_code == 200, results.text
    assert results.json() is False, results.text


@pytest.mark.dependency(name="ad_works")
def test_07_enable_leave_activedirectory(request):
    global domain_users_id
    with active_directory(AD_DOMAIN, ADUSERNAME, ADPASSWORD,
        netbiosname=hostname,
        createcomputer=AD_COMPUTER_OU,
        dns_timeout=15
    ) as ad:
        # Verify that we're not leaking passwords into middleware log
        cmd = f"""grep -R "{ADPASSWORD}" /var/log/middlewared.log"""
        results = SSH_TEST(cmd, user, password, ip)
        assert results['result'] is False, str(results['output'])

        # Verify that AD state is reported as healthy
        results = GET('/activedirectory/get_state/')
        assert results.status_code == 200, results.text
        assert results.json() == 'HEALTHY', results.text

        # Verify that `started` endpoint works correctly
        results = GET('/activedirectory/started/')
        assert results.status_code == 200, results.text
        assert results.json() is True, results.text


        # Verify that idmapping is working
        results = POST("/user/get_user_obj/", {'username': AD_USER, 'sid_info': True})
        assert results.status_code == 200, results.text
        assert results.json()['pw_name'] == AD_USER, results.text
        pw = results.json()
        domain_users_id = pw['pw_gid']

        # Verify winbindd information
        assert pw['sid_info'] is not None, results.text
        assert not pw['sid_info']['sid'].startswith('S-1-22-1-'), results.text
        assert pw['sid_info']['domain_information']['domain'] != 'LOCAL', results.text
        assert pw['sid_info']['domain_information']['domain_sid'] is not None, results.text
        assert pw['sid_info']['domain_information']['online'], results.text
        assert pw['sid_info']['domain_information']['activedirectory'], results.text

        res = make_ws_request(ip, {
            'msg': 'method',
            'method': 'dnsclient.forward_lookup',
            'params': [{'names': [f'{hostname}.{AD_DOMAIN}']}],
        })
        error = res.get('error')
        assert error is None, str(error)
        assert len(res['result']) != 0

        addresses = [x['address'] for x in res['result']]
        assert ip in addresses

        res = make_ws_request(ip, {
            'msg': 'method',
            'method': 'privilege.query',
            'params': [[['name', 'C=', AD_DOMAIN]]]
        })
        error = res.get('error')
        assert error is None, str(error)
        assert len(res['result']) == 1, str(res['result'])

        assert len(res['result'][0]['ds_groups']) == 1, str(res['result'])
        assert res['result'][0]['ds_groups'][0]['name'].endswith('domain admins')
        assert res['result'][0]['ds_groups'][0]['sid'].endswith('512')
        assert res['result'][0]['allowlist'][0] == {'method': '*', 'resource': '*'}
