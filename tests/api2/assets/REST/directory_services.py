import contextlib
import urllib.parse
from time import sleep

from functions import DELETE, GET, POST, PUT, wait_on_job


def clear_ad_info():
    results = PUT("/activedirectory/", {
        "domainname": "",
        "bindname": "",
        "verbose_logging": False,
        "allow_trusted_doms": False,
        "use_default_domain": False,
        "allow_dns_updates": True,
        "disable_freenas_cache": False,
        "restrict_pam": False,
        "site": None,
        "timeout": 60,
        "dns_timeout": 10,
        "nss_info": None,
        "enable": False,
        "kerberos_principal": "",
        "createcomputer": "",
        "kerberos_realm": None,
    })
    assert results.status_code == 200, results.text
    if not results.json().get('job_id'):
        return

    job_status = wait_on_job(results.json()['job_id'], 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])


def clear_ldap_info():
    results = PUT("/ldap/", {
        "hostname": [],
        "binddn": "",
        "bindpw": "",
        "ssl": "ON",
        "enable": False,
        "kerberos_principal": "",
        "kerberos_realm": None,
        "anonbind": False,
        "has_samba_schema": False,
        "validate_certificates": True,
        "disable_freenas_cache": False,
        "certificate": None,
    })
    if not results.json().get('job_id'):
        return

    job_status = wait_on_job(results.json()['job_id'], 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])

@contextlib.contextmanager
def active_directory(domain, username, password, **kwargs):
    payload = {
        'domainname': domain,
        'bindname': username,
        'bindpw': password,
        "kerberos_principal": "",
        "use_default_domain": False,
        'enable': True,
        **kwargs
    }

    results = PUT('/activedirectory/', payload)
    assert results.status_code == 200, results.text
    job_status = wait_on_job(results.json()['job_id'], 180)
    if job_status['state'] != 'SUCCESS':
        clear_ad_info()
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])

    sleep(5)
    config = results.json()
    yield {
        'config': config,
        'result': job_status['results']
    }


@contextlib.contextmanager
def override_nameservers(_nameserver1='', _nameserver2='', _nameserver3=''):
    results = GET("/network/configuration/")
    assert results.status_code == 200, results.text

    net_config = results.json()
    nameserver1 = net_config['nameserver1']
    nameserver2 = net_config['nameserver2']
    nameserver3 = net_config['nameserver3']

    try:
        results = PUT("/network/configuration/", {
            'nameserver1': _nameserver1,
            'nameserver2': _nameserver2,
            'nameserver3': _nameserver3
        })
        assert results.status_code == 200, results.text
        yield results.json()
    finally:
        results = PUT("/network/configuration/", {
            'nameserver1': nameserver1,
            'nameserver2': nameserver2,
            'nameserver3': nameserver3,
        })
        assert results.status_code == 200, results.text


@contextlib.contextmanager
def ldap(basedn, binddn, bindpw, hostname, **kwargs):
    payload = {
        "basedn": basedn,
        "binddn": binddn,
        "bindpw": bindpw,
        "hostname": [hostname],
        "ssl": "ON",
        "auxiliary_parameters": "",
        "validate_certificates": True,
        "enable": True,
        **kwargs
    }

    results = PUT("/ldap/", payload)
    del(payload['bindpw'])

    assert results.status_code == 200, f'res: {results.text}, payload: {payload}'
    job_id = results.json()['job_id']
    job_status = wait_on_job(job_id, 180)
    if job_status['state'] != 'SUCCESS':
        clear_ldap_info()
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])

    sleep(5)
    try:
        config = results.json()
        del(config['bindpw'])
        yield {
            'config': config,
            'result': job_status['results']
        }
    finally:
        clear_ldap_info()
