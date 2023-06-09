import contextlib
import functools
import os
import sys
import threading

from middlewared.client import Client
from middlewared.test.integration.assets.crypto import get_cert_params, root_certificate_authority
from middlewared.test.integration.utils import call
from middlewared.test.integration.utils.client import host_websocket_uri, password


sys.path.append(os.getcwd())


@functools.cache
def auth():
    return 'root', password()


def event_thread(event_endpoint: str, context: dict):
    with Client(host_websocket_uri(), py_exceptions=False) as c:
        assert c.call('auth.login', *auth()) is True

        subscribe_payload = c.event_payload()
        event = subscribe_payload['event']
        context['event'] = event

        def cb(mtype, **message):
            if len(message) != 3 or not all(
                k in message for k in ('id', 'msg', 'collection')
            ) or message['collection'] != event_endpoint or message['msg'] not in (
                'added', 'changed', 'removed'
            ):
                return

            context['result'] = message
            event.set()

        c.subscribe(event_endpoint, cb, subscribe_payload)
        event.wait(timeout=context['timeout'])


@contextlib.contextmanager
def gather_events(event_endpoint: str, context_args: dict = None):
    context = {'result': None, 'event': None, 'timeout': 60, **(context_args or {})}
    thread = threading.Thread(target=event_thread, args=(event_endpoint, context))
    thread.start()
    try:
        yield context
    finally:
        if context['event'] and context['event'].is_set() is False:
            context['event'].set()
        thread.join(timeout=5)


def test_event_create_on_non_job_method():
    with gather_events('certificateauthority.query') as context:
        with root_certificate_authority('root_ca_create_event_test') as root_ca:
            assert root_ca['CA_type_internal'] is True, root_ca
            assert context['result'] is not None, context
            assert context['result'] == {
                'msg': 'added',
                'collection': 'certificateauthority.query',
                'id': root_ca['id'],
            }, context['result']