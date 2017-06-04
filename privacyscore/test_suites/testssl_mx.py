import json
import re
from typing import Dict, Union
from urllib.parse import urlparse

from .testssl.common import run_testssl

test_name = 'testssl_mx'
test_dependencies = ['network']


def test_site(url: str, previous_results: dict, remote_host: str = None) -> Dict[str, Dict[str, Union[str, bytes]]]:
    # test first mx
    hostname = previous_results['mx_records'][0][1]  # TODO: list might be empty

    jsonresult = run_testssl(hostname, True, remote_host)

    return {
        'jsonresult': {
            'mime_type': 'application/json',
            'data': jsonresult,
        },
    }


def process_test_data(raw_data: list, previous_results: dict) -> Dict[str, Dict[str, object]]:
    """Process the raw data of the test."""
    data = json.loads(
        raw_data['jsonresult']['data'].decode())

    if not data['scanResult'] or not data['scanResult'][0]:
        # something went wrong with this test.
        raise Exception('no scan result in raw data')

    # TODO: Parse mx result -- there are no http headers to analyze here ...

    return {
        'mx_pfs': data['scanResult'][0]['pfs'][0][
            'severity'] == 'OK',
    }
