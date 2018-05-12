"""
Test the TLS configuration of the mail server, if one exists.
"""

import json
import re
from typing import Dict, Union
from urllib.parse import urlparse

from .common import run_testssl, parse_common_testssl, combine_results

name = 'testssl_mx'
dependencies = [
    'network',
]
required_keys = [
    'mx_records',
]


def scan_site(result, logger, options):
    # test first mx
    try:
        hostname = result['mx_records'][0][1]
    except (KeyError, IndexError):
        logger.error('result missing mx record')
        return

    jsonresults = run_testssl(hostname, True, options['testssl_path'])

    result['mx_ssl_finished'] = True

    combined_results = combine_results(jsonresults)

    if combined_results.get('scan_result_empty'):
        # The test terminated, but did not give any results => probably no STARTTLS
        result['mx_has_ssl'] = False
        return

    if combined_results.get('parse_error'):
        result['mx_scan_failed'] = True
        result['mx_parse_error'] = combined_results.get('parse_error')
        return

    if combined_results.get('testssl_incomplete'):
        result['mx_testssl_incomplete'] = True

    if combined_results.get('incomplete_scans'):
        result['mx_testssl_incomplete_scans'] = combined_results.get('incomplete_scans')

    if combined_results.get('missing_scans'):
        result['mx_testssl_missing_scans'] = combined_results.get('missing_scans')

    result.update(parse_common_testssl(combined_results, "mx"))
