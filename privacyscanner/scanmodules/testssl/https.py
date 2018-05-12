"""
Test the SSL configuration of the web server.
"""

import json
import re
import os
from typing import Dict, Union
from urllib.parse import urlparse

from .common import run_testssl, parse_common_testssl, combine_results

name = 'testssl_https'
dependencies = [
    'network',
]
required_keys = [
    'site_url',
    'final_https_url',
    'final_url_is_https',
    'same_content_via_https',
]


def scan_site(result, logger, options):
    # Commented out for now because it gives bad results sometimes
    scan_url = result.get('final_https_url')
    if scan_url and (
            result.get('same_content_via_https') or
            result.get('final_url_is_https')):
        hostname = urlparse(scan_url).hostname
    elif result['site_url'].startswith('https'):
        hostname = urlparse(result['site_url']).hostname
    else:
        logger.info('no url for SSL/TLS scan found')
        result['web_has_ssl'] = False
        return
    
    jsonresults = run_testssl(hostname, False, options['testssl_path'])

    combined_results = combine_results(jsonresults)
    result.add_debug_file('combined_results.json', json.dumps(combined_results).encode())

    result['web_ssl_finished'] = True

    if combined_results.get('parse_error'):
        result['web_scan_failed'] = True
        return

    if combined_results.get('scan_result_empty'):
        # The test terminated, but did not give any results => probably no HTTPS
        result['web_has_ssl'] = False
        return
    
    if combined_results.get('testssl_incomplete'):
        result['web_testssl_incomplete'] = True

    if combined_results.get('incomplete_scans'):
        result['web_testssl_incomplete_scans'] = combined_results.get('incomplete_scans')

    if combined_results.get('missing_scans'):
        result['web_testssl_missing_scans'] = combined_results.get('missing_scans')
    
    # Grab common information
    result.update(parse_common_testssl(combined_results, "web"))
    result["web_ssl_finished"] = True
    
    # detect headers
    result.update(_detect_hsts(combined_results, hostname, options['hsts_preload_path']))
    result.update(_detect_hpkp(combined_results))


def _detect_hsts(data: dict, host: str, hsts_preload_path: str) -> dict:
    def _check_contained(preloads, domain, subdomains=False):
        for entry in preloads["entries"]:
            if entry["name"] == domain:
                if subdomains:
                    try:
                        if entry["include_subdomains"]:
                            return True
                    except:
                        pass
                else:
                    return True
        return False

    result = {}

    hsts_item = data.get('hsts')
    hsts_time_item = data.get('hsts_time')
    hsts_preload_item = data.get('hsts_preload')

    # Look for HSTS Preload header
    result['web_has_hsts_preload_header'] = False
    if hsts_preload_item is not None:
        result['web_has_hsts_preload_header'] = hsts_preload_item['severity'] == 'OK'

    # Look for HSTS header
    result['web_has_hsts_header'] = False
    if result['web_has_hsts_preload_header']:
        result['web_has_hsts_header'] = True
    elif hsts_item is not None:
        result['web_has_hsts_header'] = hsts_item['severity'] == 'OK'
    
    if hsts_time_item is not None:
        result['web_has_hsts_header'] = True
        result["web_has_hsts_header_sufficient_time"] = hsts_time_item['severity'] == 'OK'

    # Check the HSTS Preloading database
    result["web_has_hsts_preload"] = False
    with open(hsts_preload_path) as fo:
        preloads = json.load(fo)
    
    # Check if exact hostname is included
    if not _check_contained(preloads, host):
        # If not included, construct ever shorter hostnames and look for policies
        # on those versions that include subdomains
        split = host.split(".")
        for i in range(1, len(split)):
            if _check_contained(preloads, ".".join(split[i:]), True):
                # Found
                result["web_has_hsts_preload"] = True
    else:
        # Found
        result["web_has_hsts_preload"] = True
    return result


def _detect_hpkp(data: dict) -> dict:
    hpkp_item = data.get('hpkp')
    hpkp_spkis = data.get('hpkp_spkis')

    if hpkp_item is not None:
        return {'web_has_hpkp_header': not hpkp_item['finding'].startswith('No')}
    elif hpkp_spkis is not None:
        return {'web_has_hpkp_header': hpkp_spkis['severity'] == "OK"}

    hpkp_item = data.get('hpkp_multiple')
    if hpkp_item is not None:
        return {'web_has_hpkp_header': True}

    return {'web_has_hpkp_header': False}
