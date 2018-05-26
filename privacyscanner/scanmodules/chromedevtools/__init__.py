from .mixins.finalurl import FinalUrlMixin
from .mixins.googleanalytics import GoogleAnalyticsMixin
from .mixins.cookies import CookieMixin
from .mixins.requests import RequestsMixin
from .mixins.certificate import CertificateMixin
from .mixins.thirdparties import ThirdPartyMixin
from .mixins.insecurecontent import InsecureContentMixin


name = 'chromedevtools'
dependencies = ['network']
required_keys = ['site_url']


class ChromeScan(FinalUrlMixin, RequestsMixin, CookieMixin, CertificateMixin,
                 GoogleAnalyticsMixin, ThirdPartyMixin, InsecureContentMixin):
    def _initialize_scripts(self):
        pass

    def _extract_information(self):
        self._extract_final_url()
        self._extract_requests()
        self._extract_cookies()
        self._extract_certificate()
        self._extract_google_analytics()
        self._extract_third_parties()
        self._extract_security_state()

    def _receive_log(self, log_type, message, call_stack):
        pass


def scan_site(result, logger, options):
    chrome_scan = ChromeScan(result, logger, options)
    chrome_scan.scan()
