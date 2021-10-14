import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


# pylint: disable=bad-option-value,useless-object-inheritance
class PyxisSession(object):
    """Helper class to support Pyxis requests and authentication."""

    def __init__(self, hostname, retries=5, backoff_factor=5, verify=False):
        """
        Initialize.

        Args:
            hostname (str)
                hostname of Pyxis service.
            retries (int)
                number of http retries.
            backoff_factor (int)
                backoff factor to apply between attempts after the second try.
            verify (bool)
                enable/disable SSL CA verification.
        """
        self.session = requests.Session()
        self.hostname = hostname
        self.session.verify = verify
        self.krb5ccname_path = None

        status_forcelist = list(range(500, 512)) + [429]
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
            method_whitelist=[
                "HEAD",
                "GET",
                "PUT",
                "DELETE",
                "OPTIONS",
                "TRACE",
                "POST",
            ],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, endpoint, **kwargs):
        """
        HTTP GET request against Pyxis server API.

        Args:
            endpoint (str): Endpoint of the request.
            **kwargs: Additional arguments to add to the requests method.
        Returns:
            requests.Response: A response object.
        """
        return self.session.get(self._api_url(endpoint), **kwargs)

    def post(self, endpoint, **kwargs):
        """
        HTTP POST request against Pyxis server API.

        Args:
            endpoint (str): Endpoint of the request.
            **kwargs: Additional arguments to add to the requests method.
        Returns:
            requests.Response: A response object.
        """
        return self.session.post(self._api_url(endpoint), **kwargs)

    def put(self, endpoint, **kwargs):
        """
        HTTP PUT request against Pyxis server API.

        Args:
            endpoint (str): Endpoint of the request.
            **kwargs: Additional arguments to add to the requests method.
        Returns:
            requests.Response: A response object.
        """
        return self.session.put(self._api_url(endpoint), **kwargs)

    def delete(self, endpoint, **kwargs):
        """
        HTTP DELETE request against Pyxis server API.

        Args:
            endpoint (str): Endpoint of the request.
            **kwargs: Additional arguments to add to the requests method.
        Returns:
            requests.Response: A response object.
        """
        return self.session.delete(self._api_url(endpoint), **kwargs)

    def _api_url(self, endpoint):
        """
        Generate full url of the API endpoint.

        Args:
            endpoint (str)
                API specific endpoint for the request.
        Returns:
            str: Full URL of the endpoint.
        """
        if "http://" not in self.hostname and "https://" not in self.hostname:
            return "https://%s/v1/%s" % (self.hostname.rstrip("/"), endpoint)
        else:
            return "%s/v1/%s" % (self.hostname.rstrip("/"), endpoint)

    def close(self):
        """Close the current session."""
        self.session.close()
