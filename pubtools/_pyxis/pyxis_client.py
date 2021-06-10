from __future__ import division
import math
from requests.exceptions import HTTPError
from .pyxis_session import PyxisSession


# pylint: disable=bad-option-value,useless-object-inheritance
class PyxisClient(object):
    """Pyxis requests wrapper."""

    def __init__(
        self,
        hostname,
        retries=3,
        auth=None,
        backoff_factor=2,
        verify=True,
    ):
        """
        Initialize.

        Args:
            hostname (str)
                Pyxis service hostname.
            retries (int)
                number of http retries for Pyxis requests.
            auth (PyxisAuth)
                PyxisAuth subclass instance.
            backoff_factor (int)
                backoff factor to apply between attempts after the second try.
            verify (bool)
                enable/disable SSL CA verification.
        """
        self.pyxis_session = PyxisSession(
            hostname, retries=retries, backoff_factor=backoff_factor, verify=verify
        )
        if auth:
            auth.apply_to_session(self.pyxis_session)

    def get_operator_indices(self, ocp_versions_range, organization=None):
        """Get a list of index images satisfying versioning and organization conditions.

        Args:
            ocp_versions_range (str)
                Supported OCP versions range.
            organization (str)
                Organization understood by IIB.

        Returns:
            list: List of index images satisfying the conditions.
        """
        params = {"ocp_versions_range": ocp_versions_range}
        if organization:
            params["organization"] = organization
        resp = self.pyxis_session.get("operators/indices", params=params)
        resp.raise_for_status()

        return resp.json()["data"]

    def get_repository_metadata(
        self, repo_name, custom_registry=None, only_internal=False, only_partner=False
    ):
        """Get metadata of a Comet repository.

        If checking only one registry hasn't been specified, check both with precedence on
        the internal registry.

        Args:
            repo_name (str):
                Name of the repository.
            custom_registry (str):
                Use a custom registry address instead of the default ones.
            only_internal (bool):
                Whether to only check internal registry.
            only_partner (bool):
                Whether to only check partner registry.
        Returns (dict):
            Metadata of the repository.
        """
        internal_registry = "registry.access.redhat.com"
        partner_registry = "registry.connect.redhat.com"
        endpoint = "repositories/registry/{0}/repository/{1}"
        if custom_registry:
            resp = self.pyxis_session.get(endpoint.format(custom_registry, repo_name))
        elif only_internal:
            resp = self.pyxis_session.get(endpoint.format(internal_registry, repo_name))
        elif only_partner:
            resp = self.pyxis_session.get(endpoint.format(partner_registry, repo_name))
        else:
            resp = self.pyxis_session.get(endpoint.format(internal_registry, repo_name))
            # if 'not found' error, try another registry
            if resp.status_code == 404:
                resp = self.pyxis_session.get(
                    endpoint.format(partner_registry, repo_name)
                )

        resp.raise_for_status()
        return resp.json()

    def upload_signatures(self, signatures):
        """
        Upload signatures from given JSON string.

        Args:
            signatures (str)
                JSON with signatures to upload.  See Pyxis API for details.

        Returns:
            list: List of uploaded signatures including auto-populated fields.
        """
        headers = {
            "Content-Type": "application/json",
        }
        resp = self.pyxis_session.post("signatures", data=signatures, headers=headers)

        return self._parse_response(resp)

    def _parse_response(self, response):
        """
        Get JSON from given response or raise an informative exception.

        Uses `requests.raise_for_status()` but tries to extract more details.
        """
        # the response may contain useful JSON even in case of 40x/50x
        # but it can't be guaranteed
        try:
            data = response.json()
        except ValueError:  # Python 2.x compat
            data = {}

        try:
            response.raise_for_status()
        except HTTPError as e:
            # We've got an error, but by default the exception contains only
            # minimal information: status code (400) and reason (Client error).
            # If the JSON was successfully parsed earlier, it may contain
            # important details (e.g. "Maximum of 100 signatures are allowed").
            extra_msg = data["detail"] if "detail" in data else response.text

            # re-raise the exception with an extra message
            raise HTTPError("{0}\n{1}".format(e, extra_msg))

        return data

    def get_container_signatures(self, manifest_digests=None, references=None):
        """Get a list of signature metadata matching given fields.

        Args:
            manifest_digests (comma separated str)
                manifest_digest used for searching in signatures.
            references (comma separated str)
                pull reference for image of signature stored.

        Returns:
            list: List of signature metadata matching given fields.
        """
        signatures_endpoint = "signatures"
        filter_criteria = []
        if manifest_digests:
            filter_criteria.append("manifest_digest=in=({0}),".format(manifest_digests))
        if references:
            filter_criteria.append("reference=in=({0}),".format(references))

        signatures_endpoint = "{0}{1}{2}".format(
            signatures_endpoint, "?filter=", "".join(filter_criteria)
        )
        signatures_endpoint = signatures_endpoint[0:-1]

        resp = self._get_items_from_all_pages(signatures_endpoint)

        return resp

    def _get_items_from_all_pages(self, endpoint, **kwargs):
        """
        Get response from all pages of pyxis.

        Args:
            endpoint (str): Endpoint of the request.
            **kwargs: Additional arguments to add to the requests method.
        Returns:
            list: list of all data records returned from pyxis

        """
        all_resp = []
        first_resp = self.pyxis_session.get(endpoint, **kwargs)
        first_resp.raise_for_status()
        first_resp_json = first_resp.json()
        all_resp.extend(first_resp_json["data"])
        # if total data is greater than data returned in first page,
        # calculate number of pages and then consequently get response from each page
        if len(first_resp_json["data"]) < first_resp_json["total"]:
            total_pages = int(
                math.ceil(first_resp_json["total"] / first_resp_json["page_size"])
            )
            for page in range(1, total_pages):
                params = {"page": page}
                resp = self.pyxis_session.get(endpoint, params=params)
                resp.raise_for_status()
                all_resp.extend(resp.json()["data"])
        return all_resp

    def delete_container_signatures(self, signature_ids):
        """Delete signatures matching given fields.

        Args:
            signature_ids ([str])
                Internal Pyxis signature IDs of signatures which should be removed.
        """
        delete_endpoint = "signatures/id/{id}"

        for signature_id in signature_ids:
            resp = self.pyxis_session.delete(delete_endpoint.format(id=signature_id))
            if resp.status_code != 404:
                resp.raise_for_status()
