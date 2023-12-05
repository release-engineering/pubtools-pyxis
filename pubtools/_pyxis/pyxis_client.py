from __future__ import division
from concurrent.futures import as_completed
from functools import partial
import math
import threading
from typing import Callable, Any

from more_executors import Executors
from requests.exceptions import HTTPError
from requests import Response

from .constants import DEFAULT_REQUEST_THREADS_LIMIT
from .pyxis_session import PyxisSession
from .pyxis_authentication import PyxisAuth


class PyxisClient:
    """Pyxis requests wrapper."""

    def __init__(
        self,
        hostname: str,
        retries: int = 5,
        auth: PyxisAuth | None = None,
        backoff_factor: int = 5,
        verify: bool = True,
        threads: int = DEFAULT_REQUEST_THREADS_LIMIT,
    ) -> None:
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
            threads (int)
                the number of threads to use for parallel requests.
        """
        self.thread_local = threading.local()
        self._session_factory = partial(
            PyxisSession,
            hostname,
            retries=retries,
            backoff_factor=backoff_factor,
            verify=verify,
        )
        self._auth = auth
        self.threads_limit = threads

    @property
    def pyxis_session(self) -> PyxisSession | Any:
        """
        Return a thread-local session for Pyxis requests.

        If a session did not exist for current thread, it is initialized and
        cached.
        """
        if not hasattr(self.thread_local, "pyxis_session"):
            self.thread_local.pyxis_session = self._make_session()
        return self.thread_local.pyxis_session

    def _make_session(self) -> PyxisSession:
        session = self._session_factory()
        if self._auth:
            self._auth.apply_to_session(session)
        return session

    def get_operator_indices(
        self, ocp_versions_range: str, organization: str | None = None
    ) -> list[str] | Any:
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
        self,
        repo_name: str,
        custom_registry: str | None = None,
        only_internal: bool = False,
        only_partner: bool = False,
    ) -> dict[Any, Any] | Any:
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

    def upload_signatures(self, signatures: list[str]) -> list[Any]:
        """
        Upload signatures from given JSON string.

        Args:
            signatures [str]
                JSON with signatures to upload.  See Pyxis API for details.

        Returns:
            list: List of uploaded signatures including auto-populated fields.
        """

        def _send_post_request(data: dict[Any, Any]) -> Response:
            response = self.pyxis_session.post("signatures", json=data)
            # SEE CLOUDDST-9698
            # Pyxis returns 500 error due to a potential sidecar config issue
            # As a workaround to that, it was suggested to clear the session
            # establish a new connection and again retry
            # After creating a new session and retrying, the request should succeed
            if response.status_code == 500:
                self._clear_session()
                response = self.pyxis_session.post("signatures", json=data)
            return response

        return self._do_parallel_requests(_send_post_request, signatures)

    def _clear_session(self) -> None:
        self.thread_local.pyxis_session.close()
        delattr(self.thread_local, "pyxis_session")

    def _do_parallel_requests(
        self, make_request: Callable[[Any], Any], data_items: list[Any]
    ) -> list[Any] | Any:
        """
        Call given function with given data items in parallel, collect responses.

        Args:
            make_request (function): a function that does the actual request.
                Must accept a single argument: a data item.
                Must return a `requests.models.Response` object.
            data_items (list): a list of arbitrary objects to be passed
                individually to `make_request()`.

        The number of parallel requests is defined by
        `DEFAULT_REQUEST_THREADS_LIMIT` (can be overridden by the user) and
        of course by the number of actually available threads.

        If a response fails consistently (see `PyxisSession` for retry policy),
        the execution is terminated and an informative error is raised.
        See `PyxisClient._handle_json_response()` for details.

        Returns:
            list(dict): list of dictionaries extracted from responses.
        """
        with Executors.thread_pool(max_workers=self.threads_limit).with_map(
            self._handle_json_response
        ) as executor:
            futures = [executor.submit(make_request, data) for data in data_items]

            return [f.result() for f in as_completed(futures)]

    def _handle_json_response(self, response: Response) -> dict[Any, Any] | Any:
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

        tolerate_codes = []
        # Uploaded data already exists in Pyxis
        if response.request.method == "POST":
            tolerate_codes = [409]
        # Data already removed from Pyxis
        elif response.request.method == "DELETE":
            tolerate_codes = [404]
        if response.status_code in tolerate_codes:
            return data

        try:
            response.raise_for_status()
        except HTTPError as e:
            # We've got an error, but by default the exception contains only
            # minimal information: status code (400) and reason (Client error).
            # If the JSON was successfully parsed earlier, it may contain
            # important details (e.g. "Maximum of 100 signatures are allowed").
            extra_msg = data["detail"] if "detail" in data else response.text

            # re-raise the exception with an extra message
            raise HTTPError("{0}\n{1}".format(e, extra_msg), response=response)

        return data

    def get_container_signatures(
        self, manifest_digests: str | None = None, references: str | None = None
    ) -> list[str]:
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

    def _get_items_from_all_pages(self, endpoint: str, **kwargs: Any) -> list[Any]:
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

    def delete_container_signatures(self, signature_ids: list[str]) -> list[Any]:
        """Delete signatures matching given fields.

        Args:
            signature_ids ([str])
                Internal Pyxis signature IDs of signatures which should be removed.
        """

        def _send_delete_request(signature_id: str) -> Response:
            delete_endpoint = "signatures/id/{id}"
            resp = self.pyxis_session.delete(delete_endpoint.format(id=signature_id))
            return resp

        return self._do_parallel_requests(_send_delete_request, signature_ids)
