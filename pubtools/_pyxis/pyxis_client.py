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
