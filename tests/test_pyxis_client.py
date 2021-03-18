import json
import mock
import requests_mock

from pubtools._pyxis import pyxis_client, pyxis_authentication
from tests.utils import load_data


@mock.patch("pubtools._pyxis.pyxis_client.PyxisSession")
def test_client_init(mock_session):
    hostname = "https://pyxis-prod-url/"

    pyxis_client.PyxisClient(hostname, 5, None, 3, True)
    mock_session.assert_called_once_with(
        hostname, retries=5, backoff_factor=3, verify=True
    )


def test_client_init_set_auth():
    hostname = "https://pyxis-prod-url/"
    crt_path = "/root/name.crt"
    key_path = "/root/name.key"
    auth = pyxis_authentication.PyxisSSLAuth(crt_path, key_path)

    my_client = pyxis_client.PyxisClient(hostname, 5, auth, 3, True)
    my_client.pyxis_session.session.cert == (crt_path, key_path)


def test_get_operator_indices():
    hostname = "https://pyxis-prod-url/"
    data = [
        {"path": "registry.io/index-image:4.5", "other": "stuff"},
        {"path": "registry.io/index-image:4.6", "other2": "stuff2"},
    ]
    ver = "4.5-4.6"
    org = "redhat"
    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/operators/indices?ocp_versions_range={1}&organization={2}".format(
                hostname, ver, org
            ),
            json={"data": data},
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_operator_indices(ver, org)
        assert res == data


def test_get_repository_metadata():
    hostname = "https://pyxis-prod-url/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    registry = "registry.access.redhat.com"

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, registry, repo_name
            ),
            json=data,
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_repository_metadata(repo_name)
        assert res == data


def test_get_repository_metadata_partner_registry():
    hostname = "https://pyxis-prod-url/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    internal_registry = "registry.access.redhat.com"
    partner_registry = "registry.connect.redhat.com"

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, internal_registry, repo_name
            ),
            text="no data",
            status_code=404,
        )
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, partner_registry, repo_name
            ),
            json=data,
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_repository_metadata(repo_name)
        assert res == data


def test_get_repository_metadata_only_internal():
    hostname = "https://pyxis-prod-url/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    registry = "registry.access.redhat.com"

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, registry, repo_name
            ),
            json=data,
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_repository_metadata(repo_name, only_internal=True)
        assert res == data


def test_get_repository_metadata_only_partner():
    hostname = "https://pyxis-prod-url/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    registry = "registry.connect.redhat.com"

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, registry, repo_name
            ),
            json=data,
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_repository_metadata(repo_name, only_partner=True)
        assert res == data


def test_get_repository_metadata_custom_registry():
    hostname = "https://pyxis-prod-url/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    registry = "some.registry.com"

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, registry, repo_name
            ),
            json=data,
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_repository_metadata(repo_name, custom_registry=registry)
        assert res == data


def test_get_signatures(hostname):
    all_signatures = json.loads(load_data("sigs_with_reference"))
    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/signatures".format(hostname),
            json=all_signatures,
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_container_signatures()
        assert res == all_signatures["data"]


def test_get_signatures_with_digest_reference(hostname):
    all_signatures = signatures_matching = json.loads(load_data("sigs_with_reference"))
    manifest_to_search = "sha256:dummy-manifest-digest-1"
    signatures_matching["data"] = all_signatures["data"][0:2]
    reference_to_search = (
        "registry.redhat.io/e2e-container/rhel-8-e2e-container-test-"
        "product:latest,registry.access.redhat.com/e2e-container/rhel-8-e2e-container-test-"
        "product:latest"
    )
    url_with_digest_ref = (
        "{0}v1/signatures?filter=manifest_digest=in=({1}),reference=in=({2})".format(
            hostname, manifest_to_search, reference_to_search
        )
    )
    with requests_mock.Mocker() as m:
        m.get(
            url_with_digest_ref,
            json=signatures_matching,
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_container_signatures(
            manifest_to_search, reference_to_search, None
        )
        assert res == signatures_matching["data"]
        assert m.request_history[0].url == url_with_digest_ref


def test_get_signatures_from_multiple_pages(hostname):
    page_1_response = json.loads(load_data("signatures_page1"))
    page_2_response = json.loads(load_data("signatures_page2"))
    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/signatures?filter=sig_key_id=in=({1})".format(hostname, "123123"),
            json=page_1_response,
        )
        m.get(
            "{0}v1/signatures?filter=sig_key_id=in=({1})&page=1".format(
                hostname, "123123"
            ),
            json=page_2_response,
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_container_signatures(None, None, "123123")
        assert res == page_1_response["data"] + page_2_response["data"]
