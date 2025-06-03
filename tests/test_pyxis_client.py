import json
import mock

import pytest
import requests
import requests_mock

from pubtools._pyxis import pyxis_client, pyxis_authentication
from tests.utils import load_data, urljoin

# flake8: noqa: W503


@mock.patch("pubtools._pyxis.pyxis_client.PyxisSession")
def test_client_init(mock_session, hostname):
    client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)

    assert not mock_session.called

    # access the lazy property to initialize the session
    client.pyxis_session

    mock_session.assert_called_once_with(
        hostname, retries=5, backoff_factor=3, verify=True
    )


def test_client_init_set_auth(hostname):
    crt_path = "/root/name.crt"
    key_path = "/root/name.key"
    auth = pyxis_authentication.PyxisSSLAuth(crt_path, key_path)

    my_client = pyxis_client.PyxisClient(hostname, 5, auth, 3, True)
    my_client.pyxis_session.session.cert == (crt_path, key_path)


def test_get_operator_indices(hostname):
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


def test_get_repository_metadata(hostname):
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


def test_get_repository_metadata_partner_registry(hostname):
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


def test_get_repository_metadata_only_internal(hostname):
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


def test_get_repository_metadata_only_partner(hostname):
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


def test_get_repository_metadata_custom_registry(hostname):
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


def test_get_signatures_with_digest_reference(hostname):
    all_signatures = signatures_matching = json.loads(load_data("sigs_with_reference"))
    signatures_matching["data"] = all_signatures["data"][0:2]
    manifest_to_search = "sha256:dummy-manifest-digest-1"
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
            manifest_to_search, reference_to_search
        )
        assert res == signatures_matching["data"]
        assert m.request_history[0].url == url_with_digest_ref


def test_get_signatures_from_multiple_pages(hostname):
    page_1_response = json.loads(load_data("signatures_page1"))
    page_2_response = json.loads(load_data("signatures_page2"))
    manifest_to_search = (
        "sha256:dummy-manifest-digest-1, sha256:dummy-manifest-digest-2"
    )
    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/signatures?filter=manifest_digest=in=({1})".format(
                hostname, manifest_to_search
            ),
            json=page_1_response,
        )
        m.get(
            "{0}v1/signatures?filter=manifest_digest=in=({1})&page=1".format(
                hostname, manifest_to_search
            ),
            json=page_2_response,
        )

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_container_signatures(manifest_to_search, None)
        assert res == page_1_response["data"] + page_2_response["data"]


def test_delete_container_signatures_success(hostname):
    ids = ["g1g1g1g1", "h2h2h2h2"]

    with requests_mock.Mocker() as m:
        m.delete(urljoin(hostname, "/v1/signatures/id/g1g1g1g1"))
        m.delete(urljoin(hostname, "/v1/signatures/id/h2h2h2h2"))

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        my_client.delete_container_signatures(ids)
        assert len(m.request_history) == 2
        observed_urls = sorted([h.url for h in m.request_history])
        expected_urls = sorted(
            [
                urljoin(hostname, "/v1/signatures/id/g1g1g1g1"),
                urljoin(hostname, "/v1/signatures/id/h2h2h2h2"),
            ]
        )
        assert observed_urls == expected_urls


def test_delete_container_signatures_tolerate_404(hostname):
    ids = ["g1g1g1g1", "h2h2h2h2"]

    with requests_mock.Mocker() as m:
        m.delete(urljoin(hostname, "/v1/signatures/id/g1g1g1g1"), status_code=404)
        m.delete(urljoin(hostname, "/v1/signatures/id/h2h2h2h2"))

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        my_client.delete_container_signatures(ids)
        assert len(m.request_history) == 2
        observed_urls = sorted([h.url for h in m.request_history])
        expected_urls = sorted(
            [
                urljoin(hostname, "/v1/signatures/id/g1g1g1g1"),
                urljoin(hostname, "/v1/signatures/id/h2h2h2h2"),
            ]
        )
        assert observed_urls == expected_urls


def test_delete_container_signatures_server_error(hostname):
    ids = ["g1g1g1g1", "h2h2h2h2"]

    with requests_mock.Mocker() as m:
        m.delete(urljoin(hostname, "/v1/signatures/id/g1g1g1g1"), status_code=500)
        m.delete(urljoin(hostname, "/v1/signatures/id/h2h2h2h2"))

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        with pytest.raises(requests.exceptions.HTTPError, match="500 Server Error.*"):
            my_client.delete_container_signatures(ids)
        assert len(m.request_history) == 2
        assert set([h.url for h in m.request_history]) == set(
            [
                urljoin(hostname, "/v1/signatures/id/g1g1g1g1"),
                urljoin(hostname, "/v1/signatures/id/h2h2h2h2"),
            ]
        )


def test_do_parallel_requests(hostname):
    # set up a fake response factory
    def _make_response(seed):
        return requests_mock.response.create_response(
            requests.Request("GET", hostname),
            status_code=200,
            json={"foo": seed},
        )

    # set up a mock requester that returns fake responses
    _do_request = mock.Mock(side_effect=[_make_response("1"), _make_response("2")])

    my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
    results = my_client._do_parallel_requests(_do_request, ["a", "b"])

    # verify that these fake responses have been processed properly
    assert len(results) == 2
    assert all(result in [{"foo": "1"}, {"foo": "2"}] for result in results)

    # verify that the mock requester was called as expected (in parallel)
    _do_request.assert_has_calls([mock.call("a"), mock.call("b")], any_order=True)


@mock.patch("pubtools._pyxis.pyxis_session.PyxisSession.post")
def test_post_signatures_500_retry(mock_session_post, hostname):
    sig_data = [
        {"foo": "bar", "foo1": "bar1"},
    ]
    response_500 = mock.MagicMock()
    response_200 = mock.MagicMock()
    response_500.status_code = 500
    response_200.status_code = 200
    response_200.json.return_value = sig_data[0]
    mock_session_post.side_effect = [response_500, response_200]
    my_client = pyxis_client.PyxisClient(hostname, 5, None, 5, True, 1)
    res = my_client.upload_signatures(sig_data)
    assert mock_session_post.call_count == 2
    assert res == sig_data


@mock.patch("pubtools._pyxis.pyxis_session.PyxisSession.post")
def test_post_signatures_tolerate_409(mock_session_post, hostname):
    sig_data = [
        {"foo": "bar", "foo1": "bar1"},
        {"foo": "bar2", "foo1": "bar3"},
    ]
    response_200 = mock.MagicMock()
    response_409 = mock.MagicMock()
    response_200.status_code = 200
    response_409.status_code = 409
    response_200.json.return_value = sig_data[0]
    return_data = {"details": "E11000 duplicate key error"}
    response_409.json.return_value = return_data
    mock_session_post.side_effect = [response_200, response_409]
    my_client = pyxis_client.PyxisClient(hostname, 5, None, 5, True, 1)
    res = my_client.upload_signatures(sig_data)
    assert mock_session_post.call_count == 2
    assert len(res) == 2
    assert sig_data[0] in res and return_data in res
