import mock
import requests_mock

from pubtools._pyxis import pyxis_client, pyxis_authentication


@mock.patch("pubtools._pyxis.pyxis_client.PyxisSession")
def test_client_init(mock_session):
    hostname = "https://pyxis.engineering.redhat.com/"

    pyxis_client.PyxisClient(hostname, 5, None, 3, True)
    mock_session.assert_called_once_with(
        hostname, retries=5, backoff_factor=3, verify=True
    )


def test_client_init_set_auth():
    hostname = "https://pyxis.engineering.redhat.com/"
    crt_path = "/root/name.crt"
    key_path = "/root/name.key"
    auth = pyxis_authentication.PyxisSSLAuth(crt_path, key_path)

    my_client = pyxis_client.PyxisClient(hostname, 5, auth, 3, True)
    my_client.pyxis_session.session.cert == (crt_path, key_path)


def test_get_operator_indices():
    hostname = "https://pyxis.engineering.redhat.com/"
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
    hostname = "https://pyxis.engineering.redhat.com/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_id = "123"
    with requests_mock.Mocker() as m:
        m.get("{0}v1/repositories/id/{1}".format(hostname, repo_id), json=data)

        my_client = pyxis_client.PyxisClient(hostname, 5, None, 3, True)
        res = my_client.get_repository_metadata(repo_id)
        assert res == data
