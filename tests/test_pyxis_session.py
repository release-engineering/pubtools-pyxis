import mock

from pubtools._pyxis import pyxis_session


@mock.patch("pubtools._pyxis.pyxis_session.requests.Session")
def test_session_init(mock_session):
    hostname = "https://pyxis.engineering.redhat.com/"
    mock_mount = mock.MagicMock()
    mock_session.return_value.mount = mock_mount

    my_pyxis_session = pyxis_session.PyxisSession(hostname)
    assert my_pyxis_session.hostname == hostname
    assert mock_mount.call_count == 2


def test_api_url():
    hostname = "https://pyxis.engineering.redhat.com/"
    my_session = pyxis_session.PyxisSession(hostname)
    assert my_session._api_url("add") == "https://pyxis.engineering.redhat.com/v1/add"

    hostname = "pyxis.engineering.redhat.com/"
    my_session = pyxis_session.PyxisSession(hostname)
    assert my_session._api_url("rm") == "https://pyxis.engineering.redhat.com/v1/rm"


@mock.patch("pubtools._pyxis.pyxis_session.requests.Session")
def test_rest_methods(mock_session):
    hostname = "https://pyxis.engineering.redhat.com/"
    mock_get = mock.MagicMock()
    mock_post = mock.MagicMock()
    mock_put = mock.MagicMock()
    mock_delete = mock.MagicMock()
    mock_session.return_value.get = mock_get
    mock_session.return_value.post = mock_post
    mock_session.return_value.put = mock_put
    mock_session.return_value.delete = mock_delete

    my_session = pyxis_session.PyxisSession(hostname)
    my_session.get("items", params={"param1": "value1"})
    mock_get.assert_called_once_with(hostname + "v1/items", params={"param1": "value1"})

    my_session = pyxis_session.PyxisSession(hostname)
    my_session.post("add-item", data={"param2": "value2"})
    mock_post.assert_called_once_with(
        hostname + "v1/add-item", data={"param2": "value2"}
    )

    my_session = pyxis_session.PyxisSession(hostname)
    my_session.put("edit-item", data={"param3": "value3"})
    mock_put.assert_called_once_with(
        hostname + "v1/edit-item", data={"param3": "value3"}
    )

    my_session = pyxis_session.PyxisSession(hostname)
    my_session.delete("rm-item", params={"param4": "value4"})
    mock_delete.assert_called_once_with(
        hostname + "v1/rm-item", params={"param4": "value4"}
    )
