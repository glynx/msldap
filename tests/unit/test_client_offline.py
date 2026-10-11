"""Offline tests for MSLDAPClient behaviour that does not need a socket."""
import pytest

from msldap.client import MSLDAPClient
from msldap.commons.common import MSLDAPClientStatus


pytestmark = pytest.mark.unit


class _FakeCon:
    def __init__(self, status):
        self.status = status


def _client(status=MSLDAPClientStatus.RUNNING):
    return MSLDAPClient(None, None, connection=_FakeCon(status))


async def _collect(agen):
    return [x async for x in agen]


class TestConfigurationNC:
    def test_uses_rootdse_configuration_nc(self):
        # child domain: the Configuration NC lives under the forest root, not the domain DN
        client = _client()
        client._tree = "DC=north,DC=sevenkingdoms,DC=local"
        client._serverinfo = {"configurationNamingContext": "CN=Configuration,DC=sevenkingdoms,DC=local"}
        assert client._get_configuration_nc() == "CN=Configuration,DC=sevenkingdoms,DC=local"

    def test_falls_back_to_domain_dn(self):
        client = _client()
        client._tree = "DC=test,DC=corp"
        assert client._get_configuration_nc() == "CN=Configuration,DC=test,DC=corp"


class TestPagedSearchErrors:
    async def test_connection_error_is_yielded(self):
        client = _client(MSLDAPClientStatus.ERROR)
        client._tree = "DC=test,DC=corp"
        res = await _collect(client.pagedsearch("(objectClass=*)", ["cn"]))
        assert len(res) == 1
        entry, err = res[0]
        assert entry is None and isinstance(err, Exception)

    async def test_missing_tree_is_yielded(self):
        client = _client()
        res = await _collect(client.pagedsearch("(objectClass=*)", ["cn"]))
        assert len(res) == 1
        entry, err = res[0]
        assert entry is None and "BIND first" in str(err)
