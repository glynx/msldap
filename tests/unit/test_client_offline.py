"""Offline tests for MSLDAPClient behaviour that does not need a socket."""
import pytest

from msldap.client import MSLDAPClient
from msldap.commons.common import MSLDAPClientStatus
from msldap.commons.exceptions import LDAPSearchException


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


class TestDnsZones:
    def _child_client(self):
        client = _client()
        client._tree = "DC=north,DC=sevenkingdoms,DC=local"
        client._serverinfo = {"rootDomainNamingContext": "DC=sevenkingdoms,DC=local"}
        return client

    def test_forest_dns_zones_under_forest_root(self):
        roots = self._child_client()._get_dns_roots()
        assert "CN=MicrosoftDNS,DC=ForestDnsZones,DC=sevenkingdoms,DC=local" in roots
        assert "CN=MicrosoftDNS,DC=DomainDnsZones,DC=north,DC=sevenkingdoms,DC=local" in roots

    async def test_missing_container_does_not_abort_listing(self):
        client = self._child_client()

        async def fake_pagedsearch(query, attributes, tree=None, **kwargs):
            if "DomainDnsZones" in tree:
                yield {"attributes": {"dc": "north.sevenkingdoms.local", "dNSProperty": []}}, None
            else:
                yield None, LDAPSearchException("noSuchObject", "no such container")

        client.pagedsearch = fake_pagedsearch
        res = await _collect(client.dnslistzones())
        assert [(zone, err) for zone, _, err in res] == [("north.sevenkingdoms.local", None)]
