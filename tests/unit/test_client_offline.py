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


class TestResolvSid:
    OWN = "S-1-5-21-2854713739-2693073368-2788288984"
    ROOT = "S-1-5-21-1798895762-2647094234-2649376422"

    def _client(self, lookups=None):
        from winacl.dtyp.sid import SID
        from msldap.ldap_objects.adtrust import MSADDomainTrust

        client = _client()
        client._tree = "DC=north,DC=sevenkingdoms,DC=local"
        client.domainsid = self.OWN
        client._domainsid_cache[self.OWN] = "north"
        client.searched = []
        lookups = lookups or {}

        async def fake_pagedsearch(query, attributes, **kwargs):
            client.searched.append(query)
            sid = query[len("(objectSid="):-1]
            if sid in lookups:
                yield {"attributes": {"sAMAccountName": lookups[sid]}}, None

        async def fake_trusts():
            trust = MSADDomainTrust()
            trust.flatName = "SEVENKINGDOMS"
            trust.securityIdentifier = SID.from_string(self.ROOT)
            yield trust, None

        client.pagedsearch = fake_pagedsearch
        client.get_all_trusts = fake_trusts
        return client

    async def test_trusted_domain_well_known_rid(self):
        client = self._client()
        assert await client.resolv_sid(self.ROOT + "-519") == ("SEVENKINGDOMS", "Enterprise Admins", None)
        # foreign SIDs are not searched in the local partition
        assert client.searched == []

    async def test_trusted_domain_unknown_rid(self):
        client = self._client()
        assert await client.resolv_sid(self.ROOT + "-1234") == ("SEVENKINGDOMS", "???", None)

    async def test_unknown_domain(self):
        client = self._client()
        assert await client.resolv_sid("S-1-5-21-1-2-3-512") == ("???", "???", None)

    async def test_builtin_alias_from_table(self):
        client = self._client()
        assert await client.resolv_sid("S-1-5-32-555") == ("BUILTIN", "Remote Desktop Users", None)

    async def test_builtin_alias_via_ldap(self):
        client = self._client({"S-1-5-32-999": "Custom Alias"})
        assert await client.resolv_sid("S-1-5-32-999") == ("BUILTIN", "Custom Alias", None)

    async def test_own_domain_uses_ldap(self):
        client = self._client({self.OWN + "-1118": "jon.snow"})
        assert await client.resolv_sid(self.OWN + "-1118") == ("north", "jon.snow", None)


class TestWhoamiFull:
    async def test_foreign_user_is_reported(self):
        # bound via a trust: the account does not exist in the connected domain
        client = _client()

        async def fake_whoami():
            return "u:NORTH\\jon.snow", None

        async def fake_get_user(name):
            return None, None

        client.whoami = fake_whoami
        client.get_user = fake_get_user
        res, err = await client.whoamifull()
        assert err is not None and "not found" in str(err)
        assert res["tokengroups"] == []


class TestAccountNames:
    def _client(self):
        client = _client()
        client.domainname = "essos.local"
        return client

    @pytest.mark.parametrize("account", [
        "khal.drogo", "essos\\khal.drogo", "ESSOS/khal.drogo", "khal.drogo@essos.local", "essos.local\\khal.drogo",
    ])
    async def test_own_domain(self, account):
        _, user = await self._client()._split_account_name(account)
        assert user == "khal.drogo"

    async def test_foreign_domain_is_rejected(self):
        with pytest.raises(Exception, match="belongs to domain north"):
            await self._client()._split_account_name("north\\jon.snow")

    async def test_tokengroups_user_reports_foreign_domain(self):
        res, err = await self._client().get_tokengroups_user("north\\jon.snow")
        assert res is None and "belongs to domain" in str(err)


class _TreeCon:
    """Directory: root with two containers, the first one has a child."""

    status = MSLDAPClientStatus.RUNNING

    def __init__(self):
        self.searches = []
        self.children = {
            "DC=test,DC=corp": ["CN=A,DC=test,DC=corp", "CN=B,DC=test,DC=corp"],
            "CN=A,DC=test,DC=corp": ["CN=A1,CN=A,DC=test,DC=corp"],
        }

    async def pagedsearch(self, base, query, attributes, **kwargs):
        self.searches.append(base)
        for dn in self.children.get(base, []):
            yield {"objectName": dn, "attributes": {"distinguishedName": dn}}, None


class TestTreePlot:
    async def test_level_one_searches_only_the_root(self):
        con = _TreeCon()
        client = MSLDAPClient(None, None, connection=con)
        tree = await client.get_tree_plot("DC=test,DC=corp", level=1)
        assert tree == {"DC=test,DC=corp": {"CN=A,DC=test,DC=corp": {}, "CN=B,DC=test,DC=corp": {}}}
        assert con.searches == ["DC=test,DC=corp"]

    async def test_level_two_searches_the_children(self):
        con = _TreeCon()
        client = MSLDAPClient(None, None, connection=con)
        tree = await client.get_tree_plot("DC=test,DC=corp", level=2)
        assert tree["DC=test,DC=corp"]["CN=A,DC=test,DC=corp"] == {"CN=A,DC=test,DC=corp": {"CN=A1,CN=A,DC=test,DC=corp": {}}}
        assert con.searches == ["DC=test,DC=corp", "CN=A,DC=test,DC=corp", "CN=B,DC=test,DC=corp"]
