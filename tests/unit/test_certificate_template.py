"""Offline tests for the certificate template vulnerability checks."""
import pytest

from msldap.ldap_objects.adcertificatetemplate import (
    EKU_CLIENT_AUTHENTICATION_OID, CertificateNameFlag, MSADCertificateTemplate)

pytestmark = pytest.mark.unit

USER_TOKEN = [
    "S-1-5-21-1-2-3-1118",  # the user
    "S-1-5-21-1-2-3-513",   # Domain Users
    "S-1-5-32-545",         # BUILTIN\Users
]


def _esc1_template(enroll_sid):
    t = MSADCertificateTemplate()
    t.name = "ESC1"
    t.Certificate_Name_Flag = int(CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT)
    t.Enrollment_Flag = 0
    t.pKIExtendedKeyUsage = [EKU_CLIENT_AUTHENTICATION_OID]
    t.enroll_sids = {enroll_sid}
    return t


@pytest.mark.parametrize("enroll_sid", ["S-1-5-11", "S-1-1-0"])
def test_implicit_token_groups_can_enroll(enroll_sid):
    # tokenGroups never contains Everyone / Authenticated Users, the check must add them
    assert "ESC1" in _esc1_template(enroll_sid).is_vulnerable2(USER_TOKEN)


def test_foreign_group_cannot_enroll():
    assert "ESC1" not in _esc1_template("S-1-5-21-9-9-9-513").is_vulnerable2(USER_TOKEN)


def test_enrollment_services_without_hostname():
    t = MSADCertificateTemplate()
    t.enroll_services = ["host.test.corp\\TEST-CA", "TEST-CA"]
    assert t.enrollment_services == [("host.test.corp", "TEST-CA"), (None, "TEST-CA")]


def test_flag_names():
    from msldap.ldap_objects.adcertificatetemplate import EnrollmentFlag, flag_names
    # value from the KerberosAuthentication template in GOAD
    assert flag_names(CertificateNameFlag, 138412032) == "SUBJECT_ALT_REQUIRE_DOMAIN_DNS, SUBJECT_ALT_REQUIRE_DNS"
    assert flag_names(CertificateNameFlag, 1) == "ENROLLEE_SUPPLIES_SUBJECT"
    assert flag_names(EnrollmentFlag, 0) == "NONE"
    assert flag_names(EnrollmentFlag, 0x20 | 0x100000) == "AUTO_ENROLLMENT, 0x100000"
    # msPKI-Certificate-Name-Flag is stored signed, high bit set -> negative
    assert flag_names(CertificateNameFlag, -2147483648) == "SUBJECT_REQUIRE_DIRECTORY_PATH"
