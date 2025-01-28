import logging
import pytest
from binascii import unhexlify
from ledger_pluto.client import CLA, InsType, P1, P2, HW_SERIAL_NUMBER, HW_PUBLIC_KEY
from .conftest import (
    TEST_ISSUER_PRIV_KEY,
    TEST_AUTH_PRIV_KEY,
    AID,
    StatusWords,
    assert_sw,
)
from ledgerblue.ecWrapper import PrivateKey

logger = logging.getLogger(__name__)


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "Attested"
    assert infos.transient_fsm_state == "Initialized"


def configure_client_and_check_state(client):
    client.set_issuer_key(AID, bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    client.get_public_key_and_verify()
    client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    check_applet_state(client)


@pytest.mark.description("'VALIDATE CERTIFICATE' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_APP_VC_OK_01")
@pytest.mark.commands("validate_certificate")
@pytest.mark.order("last")
def test_cmd_validate_certificate(client):
    check_applet_state(client)
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    infos = client.get_status()
    assert infos.fsm_state == "Attested"
    assert infos.transient_fsm_state == "Authenticated"


@pytest.mark.description(
    "When P1 differs from 0x00 and 0x80, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_VC_FAIL_01")
@pytest.mark.commands("validate_certificate")
@pytest.mark.order("first")
def test_cmd_validate_certificate_wrong_p1(sender, client):
    configure_client_and_check_state(client)
    wrong_p1 = 0x22
    dummy_data = bytearray([0x00] * 0x04)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.VALIDATE_HOST_CERTIFICATE,
        p1=wrong_p1,
        p2=P2.P2_DEFAULT,
        data=dummy_data,
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)
    check_applet_state(client)


@pytest.mark.description(
    "When P2 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_VC_FAIL_02")
@pytest.mark.commands("validate_certificate")
def test_cmd_validate_certificate_wrong_p2(sender, client):
    check_applet_state(client)
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    wrong_p2 = 0x22
    dummy_data = bytearray([0x00] * 0x04)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.VALIDATE_HOST_CERTIFICATE,
        p1=P1.P1_DEFAULT,
        p2=wrong_p2,
        data=dummy_data,
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)
    check_applet_state(client)


@pytest.mark.description(
    "When certificate data is missing, the command should be rejected with 0x6700"
)
@pytest.mark.test_spec("CHA_APP_VC_FAIL_03")
@pytest.mark.commands("validate_certificate")
def test_cmd_validate_certificate_missing_data(sender, client):
    check_applet_state(client)
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    wrong_lc = 0x00
    # Send VALIDATE CERTIFICATE with P1=0x00 and P2=0x00 (host static certificate)
    # with lc=0x00
    apdu = bytearray(
        [CLA, InsType.VALIDATE_HOST_CERTIFICATE, P1.P1_DEFAULT, P2.P2_DEFAULT, wrong_lc]
    )
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)
    check_applet_state(client)


@pytest.mark.description(
    "When the certificate signature verification fails, the command should be rejected with 0x6982"
)
@pytest.mark.test_spec("CHA_APP_VC_FAIL_04")
@pytest.mark.commands("validate_certificate")
def test_cmd_validate_certificate_wrong_signature(sender, client):
    check_applet_state(client)
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    # Send VALIDATE CERTIFICATE with P1=0x00 and P2=0x00 (host static certificate)
    # with a wrong signature
    # Generate a valid host static certificate
    hw_static_certificate, _ = client.generate_hw_static_certificate(
        unhexlify(HW_SERIAL_NUMBER),
        unhexlify(HW_PUBLIC_KEY),
        unhexlify(TEST_AUTH_PRIV_KEY),
    )
    hw_static_certificate = bytearray(unhexlify(hw_static_certificate))
    # Tamper the signature
    hw_static_certificate[-5:] = bytearray([0x00] * 5)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.VALIDATE_HOST_CERTIFICATE,
        p1=P1.VALIDATE_CERTIFICATE_P1_STATIC,
        p2=P2.P2_DEFAULT,
        data=hw_static_certificate,
    )
    assert_sw(sw1, sw2, StatusWords.SECURITY_STATUS_NOT_SATISFIED)
    check_applet_state(client)
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))

    # ================================
    # Send VALIDATE CERTIFICATE with P1=0x80 and P2=0x00 (host ephemeral certificate)
    # with a wrong signature
    # Generate a valid host ephemeral certificate
    ephemeral_private_key = PrivateKey()
    hw_ephemeral_certificate, _ = client.generate_hw_ephemeral_certificate(
        client.host_challenge,
        client.card_challenge,
        ephemeral_private_key.pubkey.serialize(compressed=False),
    )
    hw_ephemeral_certificate = bytearray(unhexlify(hw_ephemeral_certificate))
    # Tamper the signature
    hw_ephemeral_certificate[-5:] = bytearray([0x00] * 5)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.VALIDATE_HOST_CERTIFICATE,
        p1=P1.VALIDATE_CERTIFICATE_P1_EPHEMERAL,
        p2=P2.P2_DEFAULT,
        data=hw_ephemeral_certificate,
    )
    assert_sw(sw1, sw2, StatusWords.SECURITY_STATUS_NOT_SATISFIED)
    check_applet_state(client)
