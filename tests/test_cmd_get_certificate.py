import logging
import pytest
from ledger_pluto.client import CLA, InsType, P1, P2
from .conftest import (
    TEST_ISSUER_PRIV_KEY,
    TEST_AUTH_PRIV_KEY,
    AID,
    StatusWords,
    assert_sw,
)

logger = logging.getLogger(__name__)


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "Attested"
    assert infos.transient_fsm_state == "Initialized"


def configure_client_and_check_state(client):
    client.set_issuer_key(AID, bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    client.get_public_key_and_verify()
    client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    check_applet_state(client)


@pytest.mark.description("'GET CERTIFICATE' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_APP_GC_OK_01")
@pytest.mark.commands("get_certificate")
def test_cmd_get_certificate(client):
    print("test_cmd_get_certificate")
    configure_client_and_check_state(client)
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()


@pytest.mark.description(
    "When P1 differs from 0x00 and 0x80, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_GC_FAIL_01")
@pytest.mark.commands("get_certificate")
def test_cmd_get_certificate_wrong_p1(sender, client):
    check_applet_state(client)
    wrong_p1 = 0x22
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.GET_CARD_CERTIFICATE,
        p1=wrong_p1,
        p2=P2.P2_DEFAULT,
        data=b"",
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)
    check_applet_state(client)


@pytest.mark.description(
    "When P2 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_GC_FAIL_02")
@pytest.mark.commands("get_certificate")
def test_cmd_get_certificate_wrong_p2(sender, client):
    check_applet_state(client)
    wrong_p2 = 0x22
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.GET_CARD_CERTIFICATE,
        p1=P1.P1_DEFAULT,
        p2=wrong_p2,
        data=b"",
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)
    check_applet_state(client)


@pytest.mark.description(
    "When the data length is not valid (depending on P1), the command should be rejected with 0x6700"
)
@pytest.mark.test_spec("CHA_APP_GC_FAIL_03")
@pytest.mark.commands("get_certificate")
def test_cmd_get_certificate_wrong_lc(sender, client):
    check_applet_state(client)
    # Send GET CERTIFICATE with P1=0x00 and P2=0x00 (card static certificate)
    # without the wallet challenge (Lc=0x00)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.GET_CARD_CERTIFICATE,
        p1=P1.P1_DEFAULT,
        p2=P2.P2_DEFAULT,
        data=b"",
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)
    # Send GET CERTIFICATE with P1=0x00 and P2=0x00 (card static certificate)
    # with a wallet challenge too long (Lc > 0x08)
    check_applet_state(client)
    wrong_lc = 0x09
    challenge = bytearray([0x00] * wrong_lc)
    apdu = (
        bytearray(
            [CLA, InsType.GET_CARD_CERTIFICATE, P1.P1_DEFAULT, P2.P2_DEFAULT, wrong_lc]
        )
        + challenge
    )
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)
    # Send GET CERTIFICATE with P1=0x80 and P2=0x00 (card ephemeral certificate)
    # with some dummy data (Lc > 0x00)
    check_applet_state(client)
    wrong_lc = 0x04
    dummy_data = bytearray([0x00] * wrong_lc)
    apdu = (
        bytearray([CLA, InsType.GET_CARD_CERTIFICATE, 0x80, P2.P2_DEFAULT, wrong_lc])
        + dummy_data
    )
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)
    check_applet_state(client)
