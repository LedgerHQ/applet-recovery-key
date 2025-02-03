import logging
import pytest
from ledger_pluto.client import CLA, InsType, P1, P2
from .conftest import (
    TEST_ISSUER_PRIV_KEY,
    AID,
    StatusWords,
    assert_sw,
)

logger = logging.getLogger(__name__)


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "Fabrication"
    assert infos.transient_fsm_state == "Idle"


def configure_client_and_check_state(client):
    client.set_issuer_key(AID, bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    check_applet_state(client)


@pytest.mark.description("'GET PUBLIC KEY' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_APP_GPK_OK_01")
@pytest.mark.commands("get_public_key")
def test_cmd_get_public_key(client):
    configure_client_and_check_state(client)
    # This client method verifies that GET PUBLIC KEY returns 0x9000 and also that
    # the card signature of the public key with the issuer private key is valid
    client.get_public_key_and_verify()


@pytest.mark.description(
    "When P1 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_GPK_FAIL_01")
@pytest.mark.commands("get_public_key")
def test_cmd_get_public_key_wrong_p1(sender):
    wrong_p1 = 0x01
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.GET_PUBLIC_KEY, p1=wrong_p1, p2=P2.P2_DEFAULT, data=b""
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)


@pytest.mark.description(
    "When P2 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_GPK_FAIL_02")
@pytest.mark.commands("get_public_key")
def test_cmd_get_public_key_wrong_p2(sender):
    wrong_p2 = 0x01
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.GET_PUBLIC_KEY, p1=P1.P1_DEFAULT, p2=wrong_p2, data=b""
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)


@pytest.mark.description(
    "When Lc differs from 0x00, the command should be rejected with 0x6700"
)
@pytest.mark.test_spec("CHA_APP_GPK_FAIL_03")
@pytest.mark.commands("get_public_key")
def test_cmd_get_public_key_wrong_lc(sender):
    wrong_lc = 0x01
    dummy_data = bytearray([0x00] * wrong_lc)
    apdu = (
        bytearray([CLA, InsType.GET_PUBLIC_KEY, P1.P1_DEFAULT, P2.P2_DEFAULT, wrong_lc])
        + dummy_data
    )
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)
