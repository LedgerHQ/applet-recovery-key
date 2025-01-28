import logging
import pytest
from ledger_pluto.client import CLA, InsType, P1, P2
from .conftest import (
    StatusWords,
    assert_sw,
)

logger = logging.getLogger(__name__)


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "Fabrication"
    assert infos.transient_fsm_state == "Idle"


@pytest.mark.description("'GET STATUS' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_APP_GS_OK_01")
@pytest.mark.commands("get_status")
def test_cmd_get_status(client):
    # This function calls client.get_status() which verifies that GET STATUS returns 0x9000
    check_applet_state(client)


@pytest.mark.description(
    "When P1 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_GS_FAIL_01")
@pytest.mark.commands("get_status")
def test_cmd_get_status_wrong_p1(sender):
    wrong_p1 = 0x01
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.GET_STATUS, p1=wrong_p1, p2=P2.P2_DEFAULT, data=b""
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)


@pytest.mark.description(
    "When P2 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_GS_FAIL_02")
@pytest.mark.commands("get_status")
def test_cmd_get_status_wrong_p2(sender):
    wrong_p2 = 0x01
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.GET_STATUS, p1=P1.P1_DEFAULT, p2=wrong_p2, data=b""
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)


@pytest.mark.description(
    "When Lc differs from 0x00, the command should be rejected with 0x6700"
)
@pytest.mark.test_spec("CHA_APP_GS_FAIL_03")
@pytest.mark.commands("get_status")
def test_cmd_get_status_wrong_lc(sender):
    wrong_lc = 0x01
    dummy_data = bytearray([0x00] * wrong_lc)
    apdu = (
        bytearray([CLA, InsType.GET_STATUS, P1.P1_DEFAULT, P2.P2_DEFAULT, wrong_lc])
        + dummy_data
    )
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)
