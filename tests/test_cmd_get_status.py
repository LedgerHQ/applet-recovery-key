import logging
import pytest
from ledger_pluto.client import CLA, InsType, P1, P2
from ledger_pluto.command_sender import GPCommandSender
from ledger_pluto.backend.jrcp_backend import JRCPBackend
from .conftest import (
    StatusWords,
    assert_sw,
    ENC_KEY,
    MAC_KEY,
    AID,
)

logger = logging.getLogger(__name__)


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "Fabrication"
    assert infos.transient_fsm_state == "Idle"


@pytest.mark.description(
    "'GET STATUS' is supported when a SCP03 secure channel is open and should return 0x9000"
)
@pytest.mark.test_spec("CHA_APP_GS_OK_01")
@pytest.mark.commands("get_status")
def test_cmd_get_status(client, sender):
    # This function calls client.get_status() which verifies that GET STATUS returns 0x9000
    assert sender.secure_channel_opened is True
    check_applet_state(client)


@pytest.mark.description(
    "'GET STATUS' is supported without a SCP03 secure channel and should return 0x9000"
)
@pytest.mark.test_spec("CHA_APP_GS_OK_02")
@pytest.mark.commands("get_status")
def test_cmd_get_status_no_secure_channel(client):
    backend = JRCPBackend()
    backend.connect()
    sender = GPCommandSender(backend, ENC_KEY, MAC_KEY)
    client.sender = sender
    sender.send_select(AID)
    assert sender.secure_channel_opened is False
    check_applet_state(client)
    backend.disconnect()


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
