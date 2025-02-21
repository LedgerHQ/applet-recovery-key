import logging
import pytest
from ledger_pluto.client import CLA, InsType, P1, P2
from ledger_pluto.command_sender import GPCommandSender
from ledger_pluto.applet_loader import AppletLoader
from ledger_pluto.card_manager import CardManager
from ledger_pluto.backend.jrcp_backend import JRCPBackend
from ledger_pluto.ledger_pluto import configure_nxp_sim
from .conftest import (
    TEST_ISSUER_PRIV_KEY,
    TEST_AUTH_PRIV_KEY,
    AID,
    StatusWords,
    ENC_KEY,
    MAC_KEY,
    DEK_KEY,
    CAP_FILE,
    INSTALL_PARAMS,
    assert_sw,
)

logger = logging.getLogger(__name__)


@pytest.fixture(scope="function", autouse=True)
def install_applet():
    backend = JRCPBackend()
    backend.connect()
    configure_nxp_sim(None, ENC_KEY, MAC_KEY, DEK_KEY, "", backend)
    sender = GPCommandSender(backend, ENC_KEY, MAC_KEY)
    manager = CardManager(sender)
    loader = AppletLoader(sender, manager)
    loader.install_applet(CAP_FILE, install_params=INSTALL_PARAMS)
    backend.disconnect()


def configure_applet(client):
    client.set_issuer_key(AID, bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    client.get_public_key_and_verify()
    client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    infos = client.get_status()
    assert infos.fsm_state == "Pending_Tests"
    assert infos.transient_fsm_state == "Idle"


@pytest.mark.description(
    "'MARK_FACTORY_TESTS_PASSED' is supported and should return 0x9000"
)
@pytest.mark.test_spec("CHA_APP_FT_OK_01")
@pytest.mark.commands("mark_factory_tests_passed")
def test_cmd_mark_factory_tests_passed(client):
    configure_applet(client)
    client.mark_factory_tests_passed()
    infos = client.get_status()
    assert infos.fsm_state == "Attested"
    assert infos.transient_fsm_state == "Initialized"


@pytest.mark.description(
    "When P1 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_FT_FAIL_01")
@pytest.mark.commands("mark_factory_tests_passed")
def test_cmd_mark_factory_tests_passed_wrong_p1(sender, client):
    configure_applet(client)
    wrong_p1 = 0x01
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.MARK_FACTORY_TESTS_PASSED,
        p1=wrong_p1,
        p2=P2.P2_DEFAULT,
        data=b"",
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)


@pytest.mark.description(
    "When P2 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_FT_FAIL_02")
@pytest.mark.commands("mark_factory_tests_passed")
def test_cmd_mark_factory_tests_passed_wrong_p2(sender, client):
    configure_applet(client)
    wrong_p2 = 0x01
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.MARK_FACTORY_TESTS_PASSED,
        p1=P1.P1_DEFAULT,
        p2=wrong_p2,
        data=b"",
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)


@pytest.mark.description(
    "When Lc differs from 0x00, the command should be rejected with 0x6700"
)
@pytest.mark.test_spec("CHA_APP_FT_FAIL_03")
@pytest.mark.commands("mark_factory_tests_passed")
def test_cmd_mark_factory_tests_passed_wrong_lc(sender, client):
    configure_applet(client)
    wrong_lc = 0x01
    dummy_data = bytearray([0x00] * wrong_lc)
    apdu = (
        bytearray(
            [
                CLA,
                InsType.MARK_FACTORY_TESTS_PASSED,
                P1.P1_DEFAULT,
                P2.P2_DEFAULT,
                wrong_lc,
            ]
        )
        + dummy_data
    )
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)
