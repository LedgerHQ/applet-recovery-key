import logging
import pytest
from binascii import unhexlify
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
    infos = client.get_status()
    assert infos.fsm_state == "Fabrication"
    assert infos.transient_fsm_state == "Idle"


@pytest.mark.description("'SET CERTIFICATE' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_APP_SC_OK_01")
@pytest.mark.commands("set_certificate")
def test_cmd_set_certificate(client):
    configure_applet(client)
    client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    infos = client.get_status()
    assert infos.fsm_state == "Pending_Tests"
    assert infos.transient_fsm_state == "Idle"


@pytest.mark.description(
    "When P1 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_SC_FAIL_01")
@pytest.mark.commands("set_certificate")
def test_cmd_set_certificate_wrong_p1(sender, client):
    configure_applet(client)
    certificate, _ = client.generate_card_static_certificate(
        client.card_serial_number, client.card_public_key, unhexlify(TEST_AUTH_PRIV_KEY)
    )
    wrong_p1 = 0x01
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.SET_CERTIFICATE,
        p1=wrong_p1,
        p2=P2.P2_DEFAULT,
        data=unhexlify(certificate),
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)


@pytest.mark.description(
    "When P2 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_SC_FAIL_02")
@pytest.mark.commands("set_certificate")
def test_cmd_set_certificate_wrong_p2(sender, client):
    configure_applet(client)
    certificate, _ = client.generate_card_static_certificate(
        client.card_serial_number, client.card_public_key, unhexlify(TEST_AUTH_PRIV_KEY)
    )
    wrong_p2 = 0x01
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.SET_CERTIFICATE,
        p1=P1.P1_DEFAULT,
        p2=wrong_p2,
        data=unhexlify(certificate),
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)


@pytest.mark.description(
    "When certificate data is missing, the command should be rejected with 0x6700"
)
@pytest.mark.test_spec("CHA_APP_SC_FAIL_03")
@pytest.mark.commands("set_certificate")
def test_cmd_set_certificate_missing_data(sender, client):
    configure_applet(client)
    wrong_lc = 0x00
    apdu = bytearray(
        [CLA, InsType.SET_CERTIFICATE, P1.P1_DEFAULT, P2.P2_DEFAULT, wrong_lc]
    )
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)


@pytest.mark.description(
    "When the certificate signature verification fails, the command should be rejected with 0x6982"
)
@pytest.mark.test_spec("CHA_APP_SC_FAIL_04")
@pytest.mark.commands("set_certificate")
def test_cmd_set_certificate_failed_signature_verif(sender, client):
    configure_applet(client)
    certificate, _ = client.generate_card_static_certificate(
        client.card_serial_number, client.card_public_key, unhexlify(TEST_AUTH_PRIV_KEY)
    )
    # Tamper the signature
    wrong_data = bytearray(8)
    wrong_certificate = unhexlify(certificate)[:-8] + wrong_data
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.SET_CERTIFICATE,
        p1=P1.P1_DEFAULT,
        p2=P2.P2_DEFAULT,
        data=wrong_certificate,
    )
    assert_sw(sw1, sw2, StatusWords.SECURITY_STATUS_NOT_SATISFIED)


@pytest.mark.description(
    "When the card serial number in the certificate data is erroneous, the command should be rejected with 0x6A80"
)
@pytest.mark.test_spec("CHA_APP_SC_FAIL_05")
@pytest.mark.commands("set_certificate")
def test_cmd_set_certificate_wrong_card_serial(sender, client):
    configure_applet(client)
    wrong_serial_number = b'\xFF\xFF\xFF\xFF'
    certificate, _ = client.generate_card_static_certificate(
        wrong_serial_number, client.card_public_key, unhexlify(TEST_AUTH_PRIV_KEY)
    )
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.SET_CERTIFICATE,
        p1=P1.P1_DEFAULT,
        p2=P2.P2_DEFAULT,
        data=unhexlify(certificate),
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_PARAMETERS)
