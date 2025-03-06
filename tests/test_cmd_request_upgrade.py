import logging
import pytest
import os
from ledger_pluto.client import CLA, InsType, P1, P2
from ledger_pluto.client import CharonClient, CapsuleAlgorithm
from ledger_pluto.command_sender import GPCommandSender
from ledger_pluto.backend.jrcp_backend import JRCPBackend
from .conftest import (
    TEST_ISSUER_PRIV_KEY,
    TEST_AUTH_PRIV_KEY,
    AID,
    StatusWords,
    assert_sw,
    SEED_LEN,
    ENC_KEY,
    MAC_KEY,
    CAP_FILE_UPGRADE,
)

logger = logging.getLogger(__name__)


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "User_Personalized"
    assert infos.transient_fsm_state == "Authenticated"


def authenticate(client):
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    check_applet_state(client)


@pytest.fixture(scope="module", autouse=True)
def configure_applet():
    # Create a connection to the (simulated) card
    backend = JRCPBackend()
    backend.connect()
    # Create the sender object
    sender = GPCommandSender(backend, ENC_KEY, MAC_KEY)
    sender.send_select(AID)
    sender.open_secure_channel()
    client = CharonClient(sender, capsule_algo=CapsuleAlgorithm.AES_CBC_HMAC)
    client.set_issuer_key(AID, bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    client.get_public_key_and_verify()
    client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.mark_factory_tests_passed()
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    client.set_pin(pin_digits)
    seed = os.urandom(SEED_LEN)
    client.set_seed(seed)
    infos = client.get_status()
    assert infos.fsm_state == "User_Personalized"
    assert infos.transient_fsm_state == "Pin_Unlocked"


@pytest.mark.description(
    "'REQUEST UPGRADE' is supported and should return 0x9000. Applet upgrade should succeed."
)
@pytest.mark.test_spec("CHA_APP_RU_OK_01")
@pytest.mark.commands("request_upgrade")
@pytest.mark.order("last")
def test_cmd_request_upgrade(loader, client):
    authenticate(client)
    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    client.request_upgrade(pin_digits)
    check_applet_state(client)
    loader.upgrade_applet(CAP_FILE_UPGRADE)


@pytest.mark.description(
    "When P1 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_RU_FAIL_01")
@pytest.mark.commands("request_upgrade")
def test_cmd_request_upgrade_wrong_p1(sender, client):
    authenticate(client)
    wrong_p1 = 0x22
    dummy_data = bytearray([0x00] * 0x04)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.REQUEST_UPGRADE,
        p1=wrong_p1,
        p2=P2.P2_DEFAULT,
        data=dummy_data,
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)
    check_applet_state(client)


@pytest.mark.description(
    "When P2 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_RU_FAIL_02")
@pytest.mark.commands("request_upgrade")
def test_cmd_request_upgrade_wrong_p2(sender, client):
    authenticate(client)
    wrong_p2 = 0x22
    dummy_data = bytearray([0x00] * 0x04)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.REQUEST_UPGRADE,
        p1=P1.P1_DEFAULT,
        p2=wrong_p2,
        data=dummy_data,
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)
    check_applet_state(client)


@pytest.mark.description(
    "When PIN data is missing, the command should be rejected with 0x6887"
)
@pytest.mark.test_spec("CHA_APP_RU_FAIL_03")
@pytest.mark.commands("request_upgrade")
def test_cmd_request_upgrade_missing_data(sender, client):
    authenticate(client)
    # Send REQUEST UPGRADE with P1=0x00 and P2=0x00 with lc=0x00 (no data)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.REQUEST_UPGRADE,
        p1=P1.P1_DEFAULT,
        p2=P2.P2_DEFAULT,
        data=b"",
    )
    assert_sw(sw1, sw2, StatusWords.MISSING_SCP_LEDGER)
    check_applet_state(client)


@pytest.mark.description(
    "When the plain text PIN data is not properly formatted or has the wrong length, the command should be rejected with 0x6A80"
)
@pytest.mark.test_spec("CHA_APP_RU_FAIL_04")
@pytest.mark.commands("request_upgrade")
def test_cmd_request_upgrade_wrong_data(client):
    authenticate(client)
    # Send REQUEST UPGRADE with P1=0x00 and P2=0x00 with lc=pin length + 1 (wrong length)
    pin = bytearray([0x01, 0x02, 0x03])
    pin_length = len(pin) + 1

    data = pin_length.to_bytes(1, "big") + pin
    data = client.capsule.encrypt(data)
    _, sw1, sw2 = client.sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.REQUEST_UPGRADE,
        p1=P1.P1_DEFAULT,
        p2=P2.P2_DEFAULT,
        data=data,
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_PARAMETERS)
    check_applet_state(client)
    # Send REQUEST UPGRADE with P1=0x00 and P2=0x00 with pin length > 8 (wrong length)
    pin = bytearray([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09])
    pin_length = len(pin)
    data = pin_length.to_bytes(1, "big") + pin
    data = client.capsule.encrypt(data)
    _, sw1, sw2 = client.sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.REQUEST_UPGRADE,
        p1=P1.P1_DEFAULT,
        p2=P2.P2_DEFAULT,
        data=data,
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_PARAMETERS)
    check_applet_state(client)
    # Send REQUEST UPGRADE with P1=0x00 and P2=0x00 with pin length < 4 (wrong length)
    pin = bytearray([0x01, 0x02])
    pin_length = len(pin)
    data = pin_length.to_bytes(1, "big") + pin
    data = client.capsule.encrypt(data)
    _, sw1, sw2 = client.sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.REQUEST_UPGRADE,
        p1=P1.P1_DEFAULT,
        p2=P2.P2_DEFAULT,
        data=data,
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_PARAMETERS)
    check_applet_state(client)


@pytest.mark.description(
    "When PIN data is erroneous, the command should be rejected with 0x6A80 and the upgrade should fail with 0x6982"
)
@pytest.mark.test_spec("CHA_APP_RU_FAIL_05")
@pytest.mark.commands("request_upgrade")
@pytest.mark.order(-2)
def test_cmd_request_upgrade_wrong_pin(client, loader):
    authenticate(client)
    pin_digits = bytes([0x01, 0x02, 0x03, 0x05])
    with pytest.raises(AssertionError) as e:
        client.request_upgrade(pin_digits)
    assert str(e.value) == "Status Word: 0x6A80"
    check_applet_state(client)
    with pytest.raises(AssertionError) as e:
        loader.upgrade_applet(CAP_FILE_UPGRADE)
    assert str(e.value) == "Status Word: 0x6982"
