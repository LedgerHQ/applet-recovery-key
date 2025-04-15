import logging
import pytest
import os
from binascii import unhexlify
from ledger_pluto.client import CLA, InsType, P1, P2, HW_SERIAL_NUMBER, HW_PUBLIC_KEY
from ledger_pluto.client import RecoveryKeyClient, CapsuleAlgorithm
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
)

logger = logging.getLogger(__name__)


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "User_Personalized"
    assert infos.transient_fsm_state == "Pin_Unlocked"


def authenticate(client, pin=bytes([0x01, 0x02, 0x03, 0x04])):
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    client.verify_pin(pin)
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
    client = RecoveryKeyClient(sender, capsule_algo=CapsuleAlgorithm.AES_CBC_HMAC)
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
    check_applet_state(client)


@pytest.mark.description("'CHANGE PIN' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_APP_PC_OK_01")
@pytest.mark.commands("change_pin")
@pytest.mark.order("last")
def test_cmd_change_pin(client, sender):
    authenticate(client)
    pin_digits = bytes([0x04, 0x03, 0x02, 0x01, 0x00])
    client.change_pin(pin_digits)
    check_applet_state(client)
    # Re-authenticate with the new PIN to be sure it was correctly changed
    backend = JRCPBackend()
    backend.connect()
    sender = GPCommandSender(backend, ENC_KEY, MAC_KEY)
    sender.send_select(AID)
    sender.open_secure_channel()
    client = RecoveryKeyClient(sender, capsule_algo=CapsuleAlgorithm.AES_CBC_HMAC)
    authenticate(client, pin_digits)


@pytest.mark.description(
    "When P1 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_CP_FAIL_01")
@pytest.mark.commands("change_pin")
def test_cmd_change_pin_wrong_p1(client, sender):
    authenticate(client)
    wrong_p1 = 0x22
    dummy_data = bytearray([0x00] * 0x04)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.PIN_CHANGE,
        p1=wrong_p1,
        p2=P2.P2_DEFAULT,
        data=dummy_data,
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)
    check_applet_state(client)


@pytest.mark.description(
    "When P2 differs from 0x00, the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_CP_FAIL_02")
@pytest.mark.commands("change_pin")
def test_cmd_change_pin_wrong_p2(sender, client):
    authenticate(client)
    wrong_p2 = 0x22
    dummy_data = bytearray([0x00] * 0x04)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.PIN_CHANGE,
        p1=P1.P1_DEFAULT,
        p2=wrong_p2,
        data=dummy_data,
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)
    check_applet_state(client)


@pytest.mark.description(
    "When PIN data is missing, the command should be rejected with 0x6887"
)
@pytest.mark.test_spec("CHA_APP_CP_FAIL_03")
@pytest.mark.commands("change_pin")
def test_cmd_change_pin_missing_data(sender, client):
    authenticate(client)
    # Send CHANGE PIN with P1=0x00 and P2=0x00 with lc=0x00 (no data)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA,
        ins=InsType.PIN_CHANGE,
        p1=P1.P1_DEFAULT,
        p2=P2.P2_DEFAULT,
        data=b"",
    )
    assert_sw(sw1, sw2, StatusWords.MISSING_SCP_LEDGER)
    check_applet_state(client)


@pytest.mark.description(
    "When the plain text PIN data is not properly formatted or has the wrong length, the command should be rejected with 0x6A80"
)
@pytest.mark.test_spec("CHA_APP_CP_FAIL_04")
@pytest.mark.commands("change_pin")
def test_cmd_change_pin_wrong_data(client):
    authenticate(client)
    # Send CHANGE PIN with P1=0x00 and P2=0x00 with lc=pin length + 1 (wrong length)
    pin = bytearray([0x01, 0x02, 0x03])
    pin_length = len(pin) + 1

    data = pin_length.to_bytes(1, "big") + pin
    data = client.capsule.encrypt(data)
    _, sw1, sw2 = client.sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.PIN_CHANGE, p1=P1.P1_DEFAULT, p2=P2.P2_DEFAULT, data=data
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_PARAMETERS)
    check_applet_state(client)
    # Send CHANGE PIN with P1=0x00 and P2=0x00 with pin length > 8 (wrong length)
    pin = bytearray([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09])
    pin_length = len(pin)
    data = pin_length.to_bytes(1, "big") + pin
    data = client.capsule.encrypt(data)
    _, sw1, sw2 = client.sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.PIN_CHANGE, p1=P1.P1_DEFAULT, p2=P2.P2_DEFAULT, data=data
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_PARAMETERS)
    check_applet_state(client)
    # Send CHANGE PIN with P1=0x00 and P2=0x00 with pin length < 4 (wrong length)
    pin = bytearray([0x01, 0x02])
    pin_length = len(pin)
    data = pin_length.to_bytes(1, "big") + pin
    data = client.capsule.encrypt(data)
    _, sw1, sw2 = client.sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.PIN_CHANGE, p1=P1.P1_DEFAULT, p2=P2.P2_DEFAULT, data=data
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_PARAMETERS)
    check_applet_state(client)
