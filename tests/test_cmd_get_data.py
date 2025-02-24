import logging
import pytest
import os
from ledger_pluto.client import (
    CLA,
    InsType,
    CharonClient,
    CapsuleAlgorithm,
)
from ledger_pluto.command_sender import GPCommandSender
from ledger_pluto.backend.jrcp_backend import JRCPBackend
from .conftest import (
    TEST_AUTH_PRIV_KEY,
    TEST_ISSUER_PRIV_KEY,
    ENC_KEY,
    MAC_KEY,
    AID,
    TEST_SEED,
    StatusWords,
    assert_sw,
)

logger = logging.getLogger(__name__)


def configure_client_and_check_state(client):
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    infos = client.get_status()
    assert infos.fsm_state == "User_Personalized"
    assert infos.transient_fsm_state == "Authenticated"


@pytest.fixture(scope="module", autouse=True)
def setup_applet():
    # Create a connection to the (simulated) card
    backend = JRCPBackend()
    backend.connect()
    # Create the sender object
    sender = GPCommandSender(backend, ENC_KEY, MAC_KEY)
    sender.send_select(AID)
    sender.open_secure_channel()
    client = CharonClient(sender, capsule_algo=CapsuleAlgorithm.AES_CBC_HMAC)
    # Set certificate to enter Attested mode and authenticate
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
    client.set_seed(TEST_SEED)
    backend.disconnect()


@pytest.mark.description(
    "'GET DATA' is supported and should return 0x9000 as well as the data requested"
)
@pytest.mark.test_spec("CHA_APP_GD_OK_01")
@pytest.mark.commands("get_data")
@pytest.mark.order("last")
def test_cmd_get_data(client):
    configure_client_and_check_state(client)
    data_tag = "9F17"
    # The client also checks many conditions that the response should meet :
    # - Check tag is valid for get data
    # - Check if the response is None
    # - Check if the data is empty
    # - Check if the tag matches in the response
    # - Check if the length matches in the response
    response = client.get_data(int(data_tag, 16))
    assert response == ("Pin try counter", 3)
    # Check that after the card name is set, it can be retrieved correctly
    data_tag = "0066"
    card_name = "Pluto"
    client.verify_pin(bytes([0x01, 0x02, 0x03, 0x04]))
    client.set_data(int(data_tag, 16), card_name.encode())
    response = client.get_data(int(data_tag, 16))
    assert response == ("Card name", card_name)


@pytest.mark.description(
    "When P1/P2 differ from a valid tag value (0x0066 and 0x9F17), the command should be rejected with 0x6A86"
)
@pytest.mark.test_spec("CHA_APP_GD_FAIL_01")
@pytest.mark.commands("get_data")
def test_cmd_get_data_wrong_p1p2(client, sender):
    configure_client_and_check_state(client)
    wrong_p1 = 0x9D
    p2 = 0x17
    apdu_header = bytearray([CLA, InsType.GET_DATA, wrong_p1, p2])
    mac = client.capsule.mac_apdu_header(apdu_header)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.GET_DATA, p1=wrong_p1, p2=p2, data=mac
    )
    assert_sw(sw1, sw2, StatusWords.WRONG_P1_P2)


@pytest.mark.description(
    "When the requested data is not found, the command should be rejected with 0x6A88"
)
@pytest.mark.test_spec("CHA_APP_GD_FAIL_02")
@pytest.mark.commands("get_data")
def test_cmd_get_data_not_found(client, sender):
    configure_client_and_check_state(client)
    p1 = 0x00
    p2 = 0x66
    apdu_header = bytearray([CLA, InsType.GET_DATA, p1, p2])
    mac = client.capsule.mac_apdu_header(apdu_header)
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.GET_DATA, p1=p1, p2=p2, data=mac
    )
    assert_sw(sw1, sw2, StatusWords.DATA_NOT_FOUND)


@pytest.mark.description(
    "When the MAC is missing, the command should be rejected with 0x6887"
)
@pytest.mark.test_spec("CHA_APP_GD_FAIL_03")
@pytest.mark.commands("get_data")
def test_cmd_get_data_missing_mac(client, sender):
    configure_client_and_check_state(client)
    p1 = 0x9F
    p2 = 0x17
    _, sw1, sw2 = sender.build_and_send_apdu_no_throw(
        cla=CLA, ins=InsType.GET_DATA, p1=p1, p2=p2, data=b""
    )
    assert_sw(sw1, sw2, StatusWords.MISSING_SCP_LEDGER)


@pytest.mark.description(
    "When the Lc has the wrong length (!= MAC data length), the command should be rejected with 0x6700"
)
@pytest.mark.test_spec("CHA_APP_GD_FAIL_04")
@pytest.mark.commands("get_data")
def test_cmd_get_data_wrong_length(client, sender):
    configure_client_and_check_state(client)
    p1 = 0x9F
    p2 = 0x17
    apdu_header = bytearray([CLA, InsType.GET_DATA, p1, p2])
    mac = client.capsule.mac_apdu_header(apdu_header)
    apdu = apdu_header + b"0x01" + mac
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)


@pytest.mark.description(
    "When the length field of the MAC data has the wrong value, the command should be rejected with 0x6700"
)
@pytest.mark.test_spec("CHA_APP_GD_FAIL_05")
@pytest.mark.commands("get_data")
def test_cmd_get_data_wrong_mac_length_field(client, sender):
    configure_client_and_check_state(client)
    p1 = 0x9F
    p2 = 0x17
    apdu_header = bytearray([CLA, InsType.GET_DATA, p1, p2])
    mac = client.capsule.mac_apdu_header(apdu_header)
    mac_array = bytearray(mac)
    mac_array[0] = 0x01
    apdu = apdu_header + len(mac).to_bytes(1, "big") + mac_array
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.WRONG_LENGTH)


@pytest.mark.description(
    "When the MAC value is erroneous, the command should be rejected with 0x6888"
)
@pytest.mark.test_spec("CHA_APP_GD_FAIL_06")
@pytest.mark.commands("get_data")
def test_cmd_get_data_wrong_mac_value(client, sender):
    configure_client_and_check_state(client)
    p1 = 0x9F
    p2 = 0x17
    apdu_header = bytearray([CLA, InsType.GET_DATA, p1, p2])
    mac = client.capsule.mac_apdu_header(apdu_header)
    mac_length = mac[0]
    dummy_mac = bytes([mac_length]) + os.urandom(mac_length)
    # Ensure the dummy MAC is different from the real one (otherwise the test is meaningless)
    if dummy_mac == mac:
        dummy_mac = bytes([mac_length]) + os.urandom(mac_length)
    apdu = apdu_header + len(mac).to_bytes(1, "big") + dummy_mac
    _, sw1, sw2 = sender.build_and_send_raw_apdu(apdu)
    assert_sw(sw1, sw2, StatusWords.INCORRECT_SCP_LEDGER)
