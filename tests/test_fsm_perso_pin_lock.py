import logging
import os
import pytest
from ledgerblue.ecWrapper import PrivateKey
from ledger_pluto.client import (
    CharonClient,
    CapsuleAlgorithm,
)
from ledger_pluto.command_sender import GPCommandSender
from ledger_pluto.ledger_pluto import validate_reader
from .conftest import (
    TEST_AUTH_PRIV_KEY,
    TEST_ISSUER_PRIV_KEY,
    READER,
    ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED,
    ENC_KEY,
    MAC_KEY,
    AID,
)

# from ledger_pluto.command_sender import GPCommandSender
logger = logging.getLogger(__name__)


# def configure_client_and_check_state(client):
#     client.get_card_static_certificate_and_verify()
#     client.get_card_ephemeral_certificate_and_verify()
#     client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
#     client.validate_hw_ephemeral_certificate()
#     infos = client.get_infos()
#     assert infos.fsm_state == "Attested"
#     assert infos.transient_fsm_state == "Pin_Locked"


@pytest.fixture(scope="module", autouse=True)
def setup_applet():
    _, reader_obj = validate_reader(READER)
    # Create a connection to the (simulated) card
    connection = reader_obj.createConnection()
    connection.connect()
    # Create the sender object
    sender = GPCommandSender(ENC_KEY, MAC_KEY, connection)
    sender.send_select(AID)
    sender.open_scp03_secure_channel()
    client = CharonClient(sender, capsule_algo=CapsuleAlgorithm.AES_CBC_HMAC)
    # Set certificate to enter Attested mode and authenticate
    client.set_issuer_key(bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    client.get_public_key_and_verify()
    client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    client.set_pin(pin_digits)
    seed = os.urandom(64)
    client.set_seed(seed)
    connection.disconnect()


def check_applet_state(client):
    infos = client.get_infos()
    assert infos.fsm_state == "User_Personalized"
    assert infos.transient_fsm_state == "Pin_Locked"


# In User Personalized mode and before authentication, 'GET STATUS' is supported and should return 0x9000
def test_fsm_perso_pin_lock_get_status(client):
    logger.info("CHA_STATE_UP_LOCKED_OK_01")
    # This function calls client.get_infos() which verifies that GET STATUS returns 0x9000
    check_applet_state(client)


# In User Personalized mode and before authentication, 'GET CERTIFICATE' with P1 = 0x00 and P1 = 0x01 are supported and should return 0x9000
def test_fsm_perso_pin_lock_get_cert(client):
    logger.info("CHA_STATE_UP_LOCKED_OK_02")
    check_applet_state(client)
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()


@pytest.mark.skip("TODO: implement GET DATA command in applet first")
def test_fsm_perso_pin_lock_get_data(client):
    logger.info("CHA_STATE_UP_LOCKED_OK_03")
    check_applet_state(client)


# In User Personalized mode and before authentication, 'VALIDATE CERTIFICATE' with P1 = 0x00 and P1 = 0x01 are supported and should return 0x9000
def test_fsm_perso_pin_lock_validate_certificates(client):
    logger.info("CHA_STATE_UP_LOCKED_OK_04")
    check_applet_state(client)
    # We need to get the card certificates again because the connection was closed
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()


# In User Personalized mode and before authentication, the following commands should be rejected with 0x6985
def test_fsm_perso_pin_lock_unauthorized_cmds(client):
    logger.info("CHA_STATE_UP_LOCKED_FAIL_01")

    dummy_priv_key = PrivateKey()
    dummy_pub_key = dummy_priv_key.pubkey.serialize(compressed=False)
    dummy_seed = os.urandom(64)

    check_applet_state(client)
    client.card_serial_number = bytes([0x01, 0x02, 0x03, 0x04])
    client.card_public_key = dummy_pub_key

    with pytest.raises(AssertionError) as e:
        client.get_public_key_and_verify()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    client.capsule.set_hw_ephemeral_private_key(dummy_priv_key)
    client.capsule.set_card_ephemeral_public_key(dummy_pub_key)
    client.capsule.generate_session_keys()

    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    with pytest.raises(AssertionError) as e:
        client.set_pin(pin_digits)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.set_seed(dummy_seed)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    with pytest.raises(AssertionError) as e:
        client.verify_pin(pin_digits)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.change_pin(pin_digits)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.restore_seed()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    # TODO: implement this command in the applet
    # with pytest.raises(AssertionError) as e:
    #     client.verify_seed(dummy_seed)

    # TODO: implement this command in the applet
    # with pytest.raises(AssertionError) as e:
    # client.set_data()

    # TODO: implement this command in the client
    # with pytest.raises(AssertionError) as e:
    # client.factory_reset()
