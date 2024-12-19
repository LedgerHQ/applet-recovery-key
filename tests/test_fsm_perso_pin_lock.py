import logging
import os
import pytest
from ledgerblue.ecWrapper import PrivateKey
from ledger_pluto.client import (
    CharonClient,
    CapsuleAlgorithm,
)
from ledger_pluto.command_sender import GPCommandSender
from ledger_pluto.backend.jrcp_backend import JRCPBackend
from .conftest import (
    TEST_AUTH_PRIV_KEY,
    TEST_ISSUER_PRIV_KEY,
    ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED,
    ENC_KEY,
    MAC_KEY,
    AID,
    SEED_LEN,
)

logger = logging.getLogger(__name__)


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
    client.set_issuer_key(bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    client.get_public_key_and_verify()
    client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    client.set_pin(pin_digits)
    seed = os.urandom(SEED_LEN)
    client.set_seed(seed)
    backend.disconnect()


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "User_Personalized"
    assert infos.transient_fsm_state == "Pin_Locked"


@pytest.mark.description("'GET STATUS' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_LOCKED_OK_01")
@pytest.mark.state_machine("perso_pin_lock")
def test_fsm_perso_pin_lock_get_status(client):
    # This function calls client.get_status() which verifies that GET STATUS returns 0x9000
    check_applet_state(client)


@pytest.mark.description(
    "'GET CERTIFICATE' with P1 = 0x00 and P1 = 0x01 are supported and should return 0x9000"
)
@pytest.mark.test_spec("CHA_STATE_UP_LOCKED_OK_02")
@pytest.mark.state_machine("perso_pin_lock")
def test_fsm_perso_pin_lock_get_cert(client):
    check_applet_state(client)
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()


@pytest.mark.description("'GET DATA' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_LOCKED_OK_03")
@pytest.mark.state_machine("perso_pin_lock")
@pytest.mark.skip("TODO: implement GET DATA command in applet first")
def test_fsm_perso_pin_lock_get_data(client):
    check_applet_state(client)


@pytest.mark.description(
    "'VALIDATE CERTIFICATE' with P1 = 0x00 and P1 = 0x01 are supported and should return 0x9000"
)
@pytest.mark.test_spec("CHA_STATE_UP_LOCKED_OK_04")
@pytest.mark.state_machine("perso_pin_lock")
def test_fsm_perso_pin_lock_validate_certificates(client):
    check_applet_state(client)
    # We need to get the card certificates again because the connection was closed
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()


@pytest.mark.description("Unauthorized commands should be rejected with 0x6985")
@pytest.mark.test_spec("CHA_STATE_UP_LOCKED_FAIL_01")
@pytest.mark.state_machine("perso_pin_lock")
def test_fsm_perso_pin_lock_unauthorized_cmds(client):
    dummy_priv_key = PrivateKey()
    dummy_pub_key = dummy_priv_key.pubkey.serialize(compressed=False)
    dummy_seed = os.urandom(SEED_LEN)

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
