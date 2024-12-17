import logging
import os
import pytest
from ledgerblue.ecWrapper import PrivateKey
from binascii import unhexlify
from ledger_pluto.client import (
    CLA,
    InsType,
    P1,
    P2,
    HW_PUBLIC_KEY,
    HW_SERIAL_NUMBER,
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


def configure_client_and_check_state(client):
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    client.verify_pin(pin_digits)
    infos = client.get_status()
    assert infos.fsm_state == "User_Personalized"
    assert infos.transient_fsm_state == "Pin_Unlocked"


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


# In User Personalized mode, after authentication and after PIN verification, 'GET STATUS' is supported and should return 0x9000
def test_fsm_perso_pin_unlock_get_status(client):
    logger.info("CHA_STATE_UP_MGMT_OK_01")
    # This function calls client.get_status() which verifies that GET STATUS returns 0x9000
    configure_client_and_check_state(client)


@pytest.mark.skip("TODO: implement GET DATA command in applet first")
def test_fsm_perso_pin_unlock_get_data(client):
    logger.info("CHA_STATE_UP_MGMT_OK_02")
    configure_client_and_check_state(client)


def test_fsm_perso_pin_unlock_restore_seed(client):
    logger.info("CHA_STATE_UP_MGMT_OK_04")
    configure_client_and_check_state(client)
    client.restore_seed()


@pytest.mark.skip("TODO: implement VERIFY SEED command in applet first")
def test_fsm_perso_pin_unlock_verify_seed(client):
    logger.info("CHA_STATE_UP_MGMT_OK_05")
    configure_client_and_check_state(client)
    # client.verify_seed()


@pytest.mark.skip("TODO: implement SET DATA command in applet first")
def test_fsm_perso_pin_unlock_set_data(client):
    logger.info("CHA_STATE_UP_MGMT_OK_06")
    configure_client_and_check_state(client)
    # client.set_data()


@pytest.mark.skip("TODO: implement FACTORY RESET command in applet first")
def test_fsm_perso_pin_unlock_factory_reset(client):
    logger.info("CHA_STATE_UP_MGMT_OK_07")
    configure_client_and_check_state(client)
    # client.factory_reset()


# In User Personalized mode, after authentication and after PIN verification, the following commands should be rejected with 0x6985
def test_fsm_perso_pin_unlock_unauthorized_cmds(client):
    logger.info("CHA_STATE_UP_MGMT_FAIL_01")

    configure_client_and_check_state(client)

    with pytest.raises(AssertionError) as e:
        client.get_public_key_and_verify()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.get_card_static_certificate_and_verify()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.get_card_ephemeral_certificate_and_verify()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        hw_static_certificate, _ = client.generate_hw_static_certificate(
            unhexlify(HW_SERIAL_NUMBER),
            unhexlify(HW_PUBLIC_KEY),
            bytearray.fromhex(TEST_AUTH_PRIV_KEY),
        )
        client.sender.build_and_send_apdu(
            cla=CLA,
            ins=InsType.VALIDATE_HOST_CERTIFICATE,
            p1=P1.VALIDATE_CERTIFICATE_P1_STATIC,
            p2=P2.P2_DEFAULT,
            data=unhexlify(hw_static_certificate),
        )
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.hw_ephemeral_private_key = PrivateKey()
        client.hw_ephemeral_public_key = client.hw_ephemeral_private_key.pubkey
        hw_ephemeral_certificate, _ = client.generate_hw_ephemeral_certificate(
            client.host_challenge,
            client.card_challenge,
            client.hw_ephemeral_public_key.serialize(compressed=False),
        )
        client.sender.build_and_send_apdu(
            cla=CLA,
            ins=InsType.VALIDATE_HOST_CERTIFICATE,
            p1=P1.VALIDATE_CERTIFICATE_P1_EPHEMERAL,
            p2=P2.P2_DEFAULT,
            data=unhexlify(hw_ephemeral_certificate),
        )
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    with pytest.raises(AssertionError) as e:
        client.set_pin(pin_digits)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.verify_pin(pin_digits)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    dummy_seed = os.urandom(SEED_LEN)
    with pytest.raises(AssertionError) as e:
        client.set_seed(dummy_seed)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED


def test_fsm_perso_pin_unlock_change_pin(client):
    logger.info("CHA_STATE_UP_MGMT_OK_03")
    configure_client_and_check_state(client)
    pin_digits = bytes([0x04, 0x03, 0x02, 0x01])
    client.change_pin(pin_digits)
