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
    RecoveryKeyClient,
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
    TEST_SEED,
)

logger = logging.getLogger(__name__)


def configure_client_and_check_state(
    client, pin_digits=bytes([0x01, 0x02, 0x03, 0x04])
):
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
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
    client = RecoveryKeyClient(sender, capsule_algo=CapsuleAlgorithm.AES_CBC_HMAC)
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


@pytest.mark.description("'GET STATUS' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_MGMT_OK_01")
@pytest.mark.state_machine("perso_pin_unlock")
def test_fsm_perso_pin_unlock_get_status(client):
    # This function calls client.get_status() which verifies that GET STATUS returns 0x9000
    configure_client_and_check_state(client)


@pytest.mark.description("'GET DATA' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_MGMT_OK_02")
@pytest.mark.state_machine("perso_pin_unlock")
def test_fsm_perso_pin_unlock_get_data(client):
    logger.info("CHA_STATE_UP_MGMT_OK_02")
    configure_client_and_check_state(client)
    data_tag = "9F17"
    client.get_data(int(data_tag, 16))


@pytest.mark.description("'RESTORE SEED' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_MGMT_OK_04")
@pytest.mark.state_machine("perso_pin_unlock")
def test_fsm_perso_pin_unlock_restore_seed(client):
    configure_client_and_check_state(client)
    restored_seed_len, restored_seed = client.restore_seed()
    # Assert that the seed restored is the same as the one we set
    assert restored_seed_len == SEED_LEN
    assert restored_seed == TEST_SEED


@pytest.mark.description("'VERIFY SEED' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_MGMT_OK_05")
@pytest.mark.state_machine("perso_pin_unlock")
def test_fsm_perso_pin_unlock_verify_seed(client):
    configure_client_and_check_state(client)
    client.verify_seed(TEST_SEED)


@pytest.mark.description("'SET DATA' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_MGMT_OK_06")
@pytest.mark.state_machine("perso_pin_unlock")
def test_fsm_perso_pin_unlock_set_data(client):
    configure_client_and_check_state(client)
    data_tag = "0066"
    client.set_data(int(data_tag, 16), "dummy".encode())


@pytest.mark.description("'FACTORY RESET' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_MGMT_OK_07")
@pytest.mark.state_machine("perso_pin_unlock")
@pytest.mark.order("last")
def test_fsm_perso_pin_unlock_factory_reset(client):
    # This is the last test, it comes after the pin change so we have to use
    # the new pin.
    pin_digits = bytes([0x04, 0x03, 0x02, 0x01])
    configure_client_and_check_state(client, pin_digits)
    client.factory_reset()


@pytest.mark.description("'REQUEST UPGRADE' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_MGMT_OK_08")
@pytest.mark.state_machine("perso_pin_unlock")
def test_fsm_perso_pin_unlock_request_upgrade(client):
    configure_client_and_check_state(client)
    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    client.request_upgrade(pin_digits)


@pytest.mark.description("Unauthorized commands should be rejected with 0x6985")
@pytest.mark.test_spec("CHA_STATE_UP_MGMT_FAIL_01")
@pytest.mark.state_machine("perso_pin_unlock")
def test_fsm_perso_pin_unlock_unauthorized_cmds(client):
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

    with pytest.raises(AssertionError) as e:
        client.mark_factory_tests_passed()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED


@pytest.mark.description("'CHANGE PIN' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_UP_MGMT_OK_03")
@pytest.mark.state_machine("perso_pin_unlock")
def test_fsm_perso_pin_unlock_change_pin(client):
    configure_client_and_check_state(client)
    pin_digits = bytes([0x04, 0x03, 0x02, 0x01])
    client.change_pin(pin_digits)
