import logging
import os
import pytest
from ledgerblue.ecWrapper import PrivateKey
from binascii import unhexlify
from ledger_pluto.client import CLA, InsType, P1, P2, HW_PUBLIC_KEY, HW_SERIAL_NUMBER
from .conftest import (
    TEST_AUTH_PRIV_KEY,
    TEST_ISSUER_PRIV_KEY,
    ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED,
    SEED_LEN,
    AID,
)

logger = logging.getLogger(__name__)


def configure_client_and_check_state(client):
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    infos = client.get_status()
    assert infos.fsm_state == "Attested"
    assert infos.transient_fsm_state == "Authenticated"


@pytest.mark.description("'GET STATUS' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_HSM2_OK_01")
@pytest.mark.state_machine("attested2")
def test_fsm_attested_auth_get_status(client):
    # Set certificate to enter Attested mode and authenticate
    client.set_issuer_key(AID, bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    client.get_public_key_and_verify()
    client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    client.validate_hw_static_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.validate_hw_ephemeral_certificate()
    infos = client.get_status()
    assert infos.fsm_state == "Attested"
    assert infos.transient_fsm_state == "Authenticated"


@pytest.mark.description("'SET PIN' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_HSM2_OK_02")
@pytest.mark.state_machine("attested2")
def test_fsm_attested_auth_set_pin(client):
    configure_client_and_check_state(client)
    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    client.set_pin(pin_digits)


@pytest.mark.description("Unauthorized commands should be rejected with 0x6985")
@pytest.mark.test_spec("CHA_STATE_HSM2_FAIL_01")
@pytest.mark.state_machine("attested2")
def test_fsm_attest_auth_unauthorized_cmds(client):
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
        client.verify_pin(pin_digits)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.change_pin(pin_digits)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.restore_seed()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        dummy_seed = os.urandom(SEED_LEN)
        client.verify_seed(dummy_seed)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        data_tag = "0066"
        client.set_data(int(data_tag, 16), "dummy".encode())
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.factory_reset()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED


@pytest.mark.description(
    "After 'SET PIN' has been properly sent, 'SET SEED' is supported and should return 0x9000"
)
@pytest.mark.test_spec("CHA_STATE_HSM2_OK_03")
@pytest.mark.state_machine("attested2")
def test_fsm_attested_auth_set_seed(client):
    configure_client_and_check_state(client)
    pin_digits = bytes([0x01, 0x02, 0x03, 0x04])
    client.set_pin(pin_digits)
    seed = os.urandom(SEED_LEN)
    client.set_seed(seed)
