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


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "Attested"
    assert infos.transient_fsm_state == "Initialized"


@pytest.mark.description("'GET STATUS' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_HSM1_OK_01")
@pytest.mark.state_machine("attested1")
@pytest.mark.order("first")
def test_fsm_attested_no_auth_get_status(client):
    # Set certificate to enter Attested mode
    client.set_issuer_key(AID, bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    client.get_public_key_and_verify()
    client.set_certificate(bytearray.fromhex(TEST_AUTH_PRIV_KEY))
    client.mark_factory_tests_passed()
    # This function calls client.get_status() which verifies that GET STATUS returns 0x9000
    check_applet_state(client)


@pytest.mark.description(
    "'GET CERTIFICATE' with P1 = 0x00 and P1 = 0x01 are supported and should return 0x9000"
)
@pytest.mark.test_spec("CHA_STATE_HSM1_OK_02")
@pytest.mark.state_machine("attested1")
def test_fsm_attested_no_auth_get_cert(client):
    check_applet_state(client)
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()


@pytest.mark.description("Unauthorized commands should be rejected with 0x6985")
@pytest.mark.test_spec("CHA_STATE_HSM1_FAIL_01")
@pytest.mark.state_machine("attested1")
def test_fsm_attest_no_auth_unauthorized_cmds(client):
    # Dummy ephemeral keys (we don't care about the actual values, it's just so the client
    # can send the commands we want to test)
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
        client.verify_seed(dummy_seed)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        data_tag = "0066"
        client.set_data(int(data_tag, 16), "dummy".encode())
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.factory_reset()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.mark_factory_tests_passed()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.request_upgrade(pin_digits)
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED


@pytest.mark.description(
    "'VALIDATE CERTIFICATE' with P1 = 0x00 and P1 = 0x01 are supported and should return 0x9000"
)
@pytest.mark.test_spec("CHA_STATE_HSM1_OK_03")
@pytest.mark.state_machine("attested1")
def test_fsm_attested_no_auth_validate_hw_cert(client):
    check_applet_state(client)
    # We need to get the card's static and ephemeral certificates first
    # (a bit redundant with test_fsm_attested_no_auth_get_cert but necessary)
    client.get_card_static_certificate_and_verify()
    client.get_card_ephemeral_certificate_and_verify()
    # Verify VALIDATE_CERTIFICATE with P1 = 0x00 returns 0x9000
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
    # Verify VALIDATE_CERTIFICATE with P1 = 0x01 returns 0x9000
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
