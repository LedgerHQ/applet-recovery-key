import logging
import os
import pytest
from ledgerblue.ecWrapper import PrivateKey
from binascii import unhexlify
from ledger_pluto.client import CLA, InsType, P1, P2
from .conftest import (
    TEST_AUTH_PRIV_KEY,
    TEST_ISSUER_PRIV_KEY,
    ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED,
    SEED_LEN,
    AID
)

logger = logging.getLogger(__name__)


def check_applet_state(client):
    infos = client.get_status()
    assert infos.fsm_state == "Fabrication"
    assert infos.transient_fsm_state == "Idle"


def configure_client_and_check_state(client):
    client.set_issuer_key(AID, bytearray.fromhex(TEST_ISSUER_PRIV_KEY))
    check_applet_state(client)
    client.get_public_key_and_verify()


@pytest.mark.description("'GET STATUS' is supported and should return 0x9000")
@pytest.mark.order(1)
@pytest.mark.test_spec("CHA_STATE_FAB_OK_01")
@pytest.mark.state_machine("fabrication")
def test_fsm_fab_get_status(client):
    # This function calls client.get_status() which verifies that GET STATUS returns 0x9000
    check_applet_state(client)


@pytest.mark.description("'GET DATA' is supported and should return 0x9000")
@pytest.mark.skip("TODO: implement GET DATA command in applet first")
@pytest.mark.test_spec("CHA_STATE_FAB_OK_02")
@pytest.mark.state_machine("fabrication")
def test_fsm_fab_get_data(client):
    check_applet_state(client)


@pytest.mark.description("'GET PUBLIC KEY' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_FAB_OK_03")
@pytest.mark.state_machine("fabrication")
def test_fsm_fab_get_pub_key(client):
    # This function calls client.get_public_key_and_verify() which verifies that GET PUBLIC KEY returns 0x9000
    configure_client_and_check_state(client)


@pytest.mark.description("Unauthorized commands should be rejected with 0x6985")
@pytest.mark.test_spec("CHA_STATE_FAB_FAIL_01")
@pytest.mark.state_machine("fabrication")
def test_fsm_fab_unauthorized_cmds(client):
    # Dummy ephemeral keys (we don't care about the actual values, it's just so the client
    # can send the commands we want to test)
    dummy_priv_key = PrivateKey()
    dummy_pub_key = dummy_priv_key.pubkey.serialize(compressed=False)
    dummy_seed = os.urandom(SEED_LEN)

    configure_client_and_check_state(client)

    with pytest.raises(AssertionError) as e:
        client.get_card_static_certificate_and_verify()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        client.get_card_ephemeral_certificate_and_verify()
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    with pytest.raises(AssertionError) as e:
        hw_static_certificate, _ = client.generate_hw_static_certificate(
            bytes([0x01, 0x02, 0x03, 0x04]),
            dummy_pub_key,
            unhexlify(dummy_priv_key.serialize()),
        )
        client.sender.build_and_send_apdu(
            cla=CLA,
            ins=InsType.VALIDATE_HOST_CERTIFICATE,
            p1=P1.VALIDATE_CERTIFICATE_P1_STATIC,
            p2=P2.P2_DEFAULT,
            data=unhexlify(hw_static_certificate),
        )
    assert str(e.value) == ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED

    client.host_challenge = os.urandom(8)
    client.card_challenge = os.urandom(8)
    client.capsule.set_hw_ephemeral_private_key(dummy_priv_key)
    client.capsule.set_card_ephemeral_public_key(dummy_pub_key)
    client.capsule.generate_session_keys()

    with pytest.raises(AssertionError) as e:
        hw_ephemeral_certificate, _ = client.generate_hw_ephemeral_certificate(
            client.host_challenge, client.card_challenge, dummy_pub_key
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

    # TODO: implement this command in the applet
    # with pytest.raises(AssertionError) as e:
    #     client.verify_seed(dummy_seed)

    # TODO: implement this command in the applet
    # with pytest.raises(AssertionError) as e:
    # client.set_data()

    # TODO: implement this command in the client
    # with pytest.raises(AssertionError) as e:
    # client.factory_reset()


@pytest.mark.description("'SET CERTIFICATE' is supported and should return 0x9000")
@pytest.mark.test_spec("CHA_STATE_FAB_OK_04")
@pytest.mark.state_machine("fabrication")
def test_fsm_fab_set_certificate(client):
    configure_client_and_check_state(client)

    auth_key = bytearray.fromhex(TEST_AUTH_PRIV_KEY)
    check_applet_state(client)
    client.set_certificate(auth_key)
