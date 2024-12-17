import os
import logging
import pytest
from typing import Generator
from ledger_pluto.client import CharonClient, CapsuleAlgorithm
from ledger_pluto.command_sender import GPCommandSender
from ledger_pluto.applet_loader import AppletLoader
from ledger_pluto.card_manager import CardManager
from ledger_pluto.backend.jrcp_backend import JRCPBackend
from ledger_pluto.ledger_pluto import configure_nxp_sim

DEFAULT_SIM_ENC_KEY = "1111111111111111111111111111111111111111111111111111111111111111"
DEFAULT_SIM_MAC_KEY = "2222222222222222222222222222222222222222222222222222222222222222"
DEFAULT_SIM_DEK_KEY = "3333333333333333333333333333333333333333333333333333333333333333"
# Get the keys from the environment variables or use the default ones
ENC_KEY = os.environ.get("SIM_ENC_KEY") or DEFAULT_SIM_ENC_KEY
MAC_KEY = os.environ.get("SIM_MAC_KEY") or DEFAULT_SIM_MAC_KEY
DEK_KEY = os.environ.get("SIM_DEK_KEY") or DEFAULT_SIM_DEK_KEY
DEFAULT_AID = "A000000002"
# Get the applet AID from the environment variable or use the default one
AID = os.environ.get("APPLET_AID") or DEFAULT_AID
TEST_ISSUER_PRIV_KEY = (
    "fbe0ac62cef7e2b132a1e7aed49bb2fae233bf294901dfdf45ba52d5b9382978"
)
TEST_AUTH_PRIV_KEY = "7a3f314bdecdf6e7c98b0b4c0dd7e7d0c0e166be8ee7cf4c7eb991a98fbab07f"
CAP_FILE = (
    "deliverables/applet-charon/com/ledger/appletcharon/javacard/appletcharon.cap"
)
INSTALL_PARAMS = "DEADBEEF"
ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED = "Status Word: 0x6985"
SEED_LEN = 32

logger = logging.getLogger()


@pytest.fixture(scope="module", autouse=True)
def applet():
    # Load the applet
    backend = JRCPBackend()
    backend.connect()
    configure_nxp_sim(None, ENC_KEY, MAC_KEY, DEK_KEY, "", backend)
    sender = GPCommandSender(backend, ENC_KEY, MAC_KEY)
    manager = CardManager(sender)
    loader = AppletLoader(sender, manager)
    loader.install_applet(CAP_FILE, install_params=INSTALL_PARAMS)


@pytest.fixture(scope="function")
def sender(request) -> Generator[GPCommandSender, None, None]:
    backend = JRCPBackend()
    backend.connect()
    sender = GPCommandSender(backend, ENC_KEY, MAC_KEY)
    sender.send_select(AID)
    sender.open_secure_channel()

    def teardown():
        backend.disconnect()

    request.addfinalizer(teardown)
    yield sender


@pytest.fixture(scope="function")
def client(sender) -> Generator[CharonClient, None, None]:
    # Create the client object
    yield CharonClient(sender, capsule_algo=CapsuleAlgorithm.AES_CBC_HMAC)
