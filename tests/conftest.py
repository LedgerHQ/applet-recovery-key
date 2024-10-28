import os
import logging
import pytest
from typing import Generator
from ledger_pluto.client import CharonClient, CapsuleAlgorithm
from ledger_pluto.command_sender import GPCommandSender
from ledger_pluto.ledger_pluto import validate_reader
from ledger_pluto.applet_loader import AppletLoader

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
READER = "Oracle JCSDK PCSC Reader Demo 1"
CAP_FILE = (
    "deliverables/applet-charon/com/ledger/appletcharon/javacard/appletcharon.cap"
)
INSTALL_PARAMS = "DEADBEEF"
ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED = "Status Word: 0x6985"

logger = logging.getLogger()


@pytest.fixture(scope="module", autouse=True)
def applet():
    reader_name, reader_obj = validate_reader(READER)
    # Load the applet
    loader = AppletLoader(reader_name, ENC_KEY, MAC_KEY, DEK_KEY)
    loader.reinstall_applet(CAP_FILE, install_params=INSTALL_PARAMS)


@pytest.fixture(scope="function")
def sender(request) -> Generator[GPCommandSender, None, None]:
    _, reader_obj = validate_reader(READER)
    # Create a connection to the (simulated) card
    connection = reader_obj.createConnection()
    connection.connect()
    # Create the sender object
    sender = GPCommandSender(ENC_KEY, MAC_KEY, connection)
    sender.send_select(AID)
    sender.open_scp03_secure_channel()

    def teardown():
        connection.disconnect()

    request.addfinalizer(teardown)
    yield sender


@pytest.fixture(scope="function")
def client(sender) -> Generator[CharonClient, None, None]:
    # Create the client object
    yield CharonClient(sender, capsule_algo=CapsuleAlgorithm.AES_CBC_HMAC)
