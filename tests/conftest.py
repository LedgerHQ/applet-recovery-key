import os
import logging
import pytest
import functools
from io import StringIO
from typing import Generator, Tuple
from ledger_pluto.client import RecoveryKeyClient, CapsuleAlgorithm
from ledger_pluto.command_sender import GPCommandSender
from ledger_pluto.applet_loader import AppletLoader
from ledger_pluto.card_manager import CardManager
from ledger_pluto.backend.jrcp_backend import JRCPBackend
from ledger_pluto.ledger_pluto import configure_nxp_sim
from binascii import unhexlify


DEFAULT_SIM_ENC_KEY = "1111111111111111111111111111111111111111111111111111111111111111"
DEFAULT_SIM_MAC_KEY = "2222222222222222222222222222222222222222222222222222222222222222"
DEFAULT_SIM_DEK_KEY = "3333333333333333333333333333333333333333333333333333333333333333"
# Get the keys from the environment variables or use the default ones
ENC_KEY = os.environ.get("SIM_ENC_KEY") or DEFAULT_SIM_ENC_KEY
MAC_KEY = os.environ.get("SIM_MAC_KEY") or DEFAULT_SIM_MAC_KEY
DEK_KEY = os.environ.get("SIM_DEK_KEY") or DEFAULT_SIM_DEK_KEY
DEFAULT_AID = "A0000000624C4544474552303102"
# Get the applet AID from the environment variable or use the default one
AID = os.environ.get("APPLET_AID") or DEFAULT_AID
TEST_ISSUER_PRIV_KEY = (
    "fbe0ac62cef7e2b132a1e7aed49bb2fae233bf294901dfdf45ba52d5b9382978"
)
TEST_AUTH_PRIV_KEY = "7a3f314bdecdf6e7c98b0b4c0dd7e7d0c0e166be8ee7cf4c7eb991a98fbab07f"
CAP_FILE = "deliverables/applet-recovery-key/com/ledger/appletrecoverykey/javacard/appletrecoverykey.cap"
CAP_FILE_UPGRADE = "upgrade/com/ledger/appletrecoverykey/javacard/appletrecoverykey.cap"
INSTALL_PARAMS = "DEADBEEF"
ASSERT_MSG_CONDITION_OF_USE_NOT_SATISFIED = "Status Word: 0x6985"
SEED_LEN = 32
TEST_SEED = unhexlify(
    "1989299da88b55c0f8b99649cb8d317384010000184170416ca77e8d75bd1841"
)


class StatusWords:
    WRONG_P1_P2 = 0x6A86
    WRONG_LENGTH = 0x6700
    DATA_NOT_FOUND = 0x6A88
    MISSING_SCP_LEDGER = 0x6887
    INCORRECT_SCP_LEDGER = 0x6888
    SECURITY_STATUS_NOT_SATISFIED = 0x6982
    WRONG_PARAMETERS = 0x6A80


TEST_CATEGORIES = [
    (
        "state_machine",
        [
            "fabrication",
            "pending_tests",
            "attested1",
            "attested2",
            "perso_pin_lock",
            "perso_auth",
            "perso_pin_unlock",
        ],
    ),
    ("secure_channels", [""]),
    (
        "commands",
        [
            "get_status",
            "get_data",
            "get_public_key",
            "set_certificate",
            "set_status",
            "get_certificate",
            "validate_certificate",
            "set_pin",
            "change_pin",
            "verify_pin",
            "request_upgrade",
        ],
    ),
    ("generic", [""]),
    ("platform", [""]),
]
TEST_CATEGORY_DESCRIPTIONS = {
    (
        "state_machine",
        "fabrication",
    ): (
        "Fabrication",
        "Tests that verify the behavior of the applet in Fabrication persistent state",
    ),
    (
        "state_machine",
        "pending_tests",
    ): (
        "Pending Factory Tests",
        "Tests that verify the behavior of the applet in Pending Tests persistent state",
    ),
    (
        "state_machine",
        "attested1",
    ): (
        "Attested - No Authentication",
        "Tests that verify the behavior of the applet in Attested persistent state without authentication (without opening a Ledger secure channel)",
    ),
    (
        "state_machine",
        "attested2",
    ): (
        "Attested - Authenticated",
        "Tests that verify the behavior of the applet in Attested persistent state with authentication (after opening a Ledger secure channel)",
    ),
    (
        "state_machine",
        "perso_pin_lock",
    ): (
        "User Personalized - Pin Locked",
        "Tests that verify the behavior of the applet in User Personalized persistent state before authentication",
    ),
    (
        "state_machine",
        "perso_auth",
    ): (
        "User Personalized - Authenticated",
        "Tests that verify the behavior of the applet in User Personalized persistent state after authentication and before PIN verification",
    ),
    (
        "state_machine",
        "perso_pin_unlock",
    ): (
        "User Personalized - Pin Unlocked",
        "Tests that verify the behavior of the applet in User Personalized persistent state after authentication and after PIN verification",
    ),
    (
        "commands",
        "get_status",
    ): (
        "GET STATUS Command",
        "Tests that verify the behavior of the GET STATUS command",
    ),
    (
        "commands",
        "get_data",
    ): (
        "GET DATA Command",
        "Tests that verify the behavior of the GET DATA command",
    ),
    (
        "commands",
        "get_public_key",
    ): (
        "GET PUBLIC KEY Command",
        "Tests that verify the behavior of the GET PUBLIC KEY command",
    ),
    (
        "commands",
        "set_certificate",
    ): (
        "SET CERTIFICATE Command",
        "Tests that verify the behavior of the SET CERTIFICATE command",
    ),
    (
        "commands",
        "get_certificate",
    ): (
        "GET CERTIFICATE Command",
        "Tests that verify the behavior of the GET CERTIFICATE command",
    ),
    (
        "commands",
        "validate_certificate",
    ): (
        "VALIDATE CERTIFICATE Command",
        "Tests that verify the behavior of the VALIDATE CERTIFICATE command",
    ),
    (
        "commands",
        "set_pin",
    ): (
        "SET PIN Command",
        "Tests that verify the behavior of the SET PIN command",
    ),
    (
        "commands",
        "change_pin",
    ): (
        "CHANGE PIN Command",
        "Tests that verify the behavior of the CHANGE PIN command",
    ),
    (
        "commands",
        "verify_pin",
    ): (
        "VERIFY PIN Command",
        "Tests that verify the behavior of the VERIFY PIN command",
    ),
    (
        "commands",
        "set_status",
    ): (
        "SET STATUS Command",
        "Tests that verify the behavior of the SET STATUS command",
    ),
    (
        "commands",
        "request_upgrade",
    ): (
        "REQUEST UPGRADE Command",
        "Tests that verify the behavior of the REQUEST UPGRADE command",
    ),
}
TEST_DOC_URL = "https://ledgerhq.atlassian.net/wiki/spaces/FW/pages/5027168270/Charon+-+Tech+-+Test+Plan+-+Applet#Charon---{category}"


def assert_sw(sw1, sw2, expected_sw):
    sw = (sw1 << 8) + sw2
    assert sw == expected_sw


@pytest.fixture(scope="module", autouse=True)
def applet():
    # Load the applet
    backend = JRCPBackend()
    backend.connect()
    configure_nxp_sim(None, ENC_KEY, MAC_KEY, DEK_KEY, "", backend)
    sender = GPCommandSender(backend, ENC_KEY, MAC_KEY)
    manager = CardManager(sender)
    loader = AppletLoader(sender, manager)
    sender.send_select()
    sender.open_secure_channel(plain=True)
    loader.install_applet(CAP_FILE)
    loader.store_serial_number(unhexlify(AID), serial_number=unhexlify(INSTALL_PARAMS))


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
def client(sender) -> Generator[RecoveryKeyClient, None, None]:
    # Create the client object
    yield RecoveryKeyClient(sender, capsule_algo=CapsuleAlgorithm.AES_CBC_HMAC)


@pytest.fixture(scope="function")
def loader(sender) -> Generator[AppletLoader, None, None]:
    loader = AppletLoader(
        sender,
        CardManager(sender),
    )
    yield loader


def get_test_spec_name(item):
    """
    Extract the test specification name from the marker
    """
    # Check for test_spec marker
    spec_marker = item.get_closest_marker("test_spec")
    if spec_marker and spec_marker.args:
        return spec_marker.args[0]

    # Fallback to function name
    return item.name


def get_test_description(item):
    """
    Extract the description from the marker
    """
    # Check for description marker
    desc_marker = item.get_closest_marker("description")
    if desc_marker and desc_marker.args:
        return desc_marker.args[0]

    # Fallback to empty string
    return ""


class LogCapture:
    """Capture log messages during test execution"""

    def __init__(self):
        self.log_capture = StringIO()
        self.handler = logging.StreamHandler(self.log_capture)

    def __enter__(self):
        logging.getLogger().addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.getLogger().removeHandler(self.handler)

    def get_logs(self):
        return self.log_capture.getvalue()


@pytest.fixture(autouse=True)
def log_capture():
    """Fixture to capture logs for each test"""
    with LogCapture() as capture:
        yield capture


def get_test_category_and_subcategory(item) -> Tuple[str, str, str, str]:
    """
    Extract category, subcategory, and description from markers
    Returns: (category, subcategory, description)
    """
    for category, subcategories in TEST_CATEGORIES:
        marker = item.get_closest_marker(category)
        if marker:
            subcategory = marker.args[0] if marker.args else ""
            if subcategory in subcategories:
                title, desc = TEST_CATEGORY_DESCRIPTIONS[(category, subcategory)]
                return category, subcategory, desc, title
    return "uncategorized", "", "", ""


def pytest_configure(config):
    """
    Initialize the GitHub Step Summary file and test tracking
    """
    config.github_step_summary_file = os.environ.get(
        "GITHUB_STEP_SUMMARY", "test_summary.md"
    )
    open(config.github_step_summary_file, "w").close()

    config.addinivalue_line(
        "markers", "test_spec(name): mark test with a specification name"
    )
    config.addinivalue_line(
        "markers", "description(text): mark test with a description of what it does"
    )

    for category, _ in TEST_CATEGORIES:
        config.addinivalue_line(
            "markers",
            f"{category}(subcategory): mark test with category and subcategory",
        )

    # Initialize tables dict with category-subcategory pairs
    config.subcategory_tables = {}
    config.subcategory_descriptions = {}
    config.subcategory_titles = {}


def create_details_cell(content: str) -> str:
    """
    Create a properly formatted details cell for markdown tables.
    Ensures proper escaping and formatting of the content.
    """
    if not content or content == "-":
        return "-"

    # Escape any pipe characters in the content
    content = content.replace("|", "\\|")

    # Replace newlines with <br> tags to keep content in one line
    content = content.replace("\n", "<br>")

    return f"<details><summary>Details</summary><pre>{content}</pre></details>"


def pytest_runtest_makereport(item, call):
    """
    Generate a summary for each test case in markdown tables by subcategory
    """
    summary_file = item.config.github_step_summary_file
    if summary_file and call.when == "call":
        test_spec_name = get_test_spec_name(item)
        category, subcategory, category_description, subcategory_title = (
            get_test_category_and_subcategory(item)
        )
        description = get_test_description(item)

        # Get the captured logs
        log_capture = item.funcargs.get("log_capture")
        logs = log_capture.get_logs() if log_capture else ""
        # Remove lines which contain`JRCP command:` from logs
        exclude_patterns = ["JRCP command:", "JRCP response"]
        logs = "\n".join(
            line
            for line in logs.splitlines()
            if not any(p in line for p in exclude_patterns)
        )

        if call.excinfo:
            status = "❌ Failed"
            duration = f"{call.stop - call.start:.2f}s"
            details = f"Error:\n{str(call.excinfo.value)}\n\nLogs:\n{logs}"
        else:
            status = "✅ Passed"
            duration = f"{call.stop - call.start:.2f}s"
            details = logs if logs.strip() else "-"

        # Use category-subcategory pair as key
        subcategory_key = f"{category}:{subcategory}" if subcategory else category

        if subcategory_key not in item.config.subcategory_tables:
            item.config.subcategory_tables[subcategory_key] = []
            item.config.subcategory_descriptions[subcategory_key] = category_description
            item.config.subcategory_titles[subcategory_key] = subcategory_title

        # Only show details dropdown if there's content
        details_cell = create_details_cell(details)

        test_row = f"| {test_spec_name} | {item.name} | {status} | {duration} | {description} | {details_cell} |"
        item.config.subcategory_tables[subcategory_key].append(test_row)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """
    Write out the subcategory tables and generate overall summary
    """
    summary_file = config.github_step_summary_file
    if summary_file and hasattr(config, "subcategory_tables"):
        with open(summary_file, "w") as f:
            # Group subcategories by their parent category
            category_groups = {}
            for subcategory_key in config.subcategory_tables:
                category = subcategory_key.split(":")[0]
                if category not in category_groups:
                    category_groups[category] = []
                category_groups[category].append(subcategory_key)

            # Write tables grouped by category
            for category, subcategory_keys in category_groups.items():
                # Write category header with URL
                category_title = category.replace("_", " ").title()
                doc_url = TEST_DOC_URL.format(
                    category=category.replace("_", "-").title()
                )
                f.write(f"## [{category_title}]({doc_url})\n\n")

                # Write tables for each subcategory under this category
                for subcategory_key in sorted(subcategory_keys):
                    rows = config.subcategory_tables[subcategory_key]
                    description = config.subcategory_descriptions[subcategory_key]
                    subcategory_title = config.subcategory_titles[subcategory_key]

                    f.write(f"### {subcategory_title} Tests\n")
                    if description:
                        f.write(f"{description}\n")

                    f.write(
                        "| Test Specification | Function Name | Status | Duration | Description | Logs |\n"
                    )
                    f.write(
                        "|-------------------|--------------|--------|----------|-------------|----------|\n"
                    )

                    for row in rows:
                        f.write(f"{row}\n")

                    f.write("\n")

            # Write summary statistics
            stats = terminalreporter.stats
            total_tests = (
                stats.get("passed", [])
                + stats.get("failed", [])
                + stats.get("skipped", [])
                + stats.get("error", [])
            )
            passed_tests = stats.get("passed", [])
            failed_tests = stats.get("failed", []) + stats.get("error", [])
            skipped_tests = stats.get("skipped", [])

            f.write("## Test Run Summary\n")
            f.write(f"**Total Tests:** {len(total_tests)}\n")
            f.write(f"**Passed:** {len(passed_tests)} ✅\n")
            f.write(f"**Failed:** {len(failed_tests)} ❌\n")
            f.write(f"**Skipped:** {len(skipped_tests)} ⏩\n")
