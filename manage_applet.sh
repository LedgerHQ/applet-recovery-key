#!/bin/bash

# Exit on any error
set -e

# Define color functions
red() { echo -e "\e[31m$*\e[0m"; }
green() { echo -e "\e[32m$*\e[0m"; }
yellow() { echo -e "\e[33m$*\e[0m"; }

# Function to display usage
show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -d, --docker                   Run commands in docker container"
    echo "  -a, --applet-aid AID           Override applet instance AID when generating CAP file (default: A00000001100)"
    echo "  -k, --package-aid AID          Override package AID when generating CAP file (default: A000000011AA)" 
    echo "  -v, --version VERSION          Override applet version when generating CAP file (otherwise read from src/com/ledger/appletrecoverykey/Version.java)"
    echo "  -c, --clean                    Clean build artifacts"
    echo "  -p, --path                     Set dependencies path (for local generation only)"
    echo "  -t, --tests GH_USER GH_TOKEN   Run functional tests (requires GitHub credentials if in docker with -d, --docker)" 
    echo "  -o, --output-dir DIR           Set output directory for generated CAP file (default: ./deliverables/applet-recovery-key)"
    echo "  -n, --no-deps                  Do not automatically download missing dependencies"
    echo "  -h, --help                     Show this help message"
    echo ""
    echo "Without any options, the script will generate the CAP file locally with default AID and version."
    exit 0
}

# Initialize DEPS_PATH with default value
DEPS_PATH=$HOME
NO_DEPS=false

# Update paths based on DEPS_PATH
update_vars() {
    GP_API_PATH="./deps"
    UPGRADE_API_PATH="./deps"
    JCDK_PATH="$DEPS_PATH/java_card_devkit"
    JCSIM_PATH="$DEPS_PATH/jcop_simulator"
    JCAPI_PATH="$JCDK_PATH/lib/api_classic-3.0.5.jar"
    JCAPI_ANNOTATIONS_PATH=$JCDK_PATH"/lib/api_classic_annotations-3.0.5.jar"
    APPLET_AID="A0000000624C45444745523031" # == module AID
    PACKAGE_AID="A0000000624C4544474552303100"
    GP_API_URL="https://globalplatform.org/wp-content/themes/globalplatform/ajax/file-download.php?f=https://globalplatform.org/wp-content/uploads/2019/07/GlobalPlatform_Card_API-org.globalplatform-v1.7.1.zip"
    JAVA_HOME="/usr/java/jdk-17-oracle-x64"
    OUTPUT_DIR="./deliverables/applet-recovery-key"
}

export JAVA_HOME
update_vars

DOCKER_IMAGE="containers.git.orange.ledgerlabs.net/embedded-software/applet-builder:latest"
# DOCKER_IMAGE=alexisgrojean/applet-builder:latest
CONTAINER_NAME="applet-builder"

# Function to clean build artifacts
clean() {
    yellow "Cleaning build artifacts..."
    
    # Remove bin directory
    if [ -d "./bin" ]; then
        rm -rf ./bin
        green "Removed bin directory"
    fi
    
    # Remove deliverables directory
    if [ -d "./deliverables" ]; then
        rm -rf ./deliverables
        green "Removed deliverables directory"
    fi
    
    # Remove any .class files in case they're scattered
    find . -name "*.class" -type f -delete
    
    green "Clean completed successfully"
    exit 0
}

# Helper function to run commands in docker
run_in_docker() {
    local command=$1
    local error_message=${2:-"Docker command failed"}
    if ! docker run --rm --name $CONTAINER_NAME \
        --user $(id -u):$(id -g) \
        --privileged \
        -v "${PWD}:/applet" \
        $DOCKER_IMAGE \
        bash -c "cd /applet && $(declare -f red) && $(declare -f green) && $(declare -f yellow) && $(declare -f update_vars) && $(declare -f format_aid_string) && $command"; then
        red "Error: $error_message"
        exit 1
    fi
}

# Function to check required dependencies
check_dependencies() {
    yellow "Checking dependencies..."
    
    # Check for JDK 17
    if [ ! -d $JAVA_HOME ]; then
        if [ $NO_DEPS = true ]; then
            red "Error: JDK 17 not found in $JAVA_HOME"
            red "Please ensure JDK 17 is properly installed in $JAVA_HOME"
            exit 1
        fi
        yellow "Downloading JDK 17..."
        if ! curl -L -o /tmp/jdk-17_linux-x64_bin.deb https://download.oracle.com/java/17/archive/jdk-17.0.12_linux-x64_bin.deb; then
            red "Error: Failed to download JDK 17"
            exit 1
        fi
        if ! sudo apt-get install --reinstall -y /tmp/jdk-17_linux-x64_bin.deb; then
            red "Error: Failed to install JDK 17"
            rm /tmp/jdk-17_linux-x64_bin.deb
            exit 1
        fi
        rm /tmp/jdk-17_linux-x64_bin.deb
    else
        green "JDK 17 found in $JAVA_HOME ✅"
    fi

    # Check for JavaCard DevKit
    if [ ! -d $JCDK_PATH ]; then
        if [ $NO_DEPS = true ]; then
            red "Error: JavaCard DevKit not found in $JCDK_PATH"
            red "Please ensure JavaCard DevKit is properly installed in $JCDK_PATH"
            exit 1
        fi
        yellow "Downloading JavaCard DevKit..."
        if ! curl -L -b oraclelicense=accept-securebackup-cookie -o /tmp/java_card_devkit.zip https://download.oracle.com/otn-pub/java/java_card_kit/3.2/java_card_devkit_tools-bin-v24.0-b_57-20-FEB-2024.zip; then
            red "Error: Failed to download JavaCard DevKit"
            exit 1
        fi
        if ! unzip /tmp/java_card_devkit.zip -d $DEPS_PATH; then
            red "Error: Failed to extract JavaCard DevKit"
            rm /tmp/java_card_devkit.zip
            exit 1
        fi
        rm /tmp/java_card_devkit.zip
    else
        green "JavaCard DevKit found in $JCDK_PATH ✅"
    fi

    # Check for specific required files
    if [ ! -f $JCAPI_PATH ]; then
        red "Error: JavaCard API Classic jar not found in $JCAPI_PATH"
        red "Please ensure JavaCard DevKit is properly installed in $JCDK_PATH"
        exit 1
    else
        green "JavaCard API Classic jar found in $JCAPI_PATH ✅"
    fi

    green "All dependencies checked successfully ✅"
}

# Function to handle docker operations
setup_docker_and_generate_cap() {
    yellow "Checking docker installation..."
    if ! command -v docker &> /dev/null; then
        red "Error: docker is not installed"
        exit 1
    fi

    yellow "Checking if container already exists..."
    if docker ps -a | grep -q "applet-builder"; then
        yellow "Removing existing applet-builder container..."
        if ! docker rm -f applet-builder; then
            red "Error: Failed to remove existing container"
            exit 1
        fi
    fi

    yellow "Pulling docker image..."
    if ! docker pull $DOCKER_IMAGE; then
        red "Error: Failed to pull docker image"
        red "Please ensure you are connected to the Ledger Orange VPN and logged into the orange docker registry"
        exit 1
    fi
    
    yellow "Generate cap in container..."
    run_in_docker "$(declare -f check_dependencies) && $(declare -f generate_cap) && generate_cap true $USER_APPLET_AID $USER_PACKAGE_AID $USER_VERSION $USER_OUTPUT_DIR" "Build in container failed"
}

# Format from AABBCCDD to 0xAA:0xBB:0xCC:0xDD with sed
format_aid_string() {
    echo "$1" | sed 's/../0x&:/g' | sed 's/:$//'
}

# Function to build the CAP file with parameter to check if inside docker container
generate_cap() {
    # Make sure we have proper number of arguments
    if [ "$#" -ne 5 ]; then
        red "Error: Function generate_cap requires 5 arguments but got $#"
        red "Usage: generate_cap <inside_docker> <applet_aid> <package_aid> <version> <output_dir>"
        exit 1
    fi

    local INSIDE_DOCKER=$1
    local APPLET_AID=$2
    local PACKAGE_AID=$3
    local VERSION=$4
    local OUTPUT_DIR=$5

    if [ "$INSIDE_DOCKER" = true ]; then
        DEPS_PATH=$HOME
        update_vars
    fi

    green "Using applet (module) AID: $APPLET_AID"
    green "Using package AID: $PACKAGE_AID"
    green "Using version: $VERSION"
    green "Using output directory: $OUTPUT_DIR"

    check_dependencies

    yellow "Creating bin directory if it doesn't exist..."
    mkdir -p bin

    yellow "Compiling Java sources..."
    if ! $JAVA_HOME/bin/javac -source 7 -target 7 -g \
        -bootclasspath $JCAPI_PATH \
        -Xlint:-options \
        -cp $JCAPI_PATH \
        -cp "$JCAPI_PATH:$JCAPI_ANNOTATIONS_PATH:$GP_API_PATH/gpapi-globalplatform.jar:$UPGRADE_API_PATH/gpapi-upgrade.jar" \
        -d bin src/com/ledger/appletrecoverykey/*.java; then
        red "Error: Java compilation failed"
        exit 1
    fi

    yellow "Creating deliverables directory if it doesn't exist..."
    mkdir -p $OUTPUT_DIR

    FORMATTED_APPLET_AID=$(format_aid_string $APPLET_AID)
    FORMATTED_PACKAGE_AID=$(format_aid_string $PACKAGE_AID)

    yellow "Running CAP converter..."
    if ! $JCDK_PATH/bin/converter.sh -i \
        -classdir ./bin \
        -exportpath $UPGRADE_API_PATH/exports23 \
        -applet $FORMATTED_APPLET_AID com.ledger.appletrecoverykey.AppletRecoveryKey \
        -out CAP JCA EXP \
        -d $OUTPUT_DIR \
        -debug \
        -target 3.0.5 \
        com.ledger.appletrecoverykey $FORMATTED_PACKAGE_AID $VERSION; then
        red "Error: CAP conversion failed"
        exit 1
    fi

    green "CAP file generated successfully"
}

setup_docker_and_run_tests()
{
    yellow "Checking docker installation..."
    if ! command -v docker &> /dev/null; then
        red "Error: docker is not installed"
        exit 1
    fi

    yellow "Checking if container already exists..."
    if docker ps -a | grep -q "applet-builder"; then
        yellow "Removing existing applet-builder container..."
        if ! docker rm -f applet-builder; then
            red "Error: Failed to remove existing container"
            exit 1
        fi
    fi

    yellow "Pulling docker image..."
    if ! docker pull $DOCKER_IMAGE; then
        red "Error: Failed to pull docker image"
        red "Please ensure you are connected to the Ledger Orange VPN and logged into the orange docker registry"
        exit 1
    fi
    
    yellow "Run tests in container..."
    run_in_docker "$(declare -f check_dependencies) && $(declare -f run_tests) && run_tests true $GH_USER $GH_TOKEN" "Run tests in container failed"
}


run_tests()
{
    local inside_docker=$1
    local gh_user=$2
    local gh_token=$3
    if [ "$inside_docker" = true ]; then
        DEPS_PATH=$HOME
        export PATH=/home/devuser/.local/bin:$PATH
        update_vars
        if [ -n "$gh_user" ] && [ -n "$gh_token" ]; then
            export GH_USER=$gh_user
            export GH_TOKEN=$gh_token
        else
            red "Error: GitHub credentials not provided"
            exit 1
        fi
    fi
    
    check_dependencies

    # Install PDM
    yellow "Installing PDM..."
    curl -sSL https://pdm-project.org/install-pdm.py | python3 -
    # Install dependencies
    yellow "Installing dependencies..."
    
    if [ $inside_docker = true ]; then
        pdm lock -G github-actions
        pdm install -G github-actions
    else
        pdm lock -G local
        pdm install -G local
    fi

    # Check for NXP JCOP simulator
    if [ ! -d $JCSIM_PATH ]; then
        red "Error: NXP JCOP Simulator not found in $JCSIM_PATH"
        red "Please ensure NXP JCOP Simulator is properly installed in $JCSIM_PATH"
        exit 1
    fi

    # Run the NXP JCOP simulator
    if ! pgrep -x "jcop" > /dev/null; then
        yellow "Starting NXP JCOP simulator..."
        $JCSIM_PATH/linux/jcop > $HOME/sim.log 2>&1 &
    fi
    # Activate the virtual environment and run the tests
    yellow "Running tests..."
    source .venv/bin/activate
    pdm run pytest
}

# Parse command line arguments
DOCKER=false
TESTS=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--clean)
            clean
            ;;
        -d|--docker)
            DOCKER=true
            shift
            ;;
        -t|--tests)
            TESTS=true
            if [ "$DOCKER" = true ]; then
                if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                    GH_USER=$2
                    if [ -n "$3" ] && [ ${3:0:1} != "-" ]; then
                        GH_TOKEN=$3
                        shift 3
                    else
                        red "Error: -t|--tests requires a valid GitHub password argument."
                        exit 1
                    fi
                else
                    red "Error: -t|--tests requires a valid GitHub username argument."
                    exit 1
                fi
            else
                # In non-dockerized mode, we don't need to parse the username and token
                shift 1
            fi
            ;;
        -a|--applet-aid)
            if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                USER_APPLET_AID=$2
                shift 2
            else
                red "Error: -a|--applet-aid requires a valid AID argument."
                exit 1
            fi
            ;;
        -k|--package-aid)
            if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                USER_PACKAGE_AID=$2
                shift 2
            else
                red "Error: -k|--package-aid requires a valid AID argument."
                exit 1
            fi
            ;;
        -v|--version)
            if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                USER_VERSION=$2
                shift 2
            else
                red "Error: -v|--version requires a valid VERSION argument."
                exit 1
            fi
            ;;
        -p|--path)
            if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                DEPS_PATH=$2
                update_vars
                shift 2
            else
                red "Error: -p|--path requires a valid path argument."
                exit 1
            fi
            ;;
        -o|--output-dir)
            if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                USER_OUTPUT_DIR=$2
                shift 2
            else
                red "Error: -o|--output-dir requires a valid directory argument."
                exit 1
            fi
            ;;
        -n|--no-deps)
            NO_DEPS=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            red "Unknown option: $1"
            show_help
            ;;
    esac
done

if [ ! -n "$USER_APPLET_AID" ]; then
    USER_APPLET_AID=$APPLET_AID
fi

if [ ! -n "$USER_PACKAGE_AID" ]; then
    USER_PACKAGE_AID=$PACKAGE_AID
fi

if [ ! -n "$USER_OUTPUT_DIR" ]; then
    USER_OUTPUT_DIR=$OUTPUT_DIR
fi

if [ ! -n "$USER_VERSION" ]; then
    get_version # Sets USER_VERSION
fi

# Execute requested operations
if [ "$DOCKER" = true ]; then
    if [ "$TESTS" = true ]; then
        setup_docker_and_run_tests
    else
        setup_docker_and_generate_cap
    fi
else
    if [ "$TESTS" = true ]; then
        run_tests false
    else
        generate_cap false $USER_APPLET_AID $USER_PACKAGE_AID $USER_VERSION $USER_OUTPUT_DIR
    fi
fi
