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
    echo "  -a, --aid AID                  Set AID for the applet (default: A000000002)"
    echo "  -c, --clean                    Clean build artifacts"
    echo "  -p, --path                     Set dependencies path (for local generation only)"
    echo "  -t, --tests GH_USER GH_TOKEN   Run functional tests (requires GitHub credentials if in docker with -d, --docker)" 
    echo "  -h, --help                     Show this help message"
    echo ""
    echo "Without any options, the script will generate the CAP file locally."
    exit 0
}

# Initialize DEPS_PATH with default value
DEPS_PATH=$HOME

# Update paths based on DEPS_PATH
update_vars() {
    OPENSSL_PATH="$DEPS_PATH/openssl"
    GP_API_PATH="$DEPS_PATH/GlobalPlatform_Card_API-org.globalplatform-v1.7.1"
    JCDK_PATH="$DEPS_PATH/java_card_devkit"
    JCSIM_PATH="$DEPS_PATH/java_card_simulator"
    JCAPI_PATH="$JCDK_PATH/lib/api_classic-3.0.5.jar"
    JCAPI_ANNOTATIONS_PATH=$JCDK_PATH"/lib/api_classic_annotations-3.0.5.jar"
    AID="A000000002"
    GP_API_URL="https://globalplatform.org/wp-content/themes/globalplatform/ajax/file-download.php?f=https://globalplatform.org/wp-content/uploads/2019/07/GlobalPlatform_Card_API-org.globalplatform-v1.7.1.zip"
    JAVA_HOME="/usr/java/jdk-17-oracle-x64"
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
        red "Error: JDK 17 not found in $JAVA_HOME"
        red "Please ensure JDK 17 is properly installed in $JAVA_HOME"
        exit 1
    fi

    # Check for JavaCard DevKit
    if [ ! -d $JCDK_PATH ]; then
        red "Error: JavaCard DevKit not found in $JCDK_PATH"
        red "Please ensure JavaCard DevKit is properly installed in $JCDK_PATH"
        exit 1
    fi

    # Check for openssl
    if [ ! -d $OPENSSL_PATH ]; then
        red "Error: OpenSSL not found in $OPENSSL_PATH"
        red "Please ensure OpenSSL is properly installed in $OPENSSL_PATH"
        exit 1
    fi

    # Check for JavaCard Simulator
    if [ ! -d $JCSIM_PATH ]; then
        red "Error: JavaCard Simulator not found in $JCSIM_PATH"
        red "Please ensure JavaCard Simulator is properly installed in $JCSIM_PATH"
        exit 1
    fi

    # Check for specific required files
    if [ ! -f $JCAPI_PATH ]; then
        red "Error: JavaCard API Classic jar not found in $JCAPI_PATH"
        red "Please ensure JavaCard DevKit is properly installed in $JCDK_PATH"
        exit 1
    fi

    # Check if GP API is already present
    if [ ! -d $GP_API_PATH ]; then
        yellow "Downloading GP API..."
        if ! curl -L -o /tmp/gp-api.zip $GP_API_URL; then
            red "Error: Failed to download GP API"
            exit 1
        fi
        
        if ! unzip /tmp/gp-api.zip -d $DEPS_PATH; then
            red "Error: Failed to extract GP API"
            rm /tmp/gp-api.zip
            exit 1
        fi
        rm /tmp/gp-api.zip
    else
        yellow "GP API already present, skipping download..."
    fi

    green "All dependencies checked successfully"
}

# Function to install dependencies
# install_dependencies()
# {
#     yellow "Installing dependencies..."
    
#     # Install JDK 17
#     if [ ! -d $JAVA_HOME ]; then
#         yellow "Downloading JDK 17..."
#         if ! curl -L -o /tmp/jdk-17.tar.gz https://download.oracle.com/java/17/latest/jdk-17_linux-x64_bin.tar.gz; then
#             red "Error: Failed to download JDK 17"
#             exit 1
#         fi
        
#         yellow "Extracting JDK 17..."
#         if ! tar -xzf /tmp/jdk-17.tar.gz -C /usr/java; then
#             red "Error: Failed to extract JDK 17"
#             rm /tmp/jdk-17.tar.gz
#             exit 1
#         fi
#         rm /tmp/jdk-17.tar.gz
#     else
#         yellow "JDK 17 already installed, skipping download..."
#     fi

#     # Install JavaCard DevKit
#     if [ ! -d $JCDK_PATH ]; then
#         yellow "Downloading JavaCard DevKit..."
#         if ! curl -L -o /tmp/jcdk.zip https://www.oracle.com/java/technologies/javacard-sdk-downloads.html; then
#             red "Error: Failed to download JavaCard DevKit"
#             exit 1
#         fi
        
#         yellow "Extracting JavaCard DevKit..."
#         if ! unzip /tmp/jcdk.zip -d $DEPS_PATH; then
#             red "Error: Failed to extract JavaCard DevKit"
#             rm /tmp/jcdk.zip
#             exit 1
#         fi
#         rm /tmp/jcdk.zip
#     else
#         yellow "JavaCard DevKit already installed, skipping download..."
#     fi

#     green "All dependencies installed successfully"
# }

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
    run_in_docker "$(declare -f check_dependencies) && $(declare -f generate_cap) && generate_cap true $USER_AID" "Build in container failed"
}

# Format from AABBCCDD to 0xAA:0xBB:0xCC:0xDD with sed
format_aid_string() {
    echo "$1" | sed 's/../0x&:/g' | sed 's/:$//'
}

# Function to build the CAP file with parameter to check if inside docker container
generate_cap() {
    local inside_docker=$1
    local user_aid=$2
    if [ "$inside_docker" = true ]; then
        DEPS_PATH=$HOME
        update_vars
    fi

    if [ -n "$user_aid" ]; then
        AID=$user_aid
    fi

    check_dependencies

    yellow "Creating bin directory if it doesn't exist..."
    mkdir -p bin

    yellow "Compiling Java sources..."
    if ! $JAVA_HOME/bin/javac -source 7 -target 7 -g \
        -cp $JCAPI_PATH \
        -cp "$JCAPI_PATH:$JCAPI_ANNOTATIONS_PATH:$GP_API_PATH/1.5/gpapi-globalplatform.jar" \
        -d bin src/com/ledger/appletcharon/*.java; then
        red "Error: Java compilation failed"
        exit 1
    fi

    yellow "Creating deliverables directory if it doesn't exist..."
    mkdir -p ./deliverables/applet-charon

    FORMATTED_AID=$(format_aid_string $AID)

    yellow "Running CAP converter..."
    if ! $JCDK_PATH/bin/converter.sh -i \
        -classdir ./bin \
        -exportpath $GP_API_PATH/1.5/exports \
        -applet $FORMATTED_AID com.ledger.appletcharon.AppletCharon \
        -out CAP JCA EXP \
        -d ./deliverables/applet-charon \
        -debug \
        -target 3.0.5 \
        com.ledger.appletcharon $FORMATTED_AID:0x00 1.0; then
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

    # yellow "Pulling docker image..."
    # if ! docker pull $DOCKER_IMAGE; then
    #     red "Error: Failed to pull docker image"
    #     red "Please ensure you are connected to the Ledger Orange VPN and logged into the orange docker registry"
    #     exit 1
    # fi
    
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
    
    export LD_LIBRARY_PATH=$OPENSSL_PATH
    export OPENSSL_MODULES=/usr/local/ssl/lib
    
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
    
    # Get the gp.jar
    yellow "Downloading gp.jar..."
    curl -L -o gp.jar https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar
    # Run pcscd if not already running
    if [ ! -e /var/run/pcscd/pcscd.comm ]; then
        yellow "Starting pcscd service..."
        sudo systemctl stop pcscd
        pcscd
    fi
    # if ! pgrep -x "pcscd" > /dev/null; then
    #     yellow "Starting pcscd service..."
    #     pcscd
    # fi
    # Run the JavaCard simulator
    if ! pgrep -x "jcsl" > /dev/null; then
        yellow "Starting JavaCard simulator..."
        $JCSIM_PATH/runtime/bin/jcsl -log_level=finest > $HOME/sim.log 2>&1 &
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
        -a|--aid)
            if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                USER_AID=$2
                shift 2
            else
                red "Error: -a|--aid requires a valid AID argument."
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
        -h|--help)
            show_help
            ;;
        *)
            red "Unknown option: $1"
            show_help
            ;;
    esac
done

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
        generate_cap false $USER_AID
    fi
fi
