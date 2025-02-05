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
    echo "  -a, --aid AID                  Set AID for the applet when generating CAP file (default: A000000002)"
    echo "  -v, --version VERSION          Set applet version when generating CAP file (default: 1.0)"
    echo "  -c, --clean                    Clean build artifacts"
    echo "  -p, --path                     Set dependencies path (for local generation only)"
    echo "  -t, --tests GH_USER GH_TOKEN   Run functional tests (requires GitHub credentials if in docker with -d, --docker)" 
    echo "  -h, --help                     Show this help message"
    echo ""
    echo "Without any options, the script will generate the CAP file locally with default AID and version."
    exit 0
}

# Initialize DEPS_PATH with default value
DEPS_PATH=$HOME

# Update paths based on DEPS_PATH
update_vars() {
    OPENSSL_PATH="$DEPS_PATH/openssl"
    GP_API_PATH="$DEPS_PATH/GlobalPlatform_Card_API-org.globalplatform-v1.7.1"
    UPGRADE_API_PATH="./deps"
    JCDK_PATH="$DEPS_PATH/java_card_devkit"
    JCSIM_PATH="$DEPS_PATH/jcop_simulator"
    JCAPI_PATH="$JCDK_PATH/lib/api_classic-3.0.5.jar"
    JCAPI_ANNOTATIONS_PATH=$JCDK_PATH"/lib/api_classic_annotations-3.0.5.jar"
    AID="A000000002"
    VERSION="1.0"
    JAVA_HOME="/usr/java/jdk-17-oracle-x64"
}

export JAVA_HOME
update_vars

DOCKER_IMAGE="containers.git.orange.ledgerlabs.net/embedded-software/applet-builder:latest"
# DOCKER_IMAGE=alexisgrojean/applet-builder:latest
CONTAINER_NAME="applet-builder"
# Dependencies URLs for automated download
JDK_17_URL="https://download.oracle.com/java/17/archive/jdk-17.0.12_linux-x64_bin.deb"
JCDK_URL="https://download.oracle.com/otn-pub/java/java_card_kit/3.2/java_card_devkit_tools-bin-v24.0-b_57-20-FEB-2024.zip"
OPENSSL_URL="https://github.com/openssl/openssl.git"
GP_API_URL="https://globalplatform.org/wp-content/themes/globalplatform/ajax/file-download.php?f=https://globalplatform.org/wp-content/uploads/2019/07/GlobalPlatform_Card_API-org.globalplatform-v1.7.1.zip"
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
        message="JDK 17 not found in $JAVA_HOME"
        if [ $INSTALL_DEPS = true ]; then
            yellow $message
            yellow "Downloading and installing JDK 17 to $JAVA_HOME..."
            if [ ! -f /tmp/jdk-17_linux-x64_bin.deb ]; then
                sudo curl -o /tmp/jdk-17_linux-x64_bin.deb $JDK_17_URL
            fi
            # Check if script is running as root
            if [ "$EUID" -ne 0 ]; then
                red "Error: Script must be run as root to install missing JDK 17"
                exit 1
            fi

            apt-get install -y /tmp/jdk-17_linux-x64_bin.deb
            rm /tmp/jdk-17_linux-x64_bin.deb
            green "JDK 17 installed successfully"
        else
            red $message
            red "Please ensure JDK 17 is properly installed in $JAVA_HOME"
            exit 1
        fi
    fi

    # Check for JavaCard DevKit
    if [ ! -d $JCDK_PATH ]; then
        message="JavaCard DevKit not found in $JCDK_PATH"
        if [ $INSTALL_DEPS = true ]; then
            yellow $message
            yellow "Downloading and installing JavaCard DevKit to $JCDK_PATH..."
            curl -L -b oraclelicense=accept-securebackup-cookie -o /tmp/java_card_devkit.zip $JCDK_URL
            unzip /tmp/java_card_devkit.zip -d $JCDK_PATH
            rm /tmp/java_card_devkit.zip
            green "JavaCard DevKit installed successfully"
        else
            red $message
            red "Please ensure JavaCard DevKit is properly installed in $JCDK_PATH"
            exit 1
        fi
    fi

    # Check for openssl
    if [ ! -d $OPENSSL_PATH ]; then
        message="OpenSSL not found in $OPENSSL_PATH"
        if [ $INSTALL_DEPS = true ]; then
            yellow $message
            yellow "Installing dependencies for OpenSSL..." 
            apt install -y \
                build-essential \ 
                checkinstall \
                zlib1g-dev \
                gcc-multilib \
                g++-multilib 
            yellow "Downloading and installing OpenSSL to $OPENSSL_PATH..."
            git clone $OPENSSL_URL $OPENSSL_PATH \
            && cd $OPENSSL_PATH \
            && git checkout openssl-3.0.12 \
            && perl ./Configure linux-x86 no-asm no-threads enable-weak-ssl-ciphers --prefix=/usr/local/ssl --openssldir=/usr/local/ssl \
            && make \
            && make install
            cd -
            green "OpenSSL installed successfully"
        else
            red $message
            red "Please ensure OpenSSL is properly installed in $OPENSSL_PATH"
            exit 1
        fi
    fi

    # Check for specific required files
    if [ ! -f $JCAPI_PATH ]; then
        red "Error: JavaCard API Classic jar not found in $JCAPI_PATH"
        red "Please ensure JavaCard DevKit is properly installed in $JCDK_PATH"
        exit 1
    fi

    # Check if GP API is already present
    if [ ! -d $GP_API_PATH ]; then
        message="GP API not found in $GP_API_PATH"
        if [ -d $INSTALL_DEPS ]; then
            yellow $message
            yellow "Downloading GP API and extracting to $GP_API_PATH..."
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
            green "GP API installed successfully"
        else
            red $message
            red "Please ensure GP API is properly installed in $GP_API_PATH"
            exit 1
        fi
    fi

    green "All dependencies checked successfully"
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
    run_in_docker "$(declare -f check_dependencies) && $(declare -f generate_cap) && generate_cap true $USER_AID $USER_VERSION" "Build in container failed"
}

# Format from AABBCCDD to 0xAA:0xBB:0xCC:0xDD with sed
format_aid_string() {
    echo "$1" | sed 's/../0x&:/g' | sed 's/:$//'
}

# Function to build the CAP file with parameter to check if inside docker container
generate_cap() {
    local inside_docker=$1
    local user_aid=$2
    local user_version=$3
    if [ "$inside_docker" = true ]; then
        DEPS_PATH=$HOME
        update_vars
    fi

    if [ -n "$user_aid" ]; then
        AID=$user_aid
    fi

    if [ -n "$user_version" ]; then
        VERSION=$user_version
    fi

    check_dependencies

    yellow "Creating bin directory if it doesn't exist..."
    mkdir -p bin

    yellow "Compiling Java sources..."
    if ! $JAVA_HOME/bin/javac -source 7 -target 7 -g \
        -cp $JCAPI_PATH \
        -cp "$JCAPI_PATH:$JCAPI_ANNOTATIONS_PATH:$GP_API_PATH/1.5/gpapi-globalplatform.jar:$UPGRADE_API_PATH/gpapi-upgrade.jar" \
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
        -exportpath $GP_API_PATH/1.5/exports:$UPGRADE_API_PATH/exports \
        -applet $FORMATTED_AID com.ledger.appletcharon.AppletCharon \
        -out CAP JCA EXP \
        -d ./deliverables/applet-charon \
        -debug \
        -target 3.0.5 \
        com.ledger.appletcharon $FORMATTED_AID:0x00 $VERSION; then
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
    
    export LD_LIBRARY_PATH=$OPENSSL_PATH
    export OPENSSL_MODULES=/usr/local/ssl/lib
    
    # Check for NXP JCOP simulator
    if [ ! -d $JCSIM_PATH ]; then
        red "Error: NXP JCOP Simulator not found in $JCSIM_PATH"
        red "Please ensure NXP JCOP Simulator is properly installed in $JCSIM_PATH"
        exit 1
    fi

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
INSTALL_DEPS=false

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
        -i|--install-deps)
            INSTALL_DEPS=true
            shift
            ;;
        -t|--tests)
            TESTS=true
            if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                GH_USER=$2
                if [ -n "$3" ] && [ ${3:0:1} != "-" ]; then
                    GH_TOKEN=$3
                    shift 3
                else
                    shift
                fi
            else
                shift
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
        -h|--help)
            show_help
            ;;
        *)
            red "Unknown option: $1"
            show_help
            ;;
    esac
done

if [ ! -n "$USER_AID" ]; then
    USER_AID=$AID
fi

# Validate github credentials if tests are requested 
# and we are in docker mode.
if [ "$TESTS" = true ]; then
    if [ "$DOCKER" = true ]; then
        # Validate GitHub credentials only if in Docker mode
        if [ -z "$GH_USER" ] || [ -z "$GH_TOKEN" ]; then
            red "Error: When using -t|--tests with Docker, both GitHub username and token are required."
            exit 1
        fi
    fi
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
        generate_cap false $USER_AID $USER_VERSION
    fi
fi
