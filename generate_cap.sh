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
    echo "  -d, --docker      Generate cap inside applet-builder docker container"
    echo "  -c, --clean       Clean build artifacts"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Without any options, the script will generate the CAP file."
    exit 0
}

HOME="/home/devuser"
GP_API_URL="https://globalplatform.org/wp-content/themes/globalplatform/ajax/file-download.php?f=https://globalplatform.org/wp-content/uploads/2019/07/GlobalPlatform_Card_API-org.globalplatform-v1.7.1.zip"
GP_API_PATH="$HOME/GlobalPlatform_Card_API-org.globalplatform-v1.7.1"
JCDK_PATH="$HOME/java_card_devkit"
JCAPI_PATH="$JCDK_PATH/lib/api_classic-3.0.5.jar"
JCAPI_ANNOTATIONS_PATH=$JCDK_PATH"/lib/api_classic_annotations-3.0.5.jar"
JAVA_HOME="/usr/java/jdk-17-oracle-x64"
export JAVA_HOME

# DOCKER_IMAGE="containers.git.orange.ledgerlabs.net/embedded-software/applet-builder:latest"
DOCKER_IMAGE=alexisgrojean/applet-builder:latest
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
    
    # Remove any temporary files that might have been created
    find . -name "*~" -type f -delete
    find . -name "*.bak" -type f -delete
    
    green "Clean completed successfully"
    exit 0
}

# Function to check required dependencies
check_dependencies() {
    yellow "Checking dependencies..."
    
    # Check for JDK 17
    if [ ! -d $JAVA_HOME ]; then
        red "Error: JDK 17 not found in $JAVA_HOME"
        red "Please ensure JDK 17 is properly installed"
        exit 1
    fi

    # Check for JavaCard DevKit
    if [ ! -d $JCDK_PATH ]; then
        red "Error: JavaCard DevKit not found in $JCDK_PATH"
        red "Please ensure JavaCard DevKit is properly installed"
        exit 1
    fi

    # Check for specific required files
    if [ ! -f $JCAPI_PATH ]; then
        red "Error: JavaCard API Classic jar not found in $JCAPI_PATH"
        red "Please ensure JavaCard DevKit is properly installed"
        exit 1
    fi

    # # Check if GP API is already present
    if [ ! -d $GP_API_PATH ]; then
        yellow "Downloading GP API..."
        if ! curl -L -o /tmp/gp-api.zip $GP_API_URL; then
            red "Error: Failed to download GP API"
            exit 1
        fi
        
        if ! unzip /tmp/gp-api.zip -d $HOME; then
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
    if ! docker run --rm --name applet-builder \
        --user $(id -u):$(id -g) \
        --privileged \
        -v "${PWD}:/applet" \
        $DOCKER_IMAGE \
        bash -c "cd /applet && $(declare -f check_dependencies) && $(declare -f generate_cap) && generate_cap true"; then
        red "Error: Build in container failed"
        exit 1
    fi
}

# Function to build the CAP file with parameter to check if inside docker container
generate_cap() {
    local inside_docker=$1
    if [ "$inside_docker" = true ]; then
        echo $HOME
        echo "INSIDE DOCKER"
        ls /home/devuser
        GP_API_URL="https://globalplatform.org/wp-content/themes/globalplatform/ajax/file-download.php?f=https://globalplatform.org/wp-content/uploads/2019/07/GlobalPlatform_Card_API-org.globalplatform-v1.7.1.zip"
        GP_API_PATH="$HOME/GlobalPlatform_Card_API-org.globalplatform-v1.7.1"
        JCDK_PATH="$HOME/java_card_devkit"
        JCAPI_PATH="$JCDK_PATH/lib/api_classic-3.0.5.jar"
        JCAPI_ANNOTATIONS_PATH=$JCDK_PATH"/lib/api_classic_annotations-3.0.5.jar"
        JAVA_HOME="/usr/java/jdk-17-oracle-x64"

        # redefine color functions
        red() { echo -e "\e[31m$*\e[0m"; }
        green() { echo -e "\e[32m$*\e[0m"; }
        yellow() { echo -e "\e[33m$*\e[0m"; }
    fi        

    check_dependencies

    yellow "Creating bin directory if it doesn't exist..."
    mkdir -p bin

    green "Compiling Java sources..."
    if ! $JAVA_HOME/bin/javac -source 7 -target 7 -g \
        -cp $JCAPI_PATH \
        -cp "$JCAPI_PATH:$JCAPI_ANNOTATIONS_PATH:$GP_API_PATH/1.5/gpapi-globalplatform.jar" \
        -d bin src/com/ledger/appletcharon/*.java; then
        red "Error: Java compilation failed"
        exit 1
    fi

    yellow "Creating deliverables directory if it doesn't exist..."
    mkdir -p ./deliverables/applet-charon

    yellow "Running CAP converter..."
    if ! $JCDK_PATH/bin/converter.sh -i \
        -classdir ./bin \
        -exportpath $GP_API_PATH/1.5/exports \
        -applet 0xA0:0x00:0x00:0x00:0x02 com.ledger.appletcharon.AppletCharon \
        -out CAP JCA EXP \
        -d ./deliverables/applet-charon \
        -debug \
        -target 3.0.5 \
        com.ledger.appletcharon 0xA0:0x00:0x00:0x00:0x02:0x00 1.0; then
        red "Error: CAP conversion failed"
        exit 1
    fi

    green "CAP file generated successfully"
}

# Parse command line arguments
DOCKER=false

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
    setup_docker_and_generate_cap
else
    generate_cap
fi

