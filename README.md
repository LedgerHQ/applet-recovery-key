## Ledger Seed Backup Smart Card Applet

### How to build and test

#### Building the applet from sources

```
# Clone this repo

git clone git@github.com:LedgerHQ/applet-charon.git

# Go to cloned repo dir

cd applet-charon

# Pull applet builder image (need to be connected to Ledger Orange VPN + logged in to orange docker registry)

docker pull containers.git.orange.ledgerlabs.net/embedded-software/applet-builder:latest

# Run container from image and mount applet directory

docker run --user $(id -u):$(id -g) --privileged -v '.:/applet' -t -d --name applet-builder containers.git.orange.ledgerlabs.net/embedded-software/applet-builder:latest

# Enter container as root

docker exec -u 0 -it applet-builder bash

# Download and extract GP 1.7 API (contains 1.5 as well)

curl -L -o /tmp/gp-api.zip https://globalplatform.org/wp-content/themes/globalplatform/ajax/file-download.php?f=https://globalplatform.org/wp-content/uploads/2019/07/GlobalPlatform_Card_API-org.globalplatform-v1.7.1.zip \
    && mkdir -p /gp-api-1.7 \
    && unzip /tmp/gp-api.zip -d / \
    && rm /tmp/gp-api.zip

# Compile class files from java sources

/usr/java/jdk-17-oracle-x64/bin/javac -source 7 -target 7 -g -cp /java_card_devkit/lib/api_classic-3.0.5.jar -cp "/java_card_devkit/lib/api_classic-3.0.5.jar:/java_card_devkit/lib/api_classic_annotations-3.0.5.jar:/GlobalPlatform_Card_API-org.globalplatform-v1.7.1/1.5/gpapi-globalplatform.jar" -d bin src/com/ledger/appletcharon/*.java

# Run CAP converter on applet sources

/java_card_devkit/bin/converter.sh -i -classdir ./bin -exportpath /GlobalPlatform_Card_API-org.globalplatform-v1.7.1/1.5/exports -applet 0xA0:0x00:0x00:0x00:0x02 com.ledger.appletcharon.AppletCharon -out CAP JCA EXP -d ./deliverables/applet-charon -debug -target 3.0.5 com.ledger.appletcharon 0xA0:0x00:0x00:0x00:0x02:0x00 1.0
```

#### Testing the applet on a real card

```
# Clone command-sender python tool (need to be connected to Ledger Orange VPN + logged in to orange Github). You should clone this repo in the applet-charon directory so it is accessible from the docker container.

git clone git@git.orange.ledgerlabs.net:sandra-rasoamiaramanana/crypto-applet.git

# Enter applet-builder container as root

docker exec -u 0 -it applet-builder bash

# Create python virtual environment and activate it

python3 -m venv venvapplet
source venvapplet/bin/activate

# Go to crypto-applet tools

cd crypto-applet/tools/

# Install tools python requirements

python3 -m pip install -r requirements.txt

# Copy GP Pro command line tool to current directory so python tool can find it

cp /gp.jar .

# Kill PCSC daemon and launch it again as root so it can see physical reader from host

killall pcscd
pcscd

# Find your physical reader's name with a PCSC scan

pcsc_scan

# Save your card's SCP03 Keys with the python tool (ONLY FOR TESTING PURPOSES - NEVER SAVE KEYS IN PLAIN TEXT FOR PRODUCTION USE)

python3 send_commands.py -s -r "<Reader's name>"  -key-enc <ENC KEY> -key-mac <MAC KEY> -key-dek <DEK KEY>

# Load applet on card (with arbitrary 4-byte long card serial number as install parameter)

python3 send_commands.py -i ../../deliverables/applet-charon/com/ledger/appletcharon/javacard/appletcharon.cap -r "<Reader's name>" -p AABBCCDD

# Send get-info commands to real card

python3.11 send_commands.py -f ../../GET_INFO_commands.txt -r "<Reader's name>"

