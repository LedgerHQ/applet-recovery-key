# Ledger Recovery Key Applet

Javacard applet of the Ledger Recovery Key smart card. Allows to perform a secure seed backup from wallet to card and restore it later.

## How to build and test

### Building the applet from sources

Instructions for Debian like linux distributions.

1. Clone this repo and change directory.

    ```bash
    git clone git@github.com:LedgerHQ/applet-charon.git
    cd applet-charon
    ```

2. Login to Ledger Orange docker registry.

    :information_source: You will need a valid registry token to authenticate, go to your [Orange Github](https://git.orange.ledgerlabs.net/) account, then `Settings > Developer settings > Personal access tokens > Tokens (classic)`, use the `Generate new token` button and choose the following scope `read:packages`

    ```bash
    docker login containers.git.orange.ledgerlabs.net -u <user name>
    ```

3. Execute the CAP generation script (it will pull the [applet-builder Docker image](https://git.orange.ledgerlabs.net/embedded-software/applet-builder))

    ```bash
    ./manage_applet.sh -d
    ```

### Testing the applet

#### Run functional tests

The easiest way to run the functional tests is to use the `manage_applet.sh` script in dockerized mode.

:information_source: You will need a valid [Github](https://github.com/) token to access the `ledger-pluto` python tool used for the tests. Go to your Github account (not to be confused with Orange Github mentioned in the previous section of this readme !), then `Settings > Developer settings > Personal access tokens > Tokens (classic)`, use the `Generate new token` button and choose the following scope `repo`.

```bash
./manage_applet.sh -d -t <Github username> <Github token>
```

:warning: Run the `manage_applet.sh` script to generate the cap file before attempting to run the tests. Check the previous section for instructions.

#### Load the applet on a real card

**TODO** : write this section.

## `manage_applet.sh` script

The `manage_applet.sh` script assists in building (generating a CAP file), cleaning, and testing the Recovery Key applet, either locally or in a Docker container. It includes options for dependency path customization, AID setting, and running functional tests (requiring GitHub credentials for cloning ledger-pluto)

### Usage

Run the script with one or more options to specify the desired operations:

```bash
./manage_applet.sh [options]
```

#### Options

| Option                           | Description                                                                                          |
|----------------------------------|------------------------------------------------------------------------------------------------------|
| `-d`, `--docker`                 | Run the commands inside a Docker container.                                                          |
| `-a`, `--aid AID`                | Set a custom AID for the applet. Default is \`A000000002\`.                                          |
| `-c`, `--clean`                  | Clean up build artifacts (bin and deliverables directories).                                         |
| `-p`, `--path PATH`              | Specify the dependencies path for local generation.                                                  |
| `-t`, `--tests GH_USER GH_TOKEN` | Run functional tests (GitHub credentials required in Docker mode).                                   |
| `-h`, `--help`                   | Display this help message.                                                                           |

> **Note**: Running the script without options will generate the CAP file locally.

### Examples

- **Generate the CAP file locally**:

    ```bash
    ./manage_applet.sh
    ```

- **Generate the CAP file with a custom AID**:

    ```bash
    ./manage_applet.sh -a A000000003
    ```

- **Generate the CAP file using Docker**:

    ```bash
    ./manage_applet.sh -d
    ```

- **Run functional tests in Docker** (requires GitHub credentials):

    ```bash
    ./manage_applet.sh -d -t YOUR_GITHUB_USERNAME YOUR_GITHUB_TOKEN
    ```

- **Clean build artifacts**:

    ```bash
    ./manage_applet.sh -c
    ```
