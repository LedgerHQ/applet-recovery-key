# Ledger Recovery Key Applet

Javacard applet of the Ledger Recovery Key smart card. Allows to perform a secure seed backup from wallet to card and restore it later.

## Security audit

A security assessment of the source code was performed by Synacktiv, which found no critical vulnerabilities and revealed a high security level. For a detailed analysis, please refer to the [Synacktiv Security Assessment Report](doc/Synacktiv-Ledger-Security_Assessment_Report_v1.2_public.pdf).

## How to build and test

### Building the applet from sources

Instructions for Debian like linux distributions.

* Clone this repo and change directory.

    ```bash
    git clone git@github.com:LedgerHQ/applet-recovery-key.git
    cd applet-recovery-key
    ```

* Execute the CAP generation script. It will use AIDs defined in the script (actual production AIDs) and parse the version from `src/com/ledger/appletrecoverykey/Version.java`

    ```bash
    ./manage_applet.sh
    ```

> [!NOTE]
> During execution, the script may ask you to enter your user password to install the JDK 17 if it is missing.

### Testing the applet

#### Run functional tests

The easiest way to run the functional tests is to use the `manage_applet.sh` script in dockerized mode.

:information_source: You will need a valid [Github](https://github.com/) token to access the `ledger-pluto` python tool used for the tests. Go to your Github account (not to be confused with Orange Github mentioned in the previous section of this readme !), then `Settings > Developer settings > Personal access tokens > Tokens (classic)`, use the `Generate new token` button and choose the following scope `repo`.

```bash
./manage_applet.sh -d -t <Github username> <Github token>
```

:warning: Run the `manage_applet.sh` script to generate the cap file before attempting to run the tests. Check the previous section for instructions.

## State machines

The applet uses two finite state machines (FSM) to control its execution flow and what commands are allowed. The so called "Life Cycle" FSM is persistent across power cycles. On the other hand, the "Transient" state machine is reset when the card loses power (or is reset by the reader).

When the Recovery Key card is shipped to the user, the Life Cycle FSM is in the `Attested` state and a transition to `User Personalized` is done when setting the PIN code and a seed backup is performed.

### Life Cycle state machine

![alt text](doc/life_cycle_state_machine.png)

### Transient state machine

![alt text](doc/transient_state_machine.png)

## `manage_applet.sh` script

The `manage_applet.sh` script assists in building (generating a CAP file), cleaning, and testing the Recovery Key applet, either locally or in a Docker container. It includes options for dependency path customization, AID setting, and running functional tests (requiring GitHub credentials for cloning ledger-pluto)

### Usage

Run the script with one or more options to specify the desired operations:

```bash
./manage_applet.sh [options]
```

#### Options

| Option                           | Description                                                                                      |
|----------------------------------|--------------------------------------------------------------------------------------------------|
| `-d`, `--docker`                 | Run commands in a Docker container                                                               |
| `-a`, `--applet-aid AID`         | Override applet instance AID when generating CAP file (default: A0000000624C45444745523031)      |
| `-k`, `--package-aid AID`        | Override package AID when generating CAP file (default: A0000000624C4544474552303100)           |
| `-v`, `--version VERSION`        | Override applet version when generating CAP file (otherwise read from Version.java)              |
| `-c`, `--clean`                  | Clean build artifacts                                                                            |
| `-p`, `--path`                   | Set dependencies path (for local generation only)                                                |
| `-t`, `--tests GH_USER GH_TOKEN` | Run functional tests (requires GitHub credentials if in Docker with -d)                          |
| `-o`, `--output-dir DIR`         | Set output directory for generated CAP file (default: ./deliverables/applet-recovery-key)        |
| `-n`, `--no-deps`                | Do not automatically download missing dependencies                                               |
| `-h`, `--help`                   | Show help message                                                                                |

> **Note**: Running the script without options will generate the CAP file locally with default AID and version.

### Examples

- **Generate the CAP file locally with default settings**:

  ```bash
  ./manage_applet.sh
  ```

- **Generate the CAP file with custom AIDs**:

  ```bash
  ./manage_applet.sh -a A0000000624C45444745523032 -k A0000000624C4544474552303200
  ```

- **Generate the CAP file with a specific version**:

  ```bash
  ./manage_applet.sh -v 1.2
  ```

- **Generate the CAP file using Docker**:

  ```bash
  ./manage_applet.sh -d
  ```

- **Run functional tests in Docker** (requires GitHub credentials):

  ```bash
  ./manage_applet.sh -d -t YOUR_GITHUB_USERNAME YOUR_GITHUB_TOKEN
  ```

- **Run functional tests locally**:

  ```bash
  ./manage_applet.sh -t
  ```

- **Generate CAP file with custom output directory**:

  ```bash
  ./manage_applet.sh -o ./my-output-dir
  ```

- **Clean build artifacts**:

  ```bash
  ./manage_applet.sh -c
  ```

- **Generate CAP file with specified dependencies path**:

  ```bash
  ./manage_applet.sh -p /path/to/deps
  ```
