# Ledger Seed Backup Smart Card Applet

Javacard applet of the Charon smart card project. Allows to perform a seed backup from wallet to card and restore it later.

## How to build and test

### Building the applet from sources

Instructions for Debian like linux distributions.

1. Clone this repo and change directory.

    ```bash
    git clone git@github.com:LedgerHQ/applet-charon.git
    cd applet-charon
    ```

2. Login to Ledger Orange docker registry.

    :information_source: You might need to create a registry token to authenticate, go to your [Orange Github](https://git.orange.ledgerlabs.net/) account, then `Settings > Developer settings > Personal access tokens > Tokens (classic)`, use the `Generate new token` button and choose the following scope `read:packages`

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
