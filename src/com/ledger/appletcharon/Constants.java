package com.ledger.appletcharon;

public final class Constants {
    // Hardware wallet info constants
    protected static final byte HW_CERT_ROLE = (byte) 0x02;
    protected static final byte HW_EPH_CERT_ROLE = (byte) 0x12;
    protected static final byte HW_SN_LENGTH = 7;
    protected static final short MAX_HW_PUBLIC_KEY_LENGTH = 65;

    // Card info constants
    protected static final byte CARD_CERT_ROLE = (byte) 0x0A;
    protected static final byte CARD_TARGET_ID[] = { (byte) 0x33, (byte) 0x40, (byte) 0x00, (byte) 0x04 };
    protected static final byte MAX_CARD_NAME_LENGTH = 32;
    protected static final byte SN_LENGTH = 4;

    // RAM buffer size
    protected static final short RAM_BUFFER_SIZE = 256;

    // P1 values
    protected static final byte P1_GET_STATIC_CERTIFICATE = (byte) 0x00;
    protected static final byte P1_GET_EPHEMERAL_CERTIFICATE = (byte) 0x80;
    protected static final byte P1_VALIDATE_STATIC_CERTIFICATE = (byte) 0x00;
    protected static final byte P1_VALIDATE_EPHEMERAL_CERTIFICATE = (byte) 0x80;

    // Get status command TLV fields tags
    protected static final byte GET_STATUS_TARGET_ID_TAG = (byte) 0x01;
    protected static final byte GET_STATUS_SERIAL_NUMBER_TAG = (byte) 0x02;
    protected static final byte GET_STATUS_APPLET_VERSION_TAG = (byte) 0x03;
    protected static final byte GET_STATUS_APPLET_FSM_STATE_TAG = (byte) 0x04;
    protected static final byte GET_STATUS_TRANSIENT_FSM_STATE_TAG = (byte) 0x05;

    // Get data, set data commands TLV fields tags
    protected static final short DATA_PIN_TRY_COUNTER_TAG = (short) 0x9F17;
    protected static final short DATA_CARD_NAME_TAG = (short) 0x0066;

    // Basic APDU constants
    protected static final byte APDU_HEADER_SIZE = 5;
    protected static final byte LEDGER_COMMAND_CLA = (byte) 0x08;

    // GP SCP constants
    protected static final short SECURITY_LEVEL_MASK = 0x7F;

    // GlobalPlatform classes and instructions code for SCP03
    // Instruction classes
    protected static final byte GP_CLA_INITIALIZE_UPDATE = (byte) 0x80;
    protected static final byte GP_CLA_EXTERNAL_AUTHENTICATE = (byte) 0x84;
    // Instruction codes
    protected static final byte GP_INS_INITIALIZE_UPDATE = (byte) 0x50;
    protected static final byte GP_INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;

    // Custom status words
    // PIN try counter changed
    protected static final short SW_PIN_COUNTER_CHANGED = (short) 0x63C0;
    // Not enough memory in NVM to store the requested element
    protected static final short SW_NOT_ENOUGH_MEMORY = (short) 0x6581;
    // Wrong APDU data field length / Wrong Lc value
    protected static final short SW_WRONG_LENGTH = (short) 0x6700;
    // Expected 'SCP Ledger' Secure Messaging Data Objects missing
    protected static final short SW_MISSING_SCP_LEDGER = (short) 0x6887;
    // Failed to decrypt or verify the MAC for this SCP
    protected static final short SW_INCORRECT_SCP_LEDGER = (short) 0x6888;
    // Security status not satisfied
    protected static final short SW_SECURITY_STATUS = (short) 0x6982;
    // Authentication method blocked (PIN tries exceeded, applet will reset)
    protected static final short SW_AUTHENTICATION_BLOCKED = (short) 0x6983;
    // Expected 'SCP03' Secure Messaging Data Objects missing
    protected static final short SW_MISSING_SCP03 = (short) 0x6987;
    // Incorrect ‘SCP03’ Data Object (i.e. failed to decrypt or to verify the MAC
    // for this SCP)
    protected static final short SW_INCORRECT_SCP03 = (short) 0x6988;
    // Incorrect parameters in the data field of the incoming command
    protected static final short SW_INCORRECT_PARAMETERS = (short) 0x6A80;
    // Wrong P1-P2 parameters (for all commands except Get Data / Set Data)
    protected static final short SW_WRONG_P1P2 = (short) 0x6A86;
    // Reference Data not found (i.e. bad P1-P2 for the Get Data / Set Data
    // commands)
    protected static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;
    // Success
    protected static final short SW_SUCCESS = (short) 0x9000;
    // Fatal errors
    protected static final short SW_FATAL_ERROR = (short) 0x9F00;
    protected static final short SW_FATAL_ERROR_DURING_INIT = (short) 0x9F01;

    // STORE_DATA constants
    // Key tag values
    protected static final byte TAG_KEY_USAGE = (byte) 0x95;
    protected static final byte TAG_KEY_TYPE = (byte) 0x80;
    protected static final byte TAG_KEY_LENGTH = (byte) 0x81;
    protected static final byte TAG_KEY_ID = (byte) 0x82;
    protected static final byte TAG_KEY_VERSION = (byte) 0x83;
    protected static final byte TAG_KEY_PARAM_LENGTH = (byte) 0x01;
    // Data Grouping Identifier for key Control Reference Template (CRT)
    protected static final short DGI_TAG_KEY_CRT = (short) 0x00B9;
    // Data Grouping Identifier for key value
    protected static final short DGI_TAG_KEY_VALUE = (short) 0x8137;
    // Key usage: digital signature
    protected static final byte KEY_USAGE_SIGNATURE = (byte) 0x02;
    // Type: ECC private key
    protected static final byte KEY_TYPE_PRIVATE_ECC = (byte) 0xB1;
    protected static final byte KEY_VERSION_01 = (byte) 0x01;

}
