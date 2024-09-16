/** 
 * Copyright (c) 1998, 2024, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package com.ledger.appletcharon;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

/**
 * Applet class
 * 
 * @author <user>
 */

public class AppletCharon extends Applet {
    // Applet / Card info
    private static final byte role = (byte) 0xFF; // TODO : define real role.
    private static final byte APPLET_MAJOR_VERSION = (byte) 0x00;
    private static final byte APPLET_MINOR_VERSION = (byte) 0x01;
    private static final byte APPLET_PATCH_VERSION = (byte) 0x00;

    private static final byte[] targetId = { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF }; // TODO : Define real
                                                                                                   // // target ID.
    private byte[] serialNumber;
    private static final byte SN_LENGTH = 4;

    private OwnerPIN pin;
    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte PIN_MIN_SIZE = 4;
    private static final byte PIN_MAX_SIZE = 8;

    // Static certificate keys.
//    private ECPrivateKey certificatePrivateKey;
//    private ECPublicKey certificatePublicKey;
//    private byte[] certificate;

    // Session keys
//    private KeyAgreement sharedSecret;
//    private MessageDigest sessionKey;

    private SecureChannel secureChannel;

    private static final byte APDU_HEADER_SIZE = 5;
    private static final byte LEDGER_COMMAND_CLA = (byte) 0x08;

    // Instruction codes
    private static final byte INS_GET_INFO = (byte) 0x01;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x02;
    private static final byte INS_SET_CERTIFICATE = (byte) 0x03;
    private static final byte INS_GET_CARD_CERTIFICATE = (byte) 0x04;
    private static final byte INS_VALIDATE_HOST_CERTIFICATE = (byte) 0x05;
    private static final byte INS_CREATE_PIN = (byte) 0x06;
    private static final byte INS_VERIFY_PIN = (byte) 0x07;
    private static final byte INS_CHANGE_PIN = (byte) 0x08;
    private static final byte INS_CREATE_BACKUP = (byte) 0x09;
    private static final byte INS_RESTORE_BACKUP = (byte) 0x0A;

    // GlobalPlatform classes and instructions code for SCP03
    // Instruction classes
    private static final byte GP_CLA_INITIALIZE_UPDATE = (byte) 0x80;
    private static final byte GP_CLA_EXTERNAL_AUTHENTICATE = (byte) 0x84;
    // Instruction codesUPDAT
    private static final byte GP_INS_INITIALIZE_UPDATE = (byte) 0x50;
    private static final byte GP_INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;

    // Invalid input parameter to command
    private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;

    // State machines
    private AppletStateMachine appletFSM;
    private Object[] transientFSM;

    /**
     * Selects the applet. Initializes the transient state machine (in locked
     * state).
     */
    public boolean select() {
        // Initialize state machines
        transientFSM = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        transientFSM[0] = new TransientStateMachine();
        secureChannel = null;
        return true;
    }

    /**
     * Installs this applet.
     * 
     * @param bArray  the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new AppletCharon(bArray, bOffset, bLength);
    }

    /**
     * Get the serial number from the install data.
     * 
     * @param bArray  the install data
     * @param bOffset the offset in the install data
     */
    private void getSerialNumberFromInstallData(byte[] bArray, short bOffset) {
        short offset = bOffset;

        // Skip AID length
        offset += (short) (bArray[offset] + 1);

        // Skip Info length
        offset += (short) (bArray[offset] + 1);

        byte snLen = bArray[offset];

        // If there is applet data, read the serial number
        if (snLen == SN_LENGTH) {
            serialNumber = new byte[SN_LENGTH];
            Util.arrayCopyNonAtomic(bArray, (short) (offset + 1), serialNumber, (short) 0, SN_LENGTH);
        } else {
            ISOException.throwIt(SW_INVALID_PARAMETER);
        }
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected AppletCharon(byte[] bArray, short bOffset, byte bLength) {
        // Create the FSM
        appletFSM = new AppletStateMachine();
        secureChannel = null;
        pin = null;

        // Get the serial number from the install data
        getSerialNumberFromInstallData(bArray, bOffset);

        register(bArray, ((short) (bOffset + 1)), bArray[bOffset]);
    }

    /**
     * Process GlobalPlatform commands used to establish a secure channel.
     * 
     * @param apdu   the incoming APDU
     * @param buffer the buffer to use
     */
    public void processGPCommand(APDU apdu, byte[] buffer) {
        short outLength;
        switch (buffer[ISO7816.OFFSET_INS]) {
        case GP_INS_INITIALIZE_UPDATE:
            secureChannel = GPSystem.getSecureChannel();
            outLength = secureChannel.processSecurity(apdu);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLength);
            break;
        case GP_INS_EXTERNAL_AUTHENTICATE:
            if (secureChannel == null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            outLength = secureChannel.processSecurity(apdu);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLength);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            break;
        }

    }

    /**
     * Check that a secure channel is established and that the security level is
     * AUTHENTICATED.
     * 
     * @return true if the security level is AUTHENTICATED, false otherwise
     */
    private boolean checkSecurityLevel() {
        // Check the security level
        short securityLevel = secureChannel.getSecurityLevel();
        if ((securityLevel & SecureChannel.AUTHENTICATED) != (short) SecureChannel.AUTHENTICATED) {
            return false;
        }
        return true;
    }

    /**
     * Get general information about the Applet and card itself as well as
     * information about the status of current session.
     * 
     * cla: 0xE4
     * 
     * ins: 0x01
     * 
     * p1: 0x00
     *
     * p2: 0x00
     * 
     * lc: 0x00
     * 
     * data: none
     * 
     * return: [major version (1b) | minor version (1b) | patch version (1) | role
     * (1b) | target id (4b) | IC serial number (4b) | FSM State (1b) | transient
     * FSM State (1b)]
     */
    private short getInfo(byte[] buffer) {

        short offset = 0;

        // Set the version (3 bytes)
        buffer[offset++] = APPLET_MAJOR_VERSION;
        buffer[offset++] = APPLET_MINOR_VERSION;
        buffer[offset++] = APPLET_PATCH_VERSION;

        // Set the role
        buffer[offset++] = role;

        // Set target ID
        Util.arrayCopyNonAtomic(targetId, (short) 0, buffer, offset, (short) targetId.length);
        offset += targetId.length;

        // Set the serial number
        Util.arrayCopyNonAtomic(serialNumber, (short) 0, buffer, offset, (short) serialNumber.length);
        offset += serialNumber.length;

        // Set the applet FSM state
        buffer[offset++] = appletFSM.getCurrentState();

        // Set the transient FSM state
        buffer[offset++] = ((TransientStateMachine) transientFSM[0]).getCurrentState();

        return offset;
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
        // Insert your code here
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        short cdatalength = apdu.setIncomingAndReceive();

        if ((short) buffer[ISO7816.OFFSET_LC] != cdatalength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // To use the GP methods, the CLA must be 0x80 or 0x84
        if ((buffer[ISO7816.OFFSET_CLA] == GP_CLA_INITIALIZE_UPDATE)
                || (buffer[ISO7816.OFFSET_CLA] == GP_CLA_EXTERNAL_AUTHENTICATE)) {
            processGPCommand(apdu, buffer);
            return;
        }

        // For any other command than GP commands, check the security level
        if (!checkSecurityLevel()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Use GP API to unwrap data from secure channel.
        if (cdatalength > 0) {
            cdatalength = secureChannel.unwrap(buffer, (short) 0, (short) (cdatalength + APDU_HEADER_SIZE));
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_GET_INFO:
            cdatalength = getInfo(buffer);
            break;
        case INS_GET_PUBLIC_KEY:
//            getPublicKey(buffer);
            break;
        case INS_SET_CERTIFICATE:
//            verifyPIN(buffer);
            break;
        case INS_GET_CARD_CERTIFICATE:
//            getCardCertificate(buffer);
            break;
        case INS_VALIDATE_HOST_CERTIFICATE:
//            validateHostCertificate(buffer);
            break;
        case INS_CREATE_PIN:
//            createPIN(buffer);
            break;
        case INS_VERIFY_PIN:
//            verifyPIN(buffer);
            break;
        case INS_CHANGE_PIN:
//            changePIN(buffer);
            break;
        case INS_CREATE_BACKUP:
//            createBackup(buffer);
            break;
        case INS_RESTORE_BACKUP:
//            restoreBackup(buffer);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        buffer[(short) (cdatalength)] = (byte) 0x90;
        buffer[(short) (cdatalength + 1)] = (byte) 0x00;
        cdatalength += 2;
        // Wrap buffer with secure channel
        cdatalength = secureChannel.wrap(buffer, (short) 0, cdatalength);
        // Send the response
        apdu.setOutgoingAndSend((short) 0, cdatalength);
    }
}
