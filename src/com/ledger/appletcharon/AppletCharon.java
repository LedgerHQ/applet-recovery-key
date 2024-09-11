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

/**
 * Applet class
 * 
 * @author <user>
 */

public class AppletCharon extends Applet {
    // Applet / Card info
    private static final byte role = (byte) 0xFF; // TODO : define real role.
    private static final short version = (short) 0x0100;
    private static final short targetId = (short) 0xDEAD; // TODO : define real targetId.
    private static final int serialNumber = 0x12345678; // TODO : define real serial number.

    // Owner PIN
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

    private static final byte LEDGER_COMMAND_CLA = (byte) 0xE4;

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
    // Instruction codes
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
     * Only this class's install method should create the applet object.
     */
    protected AppletCharon(byte[] bArray, short bOffset, byte bLength) {
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
     * @return
     */
    private boolean checkSecurityLevel() {
        // Check the security level
        short securityLevel = secureChannel.getSecurityLevel();
        if ((securityLevel & SecureChannel.AUTHENTICATED) != (short) SecureChannel.AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return false;
        }
        return true;
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
        try {
            cdatalength = secureChannel.unwrap(buffer, (short) 0, (short) (ISO7816.OFFSET_CDATA + cdatalength));
        } catch (ISOException isoe) {
            // Throw security exception to be consistent with SE.
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
        case INS_GET_INFO:
//            getInfo(buffer);
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
    }
}
