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
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;

/**
 * Applet class
 * 
 * @author <user>
 */

public class AppletCharon extends Applet {
    // Applet / Card info
    private static final byte CARD_CERT_ROLE = (byte) 0x0A;
    private static final byte APPLET_MAJOR_VERSION = (byte) 0x00;
    private static final byte APPLET_MINOR_VERSION = (byte) 0x01;
    private static final byte APPLET_PATCH_VERSION = (byte) 0x00;

    private static final byte CARD_TARGET_ID[] = { (byte) 0x33, (byte) 0x40, (byte) 0x00, (byte) 0x04 };
    private byte[] serialNumber;
    private static final byte SN_LENGTH = 4;

    private OwnerPIN pin;
    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte PIN_MIN_SIZE = 4;
    private static final byte PIN_MAX_SIZE = 8;

    // Static certificate keys.
    private ECPrivateKey certificatePrivateKey;
    private ECPublicKey certificatePublicKey;
//    private byte[] certificate;
    private byte[] issuerKey;

    // Session keys
//    private KeyAgreement sharedSecret;
//    private MessageDigest sessionKey;

    private SecureChannel secureChannel;
    private CryptoUtil crypto;
    private Certificate cardCertificate;

    private static final byte APDU_HEADER_SIZE = 5;
    private static final byte LEDGER_COMMAND_CLA = (byte) 0x08;

    // Instruction codes
    private static final byte INS_GET_INFO = (byte) 0x01;
    private static final byte INS_SET_ISSUER_KEY = (byte) 0x02;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x40;
    private static final byte INS_SET_CERTIFICATE = (byte) 0x41;
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
    private static final short SW_INVALID_PARAMETER = (short) 0x9C0F;

    // State machines
    private AppletStateMachine appletFSM;
    private Object[] transientFSM;
    
    // RAM buffer
    private byte ramBuffer[];

    private static final short SECURITY_LEVEL_MASK = 0x7F;

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
        crypto = new CryptoUtil();
        cardCertificate = new Certificate(CARD_CERT_ROLE);
        
        // Dedicate some RAM
        if (ramBuffer == null) {
            ramBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        }

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
     * R_DECRYPTION | C_ENCRYPTION | R_MAC | C_MAC = 0x33
     * 
     * @return true if the security level is as expected, false otherwise
     */
    private boolean checkSecurityLevel() {
        // Check the security level
        short securityLevel = secureChannel.getSecurityLevel();
        if ((securityLevel & SecureChannel.AUTHENTICATED) != (short) SecureChannel.AUTHENTICATED) {
            return false;
        }
        if ((securityLevel & SECURITY_LEVEL_MASK)
            != (short) (SecureChannel.C_DECRYPTION | SecureChannel.C_MAC | SecureChannel.R_ENCRYPTION | SecureChannel.R_MAC)) {
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
        buffer[offset++] = CARD_CERT_ROLE;

        // Set target ID
        Util.arrayCopyNonAtomic(CARD_TARGET_ID, (short) 0, buffer, offset, (short) CARD_TARGET_ID.length);
        offset += CARD_TARGET_ID.length;

        // Set the serial number
        Util.arrayCopyNonAtomic(serialNumber, (short) 0, buffer, offset, (short) serialNumber.length);
        offset += serialNumber.length;

        // Set the applet FSM state
        buffer[offset++] = appletFSM.getCurrentState();

        // Set the transient FSM state
        buffer[offset++] = ((TransientStateMachine) transientFSM[0]).getCurrentState();

        return offset;
    }
    
    private void setIssuerKey(byte[] buffer) {
        if (issuerKey == null) {
            issuerKey = JCSystem.makeTransientByteArray((short) CryptoUtil.SECP256K1_PRIVATE_KEY_LEN, JCSystem.CLEAR_ON_DESELECT);
        }
        Util.arrayCopy(buffer,  (short) ISO7816.OFFSET_CDATA, issuerKey, (short) 0, (short) CryptoUtil.SECP256K1_PRIVATE_KEY_LEN);
    }

    private short getPublicKey(byte[] buffer) {
        crypto.initCurve((byte) CryptoUtil.SECP256K1);
        certificatePrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, crypto.getCurve().getCurveLength(), false);
        certificatePublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, crypto.getCurve().getCurveLength(), false);
        // Use ramBuffer for temporary data
        crypto.generateKeyPair(ramBuffer, (short) 0, certificatePrivateKey, certificatePublicKey);
        if (issuerKey == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        crypto.setSigningKey(issuerKey, (short) 0, (short) CryptoUtil.SECP256K1_PRIVATE_KEY_LEN);

        // dataToSign = role || target ID || public key
        ramBuffer[0] = CARD_CERT_ROLE;
        Util.arrayCopy(CARD_TARGET_ID, (short) (0), ramBuffer, (short) 1, (short) CARD_TARGET_ID.length);
        short outLength = (short) (1 + CARD_TARGET_ID.length);
        short publicKeyLength = certificatePublicKey.getW(ramBuffer, (short) 5);
        outLength += publicKeyLength;

        // buffer = public_key_len || public key || serial_number_len || serial number
        buffer[0] = (byte) publicKeyLength;
        Util.arrayCopy(ramBuffer, (short) (5), buffer, (short) 1, publicKeyLength);
        buffer[(short) (publicKeyLength + 1)] = (byte) SN_LENGTH;
        Util.arrayCopy(serialNumber, (short) 0, buffer, (short) (publicKeyLength + 2), (short) SN_LENGTH);
        // Compute signature
        short signatureLength = crypto.computeSignature(ramBuffer, (short) 0, outLength, buffer, (short)(publicKeyLength + 1 + SN_LENGTH + 2));
        outLength = (short) (publicKeyLength + 1 + SN_LENGTH + 1);
        buffer[outLength] = (byte) signatureLength;

        // buffer = public_key_len || public key || serial_number_len || serial number || signature len || signature
        outLength += (short) (signatureLength + 1);
        return outLength;
    }

    private short setCertificate(byte[] buffer) {
        cardCertificate.setBatchSerial(buffer, ISO7816.OFFSET_CDATA);
        short offset = ISO7816.OFFSET_CDATA + Certificate.BATCH_SERIAL_LEN;
        // buffer[offset] = public key length
        cardCertificate.setPublicKey(buffer, (short) (offset + 1), buffer[offset]);
        offset += 1 + buffer[offset];
        // buffer[offset] = serial number length
        // Check serial number
        if (Util.arrayCompare(buffer, (short) (offset + 1), serialNumber, (short) 0, buffer[offset]) != 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        offset += 1 + buffer[offset];
        // buffer[offset] = signature length
        cardCertificate.setSignature(buffer, (short) (offset + 1), buffer[offset]);
        offset += 1 + buffer[offset];
        // buffer[offset] = mcu serial length
        cardCertificate.setMcuSerial(buffer, (short) (offset + 1), buffer[offset]);

        // Verify signature
        // The curve is the same as in getPublicKey
        cardCertificate.setCurve(crypto.getCurve());
        if (cardCertificate.verifySignature(serialNumber, SN_LENGTH) != true) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        return 0;
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

        if ((short) (buffer[ISO7816.OFFSET_LC] & 0x00FF) != cdatalength) {
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

        // Check if the APDU is a Ledger command
        if (buffer[ISO7816.OFFSET_CLA] != LEDGER_COMMAND_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Use GP API to unwrap data from secure channel.
        if (cdatalength > 0) {
            buffer[ISO7816.OFFSET_CLA] = GP_CLA_EXTERNAL_AUTHENTICATE;
            cdatalength = secureChannel.unwrap(buffer, (short) 0, (short) (cdatalength + APDU_HEADER_SIZE));
        }

        // Get current persistent state
        ramBuffer[0] = appletFSM.getCurrentState();

        switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_GET_INFO:
            cdatalength = getInfo(buffer);
            break;
        case INS_SET_ISSUER_KEY:
            setIssuerKey(buffer);
            cdatalength = 0;
            break;
        case INS_GET_PUBLIC_KEY:
            if (ramBuffer[0] != AppletStateMachine.STATE_FABRICATION) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            cdatalength = getPublicKey(buffer);
            break;
        case INS_SET_CERTIFICATE:
            if (ramBuffer[0] != AppletStateMachine.STATE_FABRICATION) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            cdatalength = setCertificate(buffer);
            appletFSM.transition(AppletStateMachine.EVENT_SET_CERTIFICATE);
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

        // Add status word before wrapping response buffer
        buffer[(short) (cdatalength)] = (byte) 0x90;
        buffer[(short) (cdatalength + 1)] = (byte) 0x00;
        cdatalength += 2;
        // Wrap buffer with secure channel
        cdatalength = secureChannel.wrap(buffer, (short) 0, cdatalength);
        // Send the response
        apdu.setOutgoingAndSend((short) 0, cdatalength);
    }
}
