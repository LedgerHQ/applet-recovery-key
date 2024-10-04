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
    // Hardware wallet info
    private static final byte HW_CERT_ROLE = (byte) 0x02; // Or 0x20 ?
    private static final byte HW_SN_LENGTH = 4;
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
    private byte[] issuerKey;
    private byte[] hwStaticCertificatePublicKey;

    private SecureChannel secureChannel;
    private CryptoUtil crypto;
    private Certificate cardCertificate;
    private EphemeralCertificate ephemeralCertificate;

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

    // P1 values
    private static final byte P1_GET_STATIC_CERTIFICATE = (byte) 0x00;
    private static final byte P1_GET_EPHEMERAL_CERTIFICATE = (byte) 0x80;
    private static final byte P1_VALIDATE_STATIC_CERTIFICATE = (byte) 0x00;
    private static final byte P1_VALIDATE_EPHEMERAL_CERTIFICATE = (byte) 0x80;

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
    private TransientStateMachine transientFSM;

    // RAM buffer
    private byte ramBuffer[];

    private static final short SECURITY_LEVEL_MASK = 0x7F;

    /**
     * Selects the applet. Initializes the transient state machine (in locked
     * state).
     */
    @Override
    public boolean select() {
        // Initialize state machines
        secureChannel = null;
        return true;
    }

    /**
     * Deselects the applet. Clears the transient state machine.
     */
    public void deselect() {
        // Reset transient state machine
        transientFSM.transition(TransientStateMachine.EVENT_APPLET_DESELECTED);
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
        transientFSM = new TransientStateMachine();
        secureChannel = null;
        pin = null;
        crypto = new CryptoUtil();
        cardCertificate = new Certificate(CARD_CERT_ROLE);
        ephemeralCertificate = new EphemeralCertificate(crypto, CARD_CERT_ROLE);
//        capsule = new Capsule();
        // Dedicate some RAM
        if (ramBuffer == null) {
            ramBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        }

        // Get the serial number from the install data
        getSerialNumberFromInstallData(bArray, bOffset);
        cardCertificate.setSerialNumber(serialNumber, (short) 0, (short) SN_LENGTH);

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
        if ((securityLevel & SECURITY_LEVEL_MASK) != (short) (SecureChannel.C_DECRYPTION | SecureChannel.C_MAC
                | SecureChannel.R_ENCRYPTION | SecureChannel.R_MAC)) {
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
        buffer[offset++] = transientFSM.getCurrentState();

        return offset;
    }

    /**
     * Set the Issuer private key. This key is used only during the card
     * personalization to sign the card public key. This command is only for testing
     * and will be removed.
     *
     * cla: 0x08
     *
     * ins: 0x02
     *
     * p1: 0x00
     *
     * p2: 0x00
     *
     * lc: 0x20
     *
     * data: - issuer private key (32b)
     *
     * return: none
     */
    private void setIssuerKey(byte[] buffer) {
        if (issuerKey == null) {
            issuerKey = JCSystem.makeTransientByteArray((short) CryptoUtil.SECP256K1_PRIVATE_KEY_LEN,
                    JCSystem.CLEAR_ON_DESELECT);
        }
        Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA, issuerKey, (short) 0,
                (short) CryptoUtil.SECP256K1_PRIVATE_KEY_LEN);
    }

    /**
     * Get the card public key signed by a known Issuer private key.
     *
     * cla: 0x08
     *
     * ins: 0x40
     *
     * p1: 0x00
     *
     * p2: 0x00
     *
     * lc: 0x00
     *
     * data: none
     *
     * return: - card public key length (1b) - card public key - card serial number
     * length (1b) - card serial number - issuer signature length (1b) - issuer
     * signature
     */
    private short getPublicKey(byte[] buffer) {
        crypto.initCurve((byte) CryptoUtil.SECP256K1);
        certificatePrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                crypto.getCurve().getCurveLength(), false);
        certificatePublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
                crypto.getCurve().getCurveLength(), false);
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
        short signatureLength = crypto.computeSignature(ramBuffer, (short) 0, outLength, buffer,
                (short) (publicKeyLength + 1 + SN_LENGTH + 2));
        outLength = (short) (publicKeyLength + 1 + SN_LENGTH + 1);
        buffer[outLength] = (byte) signatureLength;

        // buffer = public_key_len || public key || serial_number_len || serial number
        // || signature len || signature
        outLength += (short) (signatureLength + 1);
        return outLength;
    }

    /**
     * Set the card certificate issued by Ledger.
     *
     * cla: 0x08
     *
     * ins: 0x41
     *
     * p1: 0x00
     *
     * p2: 0x00
     *
     * lc: data_len
     *
     * data: - batch serial number (4b) - issuer public key length (1b) - issuer
     * public key - card serial number length (1b) - card serial number - issuer
     * signature length (1b) - issuer signature
     *
     * return: none
     */
    private short setCertificate(byte[] buffer) {
        cardCertificate.setBatchSerial(buffer, ISO7816.OFFSET_CDATA);
        short offset = ISO7816.OFFSET_CDATA + Certificate.BATCH_SERIAL_LEN;
        // buffer[offset] = issuer public key length
        cardCertificate.setIssuerPublicKey(buffer, (short) (offset + 1), buffer[offset]);
        offset += 1 + buffer[offset];
        // buffer[offset] = serial number length
        // Check serial number
        if (Util.arrayCompare(buffer, (short) (offset + 1), serialNumber, (short) 0, buffer[offset]) != 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        offset += 1 + buffer[offset];
        // buffer[offset] = signature length
        cardCertificate.setSignature(buffer, (short) (offset + 1), buffer[offset]);

        // Verify signature
        // The curve is the same as in getPublicKey
        cardCertificate.setCurve(crypto.getCurve());
        ramBuffer[0] = (byte) certificatePublicKey.getW(ramBuffer, (short) 1);
        cardCertificate.setPublicKey(ramBuffer, (short) 1, (short) ramBuffer[0]);
        if (cardCertificate.verifySignature() != true) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        return 0;
    }

    /**
     * Get the card certificate. Can be the static certificate signed by the issuer
     * or an ephemeral certificate signed with the private key of the static
     * certificate.
     * 
     * cla: 0x08
     * 
     * ins: 0x04
     * 
     * p1: 0x00 for static certificate, 0x80 for ephemeral certificate
     * 
     * p2: 0x00
     * 
     * lc : 0 if p1 = 0x00, 8 if p1 = 0x80
     * 
     * data: None if p1 = 0x00, host challenge (8b) if p1 = 0x80
     * 
     * return: reply buffer length. Buffer contains the certificate data (cf.
     * getCardStaticCertificate and getCardEphemeralCertificate).
     */
    private short getCardCertificate(byte[] buffer) {
        // Check P2 is 0
        if (buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        // Check P1 = 0x00, get static certificate
        if (buffer[ISO7816.OFFSET_P1] == P1_GET_STATIC_CERTIFICATE) {
            // Check that host challenge is present
            if (buffer[ISO7816.OFFSET_LC] == 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            ephemeralCertificate.setHostChallenge(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC]);
            return cardCertificate.getCertificate(buffer, (short) 0);
        } else if (buffer[ISO7816.OFFSET_P1] == P1_GET_EPHEMERAL_CERTIFICATE) {
            // Check that no data is present
            if (buffer[ISO7816.OFFSET_LC] != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            return getCardEphemeralCertificate(buffer);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        return 0;
    }

    /**
     * Get an ephemeral certificate signed by the static certificate private key.
     * 
     * return: reply buffer length. Buffer contains the certificate data : [ Card
     * challenge length (1b) | Card challenge (8b) | Card ephemeral public key
     * length (1b) | Card ephemeral public key | Card ephemeral signature length
     * (1b) | Card ephemeral signature ]
     */
    private short getCardEphemeralCertificate(byte[] buffer) {
        ephemeralCertificate.initData(ramBuffer, (short) 0);
        // Get the ephemeral certificate signed by the static certificate private key
        return ephemeralCertificate.getSignedCertificate(ramBuffer, buffer, (short) 0, certificatePrivateKey);
    }

    /**
     * Validate hardware wallet (host) certificate. Either the static certificate
     * issued by Ledger or the ephemeral certificate signed by the static
     * certificate private key of the hardware wallet.
     *
     * cla: 0x08
     *
     * ins: 0x05
     *
     * p1: 0x00 for static certificate, 0x80 for ephemeral certificate
     *
     * p2: 0x00
     *
     * lc: data_len
     *
     * data: For static certificate validation : [ HW serial number length (1b) | HW
     * serial number | HW public key length (1b) | HW public key | HW issuer
     * signature length (1b) | HW issuer signature ]. For ephemeral certificate : [
     * HW
     *
     * return: none
     */
    private short validateHostCertificate(byte[] buffer) {
        // Check P2 is 0
        if (buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        // Check P1 = 0x00, get static certificate
        if (buffer[ISO7816.OFFSET_P1] == P1_VALIDATE_STATIC_CERTIFICATE) {
            return validateHostStaticCertificate(buffer);
        } else if (buffer[ISO7816.OFFSET_P1] == P1_VALIDATE_EPHEMERAL_CERTIFICATE) {
            return validateHostEphemeralCertificate(buffer);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        return 0;
    }

    private short validateHostStaticCertificate(byte[] buffer) {
        // Keep offset for data parsing
        short offset = ISO7816.OFFSET_CDATA;
        // Copy HW role to ramBuffer
        ramBuffer[0] = HW_CERT_ROLE;
        // Copy HW serial number to ramBuffer
        byte hwSNLength = buffer[offset++];
        if (hwSNLength != HW_SN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopy(buffer, offset, ramBuffer, (short) 1, hwSNLength);
        offset += hwSNLength;
        // Copy HW public key to ramBuffer
        byte hwPubKeyLength = buffer[offset++];
        Util.arrayCopy(buffer, offset, ramBuffer, (short) (1 + hwSNLength), hwPubKeyLength);
        offset += hwPubKeyLength;
        // Get HW issuer signature length
        byte hwCertSignatureLength = buffer[offset++];
        // Get Issuer public key and length, store it in ramBuffer
        byte issuerPublicKeyLength = (byte) cardCertificate.getIssuerPublicKey(ramBuffer,
                (short) (1 + hwSNLength + hwPubKeyLength));
        // Verify signature
        if (crypto.getCurveId() != CryptoUtil.SECP256K1) {
            crypto.initCurve((byte) CryptoUtil.SECP256K1);
        }
        crypto.setVerificationKey(ramBuffer, (short) (1 + hwSNLength + hwPubKeyLength), issuerPublicKeyLength);
        if (!crypto.verifySignature(ramBuffer, (short) 0, (short) (1 + hwSNLength + hwPubKeyLength), buffer, offset,
                hwCertSignatureLength)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } else {
            // Store the public key for later use
            if (hwStaticCertificatePublicKey == null) {
                hwStaticCertificatePublicKey = JCSystem.makeTransientByteArray((short) hwPubKeyLength,
                        JCSystem.CLEAR_ON_DESELECT);
            }
            Util.arrayCopyNonAtomic(ramBuffer, (short) (1 + hwSNLength), hwStaticCertificatePublicKey, (short) 0,
                    hwPubKeyLength);
        }
        return 0;
    }

    private short validateHostEphemeralCertificate(byte[] buffer) {
        // Keep offset for data parsing
        short offset = ISO7816.OFFSET_CDATA;
        // Skip APDU data header (header length (1b) + header data (1b))
        offset += 2;
        // Copy HW role to ramBuffer
        ramBuffer[0] = HW_CERT_ROLE;
        // Copy HW challenge to ramBuffer
        short hostChallengeLength = ephemeralCertificate.getHostChallenge(ramBuffer, (short) 1);
        // Copy card challenge to ramBuffer
        short cardChallengeLength = ephemeralCertificate.getCardChallenge(ramBuffer, (short) (1 + hostChallengeLength));
        // Copy HW ephemeral public key to ramBuffer
        byte hwEphemeralPublicKeyLength = buffer[offset++];
        Util.arrayCopy(buffer, offset, ramBuffer, (short) (1 + hostChallengeLength + cardChallengeLength),
                hwEphemeralPublicKeyLength);
        offset += hwEphemeralPublicKeyLength;
        // Get HW signature length
        byte hwEphemeralCertSignatureLength = buffer[offset++];
        // Verify signature
        if (crypto.getCurveId() != CryptoUtil.SECP256K1) {
            crypto.initCurve((byte) CryptoUtil.SECP256K1);
        }
        crypto.setVerificationKey(hwStaticCertificatePublicKey, (short) 0, (short) hwStaticCertificatePublicKey.length);
        if (!crypto.verifySignature(ramBuffer, (short) 0,
                (short) (1 + hostChallengeLength + cardChallengeLength + hwEphemeralPublicKeyLength), buffer, offset,
                hwEphemeralCertSignatureLength)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } else {
            // Generate encryption session key
            // capsule.generateSessionKey(buffer, offset, hwEphemeralPublicKeyLength,
            // ephemeralCertificate.getPrivateKey());
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
            // TODO : check FSM / Transient FSM states (here or inside function)
            cdatalength = getCardCertificate(buffer);
            break;
        case INS_VALIDATE_HOST_CERTIFICATE:
            // TODO : check FSM / Transient FSM states (here or inside function)
            cdatalength = validateHostCertificate(buffer);
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
