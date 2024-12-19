/** 
 * Copyright (c) 1998, 2024, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package com.ledger.appletcharon;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.OnUpgradeListener;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;

/**
 * Applet class
 * 
 * @author <user>
 */

public class AppletCharon extends Applet implements OnUpgradeListener {
    // Hardware wallet info
    private static final byte HW_CERT_ROLE = (byte) 0x02;
    private static final byte HW_EPH_CERT_ROLE = (byte) 0x12;
    private static final byte HW_SN_LENGTH = 7;
    // Applet / Card info
    private static final byte CARD_CERT_ROLE = (byte) 0x0A;
    private static final byte APPLET_MAJOR_VERSION = (byte) 0x00;
    private static final byte APPLET_MINOR_VERSION = (byte) 0x01;
    private static final byte APPLET_PATCH_VERSION = (byte) 0x00;

    private static final byte CARD_TARGET_ID[] = { (byte) 0x33, (byte) 0x40, (byte) 0x00, (byte) 0x04 };
    private byte[] serialNumber;
    private static final byte SN_LENGTH = 4;
    private byte[] cardName;
    private static final byte MIN_CARD_NAME_LENGTH = 1;
    private static final byte MAX_CARD_NAME_LENGTH = 32;

    private PINManager pinManager;
    private SeedManager seedManager;

    // Static certificate keys.
    private ECPrivateKey certificatePrivateKey;
    private ECPublicKey certificatePublicKey;
    private byte[] issuerKey;
    private byte[] hwStaticCertificatePublicKey;

    private SecureChannel secureChannel;
    private CryptoUtil crypto;
    private Certificate cardCertificate;
    private EphemeralCertificate ephemeralCertificate;
    private CapsuleCBC capsule;

    // Get status command TLV fields tags
    private static final byte GET_STATUS_TARGET_ID_TAG = (byte) 0x01;
    private static final byte GET_STATUS_SERIAL_NUMBER_TAG = (byte) 0x02;
    private static final byte GET_STATUS_APPLET_VERSION_TAG = (byte) 0x03;
    private static final byte GET_STATUS_APPLET_FSM_STATE_TAG = (byte) 0x04;
    private static final byte GET_STATUS_TRANSIENT_FSM_STATE_TAG = (byte) 0x05;

    // Get data, set data commands TLV fields tags
    private static final short DATA_PIN_TRY_COUNTER_TAG = (short) 0x9F17;
    private static final short DATA_CARD_NAME_TAG = (short) 0x0066;

    private static final byte APDU_HEADER_SIZE = 5;
    private static final byte LEDGER_COMMAND_CLA = (byte) 0x08;

    // Instruction codes
    private static final byte INS_SET_ISSUER_KEY = (byte) 0x02;
    private static final byte INS_GET_STATUS = (byte) 0xF2;
    private static final byte INS_GET_DATA = (byte) 0xCA;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x40;
    private static final byte INS_SET_CERTIFICATE = (byte) 0x41;
    private static final byte INS_GET_CARD_CERTIFICATE = (byte) 0x52;
    private static final byte INS_VALIDATE_HOST_CERTIFICATE = (byte) 0x51;
    private static final byte INS_SET_PIN = (byte) 0xD0;
    private static final byte INS_SET_SEED = (byte) 0xE0;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_PIN_CHANGE = (byte) 0x24;
    private static final byte INS_RESTORE_SEED = (byte) 0x14;
    private static final byte INS_VERIFY_SEED = (byte) 0x2A;
    private static final byte INS_SET_DATA = (byte) 0xDA;
    private static final byte INS_FACTORY_RESET = (byte) 0xE4;

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
    // PIN try counter changed
    protected static final short SW_PIN_COUNTER_CHANGED = (short) 0x63C0;
    // Not enough memory in NVM to store the requested element
    private static final short SW_NOT_ENOUGH_MEMORY = (short) 0x6581;
    // Wrong APDU data field length / Wrong Lc value
    protected static final short SW_WRONG_LENGTH = (short) 0x6700;
    // Expected 'SCP Ledger' Secure Messaging Data Objects missing
    private static final short SW_MISSING_SCP_LEDGER = (short) 0x6887;
    // Failed to decrypt or verify the MAC for this SCP
    protected static final short SW_INCORRECT_SCP_LEDGER = (short) 0x6888;
    // Security status not satisfied
    private static final short SW_SECURITY_STATUS = (short) 0x6982;
    // Authentication method blocked (PIN tries exceeded, applet will reset)
    private static final short SW_AUTHENTICATION_BLOCKED = (short) 0x6983;
    // Expected 'SCP03' Secure Messaging Data Objects missing
    private static final short SW_MISSING_SCP03 = (short) 0x6987;
    // Incorrect ‘SCP03’ Data Object (i.e. failed to decrypt or to verify the MAC
    // for this SCP)
    private static final short SW_INCORRECT_SCP03 = (short) 0x6988;
    // Incorrect parameters in the data field of the incoming command
    private static final short SW_INCORRECT_PARAMETERS = (short) 0x6A80;
    // Wrong P1-P2 parameters (for all commands except Get Data / Set Data)
    private static final short SW_WRONG_P1P2 = (short) 0x6A86;
    // Reference Data not found (i.e. bad P1-P2 for the Get Data / Set Data
    // commands)
    private static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;
    // Success
    private static final short SW_SUCCESS = (short) 0x9000;

    // State machines
    private AppletStateMachine appletFSM;
    private TransientStateMachine transientFSM;

    // RAM buffer
    private static final short RAM_BUFFER_SIZE = 256;
    private byte ramBuffer[];

    private static final short SECURITY_LEVEL_MASK = 0x7F;

    @Override
    public Element onSave() {
        return UpgradeManager.createElement(Element.TYPE_SIMPLE, (short) 0, (short) 6).write(serialNumber)
                .write(PINManager.save(this.pinManager)).write(SeedManager.save(this.seedManager))
                .write(Certificate.save(this.cardCertificate)).write(certificatePrivateKey).write(certificatePublicKey);
    }

    @Override
    public void onCleanup() {
        // Nothing to do
    }

    @Override
    public void onRestore(Element root) {
        if (root == null) {
            return;
        }
        root.initRead();
        if (root.canReadObject() == (short) 6) {
            serialNumber = (byte[]) root.readObject();
            PINManager pinManager = PINManager.restore((Element) root.readObject());
            if (pinManager != null) {
                this.pinManager = pinManager;
            }
            SeedManager seedManager = SeedManager.restore((Element) root.readObject());
            if (seedManager != null) {
                this.seedManager = seedManager;
            }
            Certificate cardCertificate = Certificate.restore((Element) root.readObject());
            if (cardCertificate != null) {
                this.cardCertificate = cardCertificate;
            }
            certificatePrivateKey = (ECPrivateKey) root.readObject();
            certificatePublicKey = (ECPublicKey) root.readObject();
        }
    }

    @Override
    public void onConsolidate() {
        if (certificatePrivateKey != null && certificatePublicKey != null && cardCertificate.signature != null) {
            appletFSM.transition(AppletStateMachine.EVENT_SET_CERTIFICATE);
        }
        if (seedManager.seedKey != null && pinManager.getPINStatus() == PINManager.PIN_STATUS_ACTIVATED) {
            appletFSM.transition(AppletStateMachine.EVENT_SET_SEED);
        }
        transientFSM.setOnSelectState();
    }

    /**
     * Selects the applet. Initializes the transient state machine (in locked
     * state).
     */
    @Override
    public boolean select() {
        secureChannel = null;
        // Reset certificate public key to null (CLEAR_ON_DESELECT only resets value to
        // 0)
        if (hwStaticCertificatePublicKey != null) {
            hwStaticCertificatePublicKey = null;
            JCSystem.requestObjectDeletion();
        }
        // Reset RAM pin buffer to null
        if (pinManager != null) {
            pinManager.clearPINFromRam();
        }
        transientFSM.setOnSelectState();
        // Dedicate some RAM
        if (ramBuffer == null) {
            ramBuffer = JCSystem.makeTransientByteArray(RAM_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        }
        return true;
    }

    /**
     * Deselects the applet. Clears the transient state machine.
     */
    public void deselect() {
        // Reset transient state machine
        // TODO: Check if this is necessary... Should be redundant with the call to
        // setOnSelectState in select()
        transientFSM.transition(TransientStateMachine.EVENT_APPLET_DESELECTED);
        if (secureChannel != null) {
            secureChannel.resetSecurity();
        }
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
        transientFSM = new TransientStateMachine(appletFSM);
        secureChannel = null;
        pinManager = new PINManager();
        seedManager = new SeedManager();
        crypto = new CryptoUtil();
        cardCertificate = new Certificate(CARD_CERT_ROLE);
        ephemeralCertificate = new EphemeralCertificate(crypto, CARD_CERT_ROLE);
        capsule = new CapsuleCBC();

        if (UpgradeManager.isUpgrading() == false) {
            // Get the serial number from the install data
            getSerialNumberFromInstallData(bArray, bOffset);
            cardCertificate.setSerialNumber(serialNumber, (short) 0, (short) SN_LENGTH);
        }
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
            try {
                outLength = secureChannel.processSecurity(apdu);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLength);
            } catch (Exception e) {
                ISOException.throwIt((short) 0xBEAF);
            }
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
        if ((securityLevel & SECURITY_LEVEL_MASK) != (short) (SecureChannel.C_DECRYPTION | SecureChannel.C_MAC | SecureChannel.R_ENCRYPTION
                | SecureChannel.R_MAC)) {
            return false;
        }
        return true;
    }

    /**
     * Constructs a single TLV field with the given tag and value.
     *
     * @param tlvFields the byte array to write the TLV field to
     * @param offset    the starting offset to write the TLV field
     * @param tag       the tag (byte or short) for the TLV field
     * @param value     the value bytes for the TLV field
     * @return the new offset after writing the TLV field
     */
    private short buildTLVField(byte[] tlvFields, short offset, Object tag, byte[] value) {
        if (tag instanceof byte[]) {
            byte[] tagarray = (byte[]) tag;
            tlvFields[offset++] = (byte) tagarray[0];
        } else if (tag instanceof short[]) {
            short[] tagarray = (short[]) tag;
            tlvFields[offset++] = (byte) ((tagarray[0] >> 8) & 0xFF);
            tlvFields[offset++] = (byte) (tagarray[0] & 0xFF);
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        tlvFields[offset++] = (byte) value.length;
        Util.arrayCopyNonAtomic(value, (short) 0, tlvFields, offset, (short) value.length);
        return (short) (offset + value.length);
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
    private short getStatus(byte[] buffer) {
        short offset = 0;
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_TARGET_ID_TAG }, CARD_TARGET_ID);
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_SERIAL_NUMBER_TAG }, serialNumber);
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_APPLET_VERSION_TAG },
                new byte[] { APPLET_MAJOR_VERSION, APPLET_MINOR_VERSION, APPLET_PATCH_VERSION });
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_APPLET_FSM_STATE_TAG }, new byte[] { appletFSM.getCurrentState() });
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_TRANSIENT_FSM_STATE_TAG },
                new byte[] { transientFSM.getCurrentState() });
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
    private short setIssuerKey(byte[] buffer) {
        if (issuerKey == null) {
            issuerKey = JCSystem.makeTransientByteArray((short) CryptoUtil.SECP256K1_PRIVATE_KEY_LEN, JCSystem.CLEAR_ON_DESELECT);
        }
        Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA, issuerKey, (short) 0, (short) CryptoUtil.SECP256K1_PRIVATE_KEY_LEN);
        return 0;
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
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_FABRICATION || ramBuffer[1] != TransientStateMachine.STATE_IDLE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        crypto.initCurve((byte) CryptoUtil.SECP256K1);
        certificatePrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, crypto.getCurve().getCurveLength(),
                false);
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
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_FABRICATION || ramBuffer[1] != TransientStateMachine.STATE_IDLE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        cardCertificate.setBatchSerial(buffer, ISO7816.OFFSET_CDATA);
        short offset = ISO7816.OFFSET_CDATA + Certificate.BATCH_SERIAL_LEN;
        // buffer[offset] = issuer public key length
        cardCertificate.setIssuerPublicKey(buffer, (short) (offset + 1), buffer[offset]);
        offset += 1 + buffer[offset];
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
        // Set FSM state
        appletFSM.transition(AppletStateMachine.EVENT_SET_CERTIFICATE);
        transientFSM.transition(TransientStateMachine.EVENT_SET_CERTIFICATE);
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
        // Check FSM states
        if ((ramBuffer[0] != AppletStateMachine.STATE_ATTESTED || ramBuffer[1] != TransientStateMachine.STATE_INITIALIZED)
                && (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_PIN_LOCKED)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

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
            if (ephemeralCertificate.getHostChallenge(ramBuffer, (short) 0) == 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
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
        // Check FSM states
        if ((ramBuffer[0] != AppletStateMachine.STATE_ATTESTED || ramBuffer[1] != TransientStateMachine.STATE_INITIALIZED)
                && (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_PIN_LOCKED)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short rDataLength = 0;
        // Check P2 is 0
        if (buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        // Check P1 = 0x00, get static certificate
        if (buffer[ISO7816.OFFSET_P1] == P1_VALIDATE_STATIC_CERTIFICATE) {
            if (hwStaticCertificatePublicKey != null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            rDataLength = validateHostStaticCertificate(buffer);
        } else if (buffer[ISO7816.OFFSET_P1] == P1_VALIDATE_EPHEMERAL_CERTIFICATE) {
            if (hwStaticCertificatePublicKey == null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            rDataLength = validateHostEphemeralCertificate(buffer);
            transientFSM.transition(TransientStateMachine.EVENT_CERT_VALID);
        } else {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        return rDataLength;
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
        byte issuerPublicKeyLength = (byte) cardCertificate.getIssuerPublicKey(ramBuffer, (short) (1 + hwSNLength + hwPubKeyLength));
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
                hwStaticCertificatePublicKey = JCSystem.makeTransientByteArray((short) hwPubKeyLength, JCSystem.CLEAR_ON_DESELECT);
            }
            Util.arrayCopyNonAtomic(ramBuffer, (short) (1 + hwSNLength), hwStaticCertificatePublicKey, (short) 0, hwPubKeyLength);
        }
        return 0;
    }

    private short validateHostEphemeralCertificate(byte[] buffer) {
        // Keep offset for data parsing
        short offset = ISO7816.OFFSET_CDATA;
        // Skip APDU data header (1b, always 0x00)
        offset += 1;
        // Copy HW role to ramBuffer
        ramBuffer[0] = HW_EPH_CERT_ROLE;
        // Copy HW challenge to ramBuffer
        short hostChallengeLength = ephemeralCertificate.getHostChallenge(ramBuffer, (short) 1);
        // Copy card challenge to ramBuffer
        short cardChallengeLength = ephemeralCertificate.getCardChallenge(ramBuffer, (short) (1 + hostChallengeLength));
        // Copy HW ephemeral public key to ramBuffer
        byte hwEphemeralPublicKeyLength = buffer[offset++];
        Util.arrayCopy(buffer, offset, ramBuffer, (short) (1 + hostChallengeLength + cardChallengeLength), hwEphemeralPublicKeyLength);
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
            capsule.generateSessionKeys(ramBuffer, (short) (1 + hostChallengeLength + cardChallengeLength), hwEphemeralPublicKeyLength,
                    ephemeralCertificate.getPrivateKey());
        }
        return 0;
    }

    private short setPIN(byte[] buffer) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_ATTESTED || ramBuffer[1] != TransientStateMachine.STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Decrypt data
        capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC], ramBuffer, (short) 0);
        // Set PIN in transient memory
        pinManager.createPIN(ramBuffer);
        return 0;
    }

    private short verifyPIN(byte[] buffer) {
        boolean pinVerified = false;
        byte triesRemaining = 0;
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Decrypt data
        capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC], ramBuffer, (short) 0);
        // Verify PIN
        pinVerified = pinManager.verifyPIN(ramBuffer);
        if (!pinVerified) {
            triesRemaining = pinManager.getTriesRemaining();
            if (triesRemaining == 0) {
                // Reset PIN, Seed and FSM
                pinManager.resetPIN();
                seedManager.clearSeed();
                appletFSM.transition(AppletStateMachine.EVENT_PIN_TRY_LIMIT_EXCEEDED);
                transientFSM.transition(TransientStateMachine.EVENT_PIN_TRY_LIMIT_EXCEEDED);
                ISOException.throwIt(SW_AUTHENTICATION_BLOCKED);
            } else {
                ISOException.throwIt((short) (SW_PIN_COUNTER_CHANGED + triesRemaining));
            }
        }
        // Set FSM state
        transientFSM.transition(TransientStateMachine.EVENT_PIN_VERIFIED);
        return 0;
    }

    private short changePIN(byte[] buffer) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_PIN_UNLOCKED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Decrypt data
        capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC], ramBuffer, (short) 0);
        // Change PIN
        pinManager.changePIN(ramBuffer);
        return 0;
    }

    private short factoryReset(byte[] buffer, short dataLength) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_PIN_UNLOCKED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check data length
        if (dataLength == 0 || buffer[ISO7816.OFFSET_LC] == 0) {
            ISOException.throwIt(SW_MISSING_SCP_LEDGER);
        }
        if (buffer[ISO7816.OFFSET_LC] != buffer[ISO7816.OFFSET_CDATA] + 1) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        // Check MAC
        if (!capsule.checkMAC(buffer, (short) 0, (short) (APDU_HEADER_SIZE - 1), (short) ISO7816.OFFSET_CDATA))

        {
            ISOException.throwIt(SW_INCORRECT_SCP_LEDGER);
        }
        // Reset PIN
        pinManager.resetPIN();
        // Clear seed
        seedManager.clearSeed();
        // Reset FSM states
        appletFSM.transition(AppletStateMachine.EVENT_FACTORY_RESET);
        transientFSM.transition(TransientStateMachine.EVENT_FACTORY_RESET);
        return 0;
    }

    private short setSeed(byte[] buffer) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_ATTESTED || ramBuffer[1] != TransientStateMachine.STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check PIN is set (meaning PIN value has been put in transient memory)
        if (pinManager.getPINStatus() != PINManager.PIN_STATUS_SET) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Decrypt data
        capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF), ramBuffer, (short) 0);
        // Set seed
        seedManager.setSeed(ramBuffer);
        // Activate PIN
        pinManager.activatePIN();
        // Set FSM state
        appletFSM.transition(AppletStateMachine.EVENT_SET_SEED);
        transientFSM.transition(TransientStateMachine.EVENT_PIN_VERIFIED);
        return 0;
    }

    private short restoreSeed(byte[] buffer) {
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_PIN_UNLOCKED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Restore seed to ramBuffer
        byte seedLength = seedManager.restoreSeed(ramBuffer, (short) 1);
        ramBuffer[0] = seedLength;
        // Encrypt seed
        return capsule.encryptData(ramBuffer, (short) 0, (short) ((seedLength + 1) & 0x00FF), buffer, (short) 0);
    }

    private short getData(byte[] buffer, short cdatalength) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] < TransientStateMachine.STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check cData length field is correct (cdatalength is the APDU length including
        // header)
        if (buffer[ISO7816.OFFSET_LC] != 0 || cdatalength != buffer[ISO7816.OFFSET_LC] + APDU_HEADER_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Extract tag of data as short from P1 / P2
        short tag = (short) (((short) buffer[ISO7816.OFFSET_P1] << 8) | (short) buffer[ISO7816.OFFSET_P2]);
        short fieldLength = 0;
        switch (tag) {
        case DATA_CARD_NAME_TAG:
            if (cardName == null) {
                ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
            }
            fieldLength = buildTLVField(ramBuffer, (short) 0, new short[] { DATA_CARD_NAME_TAG }, cardName);
            break;
        case DATA_PIN_TRY_COUNTER_TAG:
            byte pinTries = pinManager.getTriesRemaining();
            fieldLength = buildTLVField(ramBuffer, (short) 0, new short[] { DATA_PIN_TRY_COUNTER_TAG }, new byte[] { pinTries });
            break;
        default:
            ISOException.throwIt(SW_WRONG_P1P2);
            break;
        }
        return capsule.encryptData(ramBuffer, (short) 0, fieldLength, buffer, (short) 0);
    }

    private short setData(byte[] buffer, short cdatalength) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_PIN_UNLOCKED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check data length
        if (cdatalength == 0 || buffer[ISO7816.OFFSET_LC] == 0) {
            ISOException.throwIt(SW_MISSING_SCP_LEDGER);
        }
        // Check cData length field is correct (cdatalength is the APDU length including
        // header)
        if (cdatalength != buffer[ISO7816.OFFSET_LC] + APDU_HEADER_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Extract tag of data as short from P1 / P2
        short tag = (short) (((short) buffer[ISO7816.OFFSET_P1] << 8) | (short) buffer[ISO7816.OFFSET_P2]);
        if (tag != DATA_CARD_NAME_TAG) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF), ramBuffer, (short) 0);
        byte nameLength = ramBuffer[0];
        if (nameLength < MIN_CARD_NAME_LENGTH || nameLength > MAX_CARD_NAME_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (cardName != null) {
            cardName = null;
            JCSystem.requestObjectDeletion();
        }
        cardName = new byte[nameLength];
        Util.arrayCopyNonAtomic(ramBuffer, (short) 1, cardName, (short) 0, nameLength);
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
        if ((buffer[ISO7816.OFFSET_CLA] == GP_CLA_INITIALIZE_UPDATE) || (buffer[ISO7816.OFFSET_CLA] == GP_CLA_EXTERNAL_AUTHENTICATE)) {
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
        try {
            if (cdatalength > 0) {
                buffer[ISO7816.OFFSET_CLA] = GP_CLA_EXTERNAL_AUTHENTICATE;
                cdatalength = secureChannel.unwrap(buffer, (short) 0, (short) (cdatalength + APDU_HEADER_SIZE));
                buffer[ISO7816.OFFSET_CLA] = LEDGER_COMMAND_CLA;
            }
        } catch (Exception e) {
            ISOException.throwIt((short) 0xFEDE);
        }

        // Get current persistent state
        ramBuffer[0] = appletFSM.getCurrentState();
        ramBuffer[1] = transientFSM.getCurrentState();

        switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_GET_STATUS:
            cdatalength = getStatus(buffer);
            break;
        case INS_SET_ISSUER_KEY:
            cdatalength = setIssuerKey(buffer);
            break;
        case INS_GET_PUBLIC_KEY:
            cdatalength = getPublicKey(buffer);
            break;
        case INS_SET_CERTIFICATE:
            cdatalength = setCertificate(buffer);
            break;
        case INS_GET_CARD_CERTIFICATE:
            cdatalength = getCardCertificate(buffer);
            break;
        case INS_VALIDATE_HOST_CERTIFICATE:
            cdatalength = validateHostCertificate(buffer);
            break;
        case INS_SET_PIN:
            cdatalength = setPIN(buffer);
            break;
        case INS_VERIFY_PIN:
            cdatalength = verifyPIN(buffer);
            break;
        case INS_PIN_CHANGE:
            cdatalength = changePIN(buffer);
            break;
        case INS_SET_SEED:
            cdatalength = setSeed(buffer);
            break;
        case INS_RESTORE_SEED:
            cdatalength = restoreSeed(buffer);
            break;
        case INS_VERIFY_SEED:
            if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_PIN_UNLOCKED) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            // TODO: Implement seed verification
            break;
        case INS_GET_DATA:
            cdatalength = getData(buffer, cdatalength);
            break;
        case INS_SET_DATA:
            cdatalength = setData(buffer, cdatalength);
            break;
        case INS_FACTORY_RESET:
            cdatalength = factoryReset(buffer, cdatalength);
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
