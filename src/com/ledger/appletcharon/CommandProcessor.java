package com.ledger.appletcharon;

import static com.ledger.appletcharon.Constants.APDU_HEADER_SIZE;
import static com.ledger.appletcharon.Constants.CARD_CERT_ROLE;
import static com.ledger.appletcharon.Constants.CARD_TARGET_ID;
import static com.ledger.appletcharon.Constants.DATA_CARD_NAME_TAG;
import static com.ledger.appletcharon.Constants.DATA_PIN_TRY_COUNTER_TAG;
import static com.ledger.appletcharon.Constants.GET_STATUS_APPLET_FSM_STATE_TAG;
import static com.ledger.appletcharon.Constants.GET_STATUS_APPLET_VERSION_TAG;
import static com.ledger.appletcharon.Constants.GET_STATUS_SERIAL_NUMBER_TAG;
import static com.ledger.appletcharon.Constants.GET_STATUS_TARGET_ID_TAG;
import static com.ledger.appletcharon.Constants.GET_STATUS_TRANSIENT_FSM_STATE_TAG;
import static com.ledger.appletcharon.Constants.HW_CERT_ROLE;
import static com.ledger.appletcharon.Constants.HW_EPH_CERT_ROLE;
import static com.ledger.appletcharon.Constants.HW_SN_LENGTH;
import static com.ledger.appletcharon.Constants.MAX_CARD_NAME_LENGTH;
import static com.ledger.appletcharon.Constants.P1_GET_EPHEMERAL_CERTIFICATE;
import static com.ledger.appletcharon.Constants.P1_GET_STATIC_CERTIFICATE;
import static com.ledger.appletcharon.Constants.P1_VALIDATE_EPHEMERAL_CERTIFICATE;
import static com.ledger.appletcharon.Constants.P1_VALIDATE_STATIC_CERTIFICATE;
import static com.ledger.appletcharon.Constants.SN_LENGTH;
import static com.ledger.appletcharon.Constants.SW_AUTHENTICATION_BLOCKED;
import static com.ledger.appletcharon.Constants.SW_INCORRECT_PARAMETERS;
import static com.ledger.appletcharon.Constants.SW_INCORRECT_SCP_LEDGER;
import static com.ledger.appletcharon.Constants.SW_MISSING_SCP_LEDGER;
import static com.ledger.appletcharon.Constants.SW_PIN_COUNTER_CHANGED;
import static com.ledger.appletcharon.Constants.SW_REFERENCE_DATA_NOT_FOUND;
import static com.ledger.appletcharon.Constants.SW_SECURITY_STATUS;
import static com.ledger.appletcharon.Constants.SW_WRONG_LENGTH;
import static com.ledger.appletcharon.Constants.SW_WRONG_P1P2;
import static com.ledger.appletcharon.Utils.buildTLVField;
import static com.ledger.appletcharon.Version.APPLET_MAJOR_VERSION;
import static com.ledger.appletcharon.Version.APPLET_MINOR_VERSION;
import static com.ledger.appletcharon.Version.APPLET_PATCH_VERSION;
import static com.ledger.appletcharon.Constants.CERTIFICATE_TRUSTED_NAME_TAG;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class CommandProcessor {
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

    private final AppletCharon app;
    private final byte[] ramBuffer;

    public CommandProcessor(AppletCharon applet, byte[] ramBuffer) {
        this.app = applet;
        this.ramBuffer = ramBuffer;
    }

    private short getStatus(byte[] buffer) {
        // Check P1 and P2 are 0
        if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        // Check length field
        if (buffer[ISO7816.OFFSET_LC] != 0) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        short offset = 0;
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_TARGET_ID_TAG }, CARD_TARGET_ID);
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_SERIAL_NUMBER_TAG }, app.serialNumber);
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_APPLET_VERSION_TAG },
                new byte[] { APPLET_MAJOR_VERSION, APPLET_MINOR_VERSION, APPLET_PATCH_VERSION });
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_APPLET_FSM_STATE_TAG },
                new byte[] { app.appletFSM.getCurrentState() });
        offset = buildTLVField(buffer, offset, new byte[] { GET_STATUS_TRANSIENT_FSM_STATE_TAG },
                new byte[] { app.transientFSM.getCurrentState() });
        return offset;
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
        if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        if (buffer[ISO7816.OFFSET_LC] != 0) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        app.certificatePrivateKey.clearKey();
        app.certificatePublicKey.clearKey();
        // Use ramBuffer for temporary data
        app.crypto.generateKeyPair(ramBuffer, (short) 0, app.certificatePrivateKey, app.certificatePublicKey);

        // dataToSign = role || target ID || public key
        ramBuffer[0] = CARD_CERT_ROLE;
        Util.arrayCopy(CARD_TARGET_ID, (short) (0), ramBuffer, (short) 1, (short) CARD_TARGET_ID.length);
        short outLength = (short) (1 + CARD_TARGET_ID.length);
        short publicKeyLength = app.certificatePublicKey.getW(ramBuffer, (short) 5);
        outLength += publicKeyLength;

        // buffer = public_key_len || public key || serial_number_len || serial number
        buffer[0] = (byte) publicKeyLength;
        Util.arrayCopy(ramBuffer, (short) (5), buffer, (short) 1, publicKeyLength);
        buffer[(short) (publicKeyLength + 1)] = (byte) SN_LENGTH;
        Util.arrayCopy(app.serialNumber, (short) 0, buffer, (short) (publicKeyLength + 2), (short) SN_LENGTH);
        // Compute signature
        short signatureLength = app.crypto.computeSignatureWithKey(ramBuffer, (short) 0, outLength, buffer,
                (short) (publicKeyLength + 1 + SN_LENGTH + 2), app.issuerKey);
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
     * data: - issuer public key length (1b) - issuer public key - certificate length - certificate
     *
     * return: none
     */
    private short setCertificate(byte[] buffer, short cdatalength) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_FABRICATION || ramBuffer[1] != TransientStateMachine.STATE_IDLE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check P1 and P2 are 0
        if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        // Check data length
        if (cdatalength == 0 || buffer[ISO7816.OFFSET_LC] == 0
                || (short) (buffer[ISO7816.OFFSET_LC] & 0xFF) != cdatalength - (short) (APDU_HEADER_SIZE)) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        // offset for certificate
        // LC = certificateLength
        short offset = ISO7816.OFFSET_CDATA;
        offset = app.cardCertificatePKI.parseTLVGetOffset(CERTIFICATE_TRUSTED_NAME_TAG, buffer, offset, cdatalength);
        // Check serial number
        if (Util.arrayCompare(buffer, (short) (offset + 1), app.serialNumber, (short) 0, buffer[offset]) != 0) {
            ISOException.throwIt(SW_INCORRECT_PARAMETERS);
        }

        // Verify signature
        offset = ISO7816.OFFSET_CDATA;
        if (app.cardCertificatePKI.verifySignature(buffer, offset, cdatalength) != true) {
            ISOException.throwIt(SW_SECURITY_STATUS);
        }
        // Set FSM state
        app.appletFSM.transition(AppletStateMachine.EVENT_SET_CERTIFICATE);
        app.transientFSM.transition(TransientStateMachine.EVENT_SET_CERTIFICATE);
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
        app.ephemeralCertificate.initData(ramBuffer, (short) 0);
        // Get the ephemeral certificate signed by the static certificate private key
        return app.ephemeralCertificate.getSignedCertificate(ramBuffer, buffer, (short) 0, app.certificatePrivateKey);
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
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        // Check P1 = 0x00, get static certificate
        if (buffer[ISO7816.OFFSET_P1] == P1_GET_STATIC_CERTIFICATE) {
            // Check that host challenge is present
            if (buffer[ISO7816.OFFSET_LC] == 0 || buffer[ISO7816.OFFSET_LC] > 8) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            app.ephemeralCertificate.setHostChallenge(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC]);
            return app.cardCertificatePKI.getCertificate(buffer, (short) 0);
        } else if (buffer[ISO7816.OFFSET_P1] == P1_GET_EPHEMERAL_CERTIFICATE) {
            // Check that no data is present
            if (buffer[ISO7816.OFFSET_LC] != 0) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            if (app.ephemeralCertificate.getHostChallenge(ramBuffer, (short) 0) == 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            return getCardEphemeralCertificate(buffer);
        } else {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        return 0;
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
    private short validateHostCertificate(byte[] buffer, short cdatalength) {
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
        // Check data length
        if (cdatalength == 0 || buffer[ISO7816.OFFSET_LC] == 0
                || (short) (buffer[ISO7816.OFFSET_LC] & 0xFF) != cdatalength - (short) (APDU_HEADER_SIZE)) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        // Check P1 = 0x00, get static certificate
        if (buffer[ISO7816.OFFSET_P1] == P1_VALIDATE_STATIC_CERTIFICATE) {
            if (app.hwStaticCertificatePublicKeyLength[0] != 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            rDataLength = validateHostStaticCertificate(buffer);
        } else if (buffer[ISO7816.OFFSET_P1] == P1_VALIDATE_EPHEMERAL_CERTIFICATE) {
            if (app.hwStaticCertificatePublicKeyLength[0] == 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            rDataLength = validateHostEphemeralCertificate(buffer);
            app.transientFSM.transition(TransientStateMachine.EVENT_CERT_VALID);
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
        Util.arrayCopy(buffer, offset, app.hwSerialNumber, (short) 0, hwSNLength);
        Util.arrayCopy(buffer, offset, ramBuffer, (short) 1, hwSNLength);
        offset += hwSNLength;
        // Copy HW public key to ramBuffer
        byte hwPubKeyLength = buffer[offset++];
        Util.arrayCopy(buffer, offset, ramBuffer, (short) (1 + hwSNLength), hwPubKeyLength);
        offset += hwPubKeyLength;
        // Get HW issuer signature length
        byte hwCertSignatureLength = buffer[offset++];
        // Get Issuer public key and length, store it in ramBuffer
        byte issuerPublicKeyLength = (byte) app.cardCertificatePKI.getIssuerPublicKey(ramBuffer, (short) (1 + hwSNLength + hwPubKeyLength));
        // Verify signature
        if (app.crypto.getCurveId() != CryptoUtil.SECP256K1) {
            app.crypto.initCurve((byte) CryptoUtil.SECP256K1);
        }
        app.crypto.setVerificationKey(ramBuffer, (short) (1 + hwSNLength + hwPubKeyLength), issuerPublicKeyLength);
        if (!app.crypto.verifySignature(ramBuffer, (short) 0, (short) (1 + hwSNLength + hwPubKeyLength), buffer, offset,
                hwCertSignatureLength)) {
            ISOException.throwIt(SW_SECURITY_STATUS);
        } else {
            Util.arrayCopyNonAtomic(ramBuffer, (short) (1 + hwSNLength), app.hwStaticCertificatePublicKey, (short) 0, hwPubKeyLength);
            app.hwStaticCertificatePublicKeyLength[0] = hwPubKeyLength;
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
        short hostChallengeLength = app.ephemeralCertificate.getHostChallenge(ramBuffer, (short) 1);
        // Copy card challenge to ramBuffer
        short cardChallengeLength = app.ephemeralCertificate.getCardChallenge(ramBuffer, (short) (1 + hostChallengeLength));
        // Copy HW ephemeral public key to ramBuffer
        byte hwEphemeralPublicKeyLength = buffer[offset++];
        Util.arrayCopy(buffer, offset, ramBuffer, (short) (1 + hostChallengeLength + cardChallengeLength), hwEphemeralPublicKeyLength);
        offset += hwEphemeralPublicKeyLength;
        // Get HW signature length
        byte hwEphemeralCertSignatureLength = buffer[offset++];
        // Verify signature
        if (app.crypto.getCurveId() != CryptoUtil.SECP256K1) {
            app.crypto.initCurve((byte) CryptoUtil.SECP256K1);
        }
        app.crypto.setVerificationKey(app.hwStaticCertificatePublicKey, (short) 0, app.hwStaticCertificatePublicKeyLength[0]);
        if (!app.crypto.verifySignature(ramBuffer, (short) 0,
                (short) (1 + hostChallengeLength + cardChallengeLength + hwEphemeralPublicKeyLength), buffer, offset,
                hwEphemeralCertSignatureLength)) {
            ISOException.throwIt(SW_SECURITY_STATUS);
        } else {
            // Generate fixed info and session keys
            // Set fixed info offset
            short fixedInfoInitialOffset = (short) (1 + hostChallengeLength + cardChallengeLength + hwEphemeralPublicKeyLength);
            short fixedInfoOffset = fixedInfoInitialOffset;
            // Put fixed info in ramBuffer after other data
            ramBuffer[fixedInfoOffset] = ((CapsuleCBC.KEY_LENGTH * 8) >> 8);
            ramBuffer[(short) (fixedInfoOffset + 1)] = ((CapsuleCBC.KEY_LENGTH * 8) & 0xFF);
            fixedInfoOffset += 2;
            // Put host challenge length and value
            ramBuffer[fixedInfoOffset++] = (byte) hostChallengeLength;
            Util.arrayCopy(ramBuffer, (short) 1, ramBuffer, fixedInfoOffset, hostChallengeLength);
            // Put card challenge length and value
            fixedInfoOffset += hostChallengeLength;
            ramBuffer[fixedInfoOffset++] = (byte) cardChallengeLength;
            Util.arrayCopy(ramBuffer, (short) (1 + hostChallengeLength), ramBuffer, fixedInfoOffset, cardChallengeLength);
            // Put host serial number length and value
            fixedInfoOffset += cardChallengeLength;
            ramBuffer[fixedInfoOffset++] = HW_SN_LENGTH;
            Util.arrayCopy(app.hwSerialNumber, (short) 0, ramBuffer, fixedInfoOffset, HW_SN_LENGTH);
            // Put card serial number length and value
            fixedInfoOffset += HW_SN_LENGTH;
            ramBuffer[fixedInfoOffset++] = SN_LENGTH;
            Util.arrayCopy(app.serialNumber, (short) 0, ramBuffer, fixedInfoOffset, SN_LENGTH);
            fixedInfoOffset += SN_LENGTH;
            short fixedInfoLength = (short) (fixedInfoOffset - fixedInfoInitialOffset);
            // Set fixed info in capsule
            app.capsule.setFixedInfo(ramBuffer, fixedInfoInitialOffset, fixedInfoLength);
            // Generate encryption and MAC session keys
            app.capsule.generateSessionKeys(ramBuffer, (short) (1 + hostChallengeLength + cardChallengeLength), hwEphemeralPublicKeyLength,
                    app.ephemeralCertificate.getPrivateKey());
        }
        return 0;
    }

    private short setPIN(byte[] buffer, short cdatalength) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_ATTESTED || ramBuffer[1] != TransientStateMachine.STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check P1 and P2 are 0
        if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        // Check data presence
        if (cdatalength == 0 || buffer[ISO7816.OFFSET_LC] == 0) {
            ISOException.throwIt(SW_MISSING_SCP_LEDGER);
        }
        // Check data length
        if (cdatalength != buffer[ISO7816.OFFSET_LC] + APDU_HEADER_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Decrypt data
        short plainDataLength = app.capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC], ramBuffer, (short) 0);
        // Check plain PIN data length
        if (plainDataLength != ramBuffer[0] + 1) {
            ISOException.throwIt(SW_INCORRECT_PARAMETERS);
        }
        // Set PIN in transient memory
        app.pinManager.createPIN(ramBuffer);
        return 0;

    }

    private short verifyPIN(byte[] buffer, short cdatalength) {
        boolean pinVerified = false;
        byte triesRemaining = 0;
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check P1 and P2 are 0
        if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        // Check data presence
        if (cdatalength == 0 || buffer[ISO7816.OFFSET_LC] == 0) {
            ISOException.throwIt(SW_MISSING_SCP_LEDGER);
        }
        // Check data length
        if (cdatalength != buffer[ISO7816.OFFSET_LC] + APDU_HEADER_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Decrypt data
        short plainDataLength = app.capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC], ramBuffer, (short) 0);
        // Check plain PIN data length
        if (plainDataLength != ramBuffer[0] + 1) {
            ISOException.throwIt(SW_INCORRECT_PARAMETERS);
        }
        // Verify PIN
        pinVerified = app.pinManager.verifyPIN(ramBuffer);
        if (!pinVerified) {
            app.isPinVerifiedForUpgrade[0] = false;
            triesRemaining = app.pinManager.getTriesRemaining();
            if (triesRemaining == 0) {
                // Reset card name length
                app.cardNameLength = 0;
                // Reset PIN, Seed and FSM
                app.pinManager.resetPIN();
                app.seedManager.clearSeed();
                app.appletFSM.transition(AppletStateMachine.EVENT_PIN_TRY_LIMIT_EXCEEDED);
                app.transientFSM.transition(TransientStateMachine.EVENT_PIN_TRY_LIMIT_EXCEEDED);
                ISOException.throwIt(SW_AUTHENTICATION_BLOCKED);
            } else {
                ISOException.throwIt((short) (SW_PIN_COUNTER_CHANGED + triesRemaining));
            }
        } else {
            app.isPinVerifiedForUpgrade[0] = true;
            // Set FSM state
            app.transientFSM.transition(TransientStateMachine.EVENT_PIN_VERIFIED);
        }
        return 0;
    }

    private short changePIN(byte[] buffer, short cdatalength) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_PIN_UNLOCKED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check P1 and P2 are 0
        if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        // Check data presence
        if (cdatalength == 0 || buffer[ISO7816.OFFSET_LC] == 0) {
            ISOException.throwIt(SW_MISSING_SCP_LEDGER);
        }
        // Check data length
        if (cdatalength != buffer[ISO7816.OFFSET_LC] + APDU_HEADER_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Decrypt data
        short plainDataLength = app.capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC], ramBuffer, (short) 0);
        // Check plain PIN data length
        if (plainDataLength != ramBuffer[0] + 1) {
            ISOException.throwIt(SW_INCORRECT_PARAMETERS);
        }
        // Change PIN
        app.pinManager.changePIN(ramBuffer);
        return 0;
    }

    private short setSeed(byte[] buffer) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_ATTESTED || ramBuffer[1] != TransientStateMachine.STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check PIN is set (meaning PIN value has been put in transient memory)
        if (app.pinManager.getPINStatus() != PINManager.PIN_STATUS_SET) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Decrypt data
        app.capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF), ramBuffer, (short) 0);
        // Set seed
        app.seedManager.setSeed(ramBuffer);
        // Activate PIN
        app.pinManager.activatePIN();
        // Set FSM state
        app.appletFSM.transition(AppletStateMachine.EVENT_SET_SEED);
        app.transientFSM.transition(TransientStateMachine.EVENT_PIN_VERIFIED);
        return 0;
    }

    private short restoreSeed(byte[] buffer, short dataLength) {
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
        if (!app.capsule.checkMAC(buffer, (short) 0, (short) (APDU_HEADER_SIZE - 1), (short) ISO7816.OFFSET_CDATA)) {
            ISOException.throwIt(SW_INCORRECT_SCP_LEDGER);
        }
        // Restore seed to ramBuffer
        byte seedLength = app.seedManager.restoreSeed(ramBuffer, (short) 1);
        ramBuffer[0] = seedLength;
        // Encrypt seed
        return app.capsule.encryptData(ramBuffer, (short) 0, (short) ((SeedManager.MAX_SEED_LENGTH + 1) & 0x00FF), buffer, (short) 0);
    }

    private short verifySeed(byte[] buffer, short cdatalength) {
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] != TransientStateMachine.STATE_PIN_UNLOCKED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (cdatalength == 0 || buffer[ISO7816.OFFSET_LC] == 0) {
            ISOException.throwIt(SW_MISSING_SCP_LEDGER);
        }
        if (cdatalength != buffer[ISO7816.OFFSET_LC] + APDU_HEADER_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        app.capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF), ramBuffer, (short) 0);
        short challengeLength = (short) (ramBuffer[0] & 0x00FF);
        // Sign challenge
        short signatureLength = app.seedManager.signChallenge(ramBuffer, (short) 1, challengeLength, ramBuffer,
                (short) (2 + challengeLength));
        ramBuffer[(short) ((1 + challengeLength) & 0x00FF)] = (byte) signatureLength;
        // Encrypt signature
        return app.capsule.encryptData(ramBuffer, (short) ((challengeLength + 1) & 0x00FF), (short) ((signatureLength + 1) & 0x00FF),
                buffer, (short) 0);
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
        if (!app.capsule.checkMAC(buffer, (short) 0, (short) (APDU_HEADER_SIZE - 1), (short) ISO7816.OFFSET_CDATA))

        {
            ISOException.throwIt(SW_INCORRECT_SCP_LEDGER);
        }
        // Reset card name length
        app.cardNameLength = 0;
        // Reset PIN
        app.pinManager.resetPIN();
        // Clear seed
        app.seedManager.clearSeed();
        // Reset FSM states
        app.appletFSM.transition(AppletStateMachine.EVENT_FACTORY_RESET);
        app.transientFSM.transition(TransientStateMachine.EVENT_FACTORY_RESET);
        return 0;
    }

    private short getData(byte[] buffer, short cdatalength) {
        // Check FSM states
        if (ramBuffer[0] != AppletStateMachine.STATE_USER_PERSONALIZED || ramBuffer[1] < TransientStateMachine.STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Check data length
        if (cdatalength == 0 || buffer[ISO7816.OFFSET_LC] == 0) {
            ISOException.throwIt(SW_MISSING_SCP_LEDGER);
        }
        // Check cData length field is correct (cdatalength is the APDU length including
        // header)
        if ((cdatalength != buffer[ISO7816.OFFSET_LC] + APDU_HEADER_SIZE)
                || (buffer[ISO7816.OFFSET_LC] != buffer[ISO7816.OFFSET_CDATA] + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Check MAC
        if (!app.capsule.checkMAC(buffer, (short) 0, (short) (APDU_HEADER_SIZE - 1), (short) ISO7816.OFFSET_CDATA)) {
            ISOException.throwIt(SW_INCORRECT_SCP_LEDGER);
        }
        // Extract tag of data as short from P1 / P2
        short tag = (short) (((short) buffer[ISO7816.OFFSET_P1] << 8) | (short) buffer[ISO7816.OFFSET_P2]);
        short fieldLength = 0;
        switch (tag) {
        case DATA_CARD_NAME_TAG:
            if (app.cardNameLength == 0) {
                ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
            }
            fieldLength = buildTLVField(ramBuffer, (short) 0, new short[] { DATA_CARD_NAME_TAG }, app.cardName, app.cardNameLength);
            break;
        case DATA_PIN_TRY_COUNTER_TAG:
            byte pinTries = app.pinManager.getTriesRemaining();
            fieldLength = buildTLVField(ramBuffer, (short) 0, new short[] { DATA_PIN_TRY_COUNTER_TAG }, new byte[] { pinTries });
            break;
        default:
            ISOException.throwIt(SW_WRONG_P1P2);
            break;
        }
        return app.capsule.encryptData(ramBuffer, (short) 0, fieldLength, buffer, (short) 0);
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
        app.capsule.decryptData(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF), ramBuffer, (short) 0);
        byte nameLength = ramBuffer[0];
        // Erase card name if nameLength is 0
        if (nameLength == 0) {
            app.cardNameLength = 0;
            return 0;
        }
        // Throw exception if name is too long
        if (nameLength > MAX_CARD_NAME_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Set card name
        app.cardNameLength = nameLength;
        Util.arrayFill(app.cardName, (short) 0, (short) app.cardName.length, (byte) 0);
        Util.arrayCopyNonAtomic(ramBuffer, (short) 1, app.cardName, (short) 0, nameLength);
        return 0;
    }

    public short processCommand(byte[] buffer, short cDataLength) throws ISOException {

        short cdatalength = cDataLength;

        switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_GET_STATUS:
            cdatalength = getStatus(buffer);
            break;
        case INS_GET_PUBLIC_KEY:
            cdatalength = getPublicKey(buffer);
            break;
        case INS_SET_CERTIFICATE:
            cdatalength = setCertificate(buffer, cdatalength);
            break;
        case INS_GET_CARD_CERTIFICATE:
            cdatalength = getCardCertificate(buffer);
            break;
        case INS_VALIDATE_HOST_CERTIFICATE:
            cdatalength = validateHostCertificate(buffer, cdatalength);
            break;
        case INS_SET_PIN:
            cdatalength = setPIN(buffer, cdatalength);
            break;
        case INS_VERIFY_PIN:
            cdatalength = verifyPIN(buffer, cdatalength);
            break;
        case INS_PIN_CHANGE:
            cdatalength = changePIN(buffer, cdatalength);
            break;
        case INS_SET_SEED:
            cdatalength = setSeed(buffer);
            break;
        case INS_RESTORE_SEED:
            cdatalength = restoreSeed(buffer, cdatalength);
            break;
        case INS_VERIFY_SEED:
            cdatalength = verifySeed(buffer, cdatalength);
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
        return cdatalength;
    }
}