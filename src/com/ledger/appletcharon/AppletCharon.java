/** 
 * Copyright (c) 1998, 2024, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package com.ledger.appletcharon;

import static com.ledger.appletcharon.Constants.APDU_HEADER_SIZE;
import static com.ledger.appletcharon.Constants.CARD_CERT_ROLE;
import static com.ledger.appletcharon.Constants.DGI_TAG_KEY_CRT;
import static com.ledger.appletcharon.Constants.DGI_TAG_PRIVATE_KEY_VALUE;
import static com.ledger.appletcharon.Constants.DGI_TAG_PUBLIC_KEY_VALUE;
import static com.ledger.appletcharon.Constants.GET_STATUS_SERIAL_NUMBER_TAG;
import static com.ledger.appletcharon.Constants.GP_CLA_EXTERNAL_AUTHENTICATE;
import static com.ledger.appletcharon.Constants.GP_CLA_INITIALIZE_UPDATE;
import static com.ledger.appletcharon.Constants.GP_INS_EXTERNAL_AUTHENTICATE;
import static com.ledger.appletcharon.Constants.GP_INS_INITIALIZE_UPDATE;
import static com.ledger.appletcharon.Constants.HW_SN_LENGTH;
import static com.ledger.appletcharon.Constants.INS_GET_STATUS;
import static com.ledger.appletcharon.Constants.KEY_TYPE_PRIVATE_ECC;
import static com.ledger.appletcharon.Constants.KEY_TYPE_PUBLIC_ECC;
import static com.ledger.appletcharon.Constants.KEY_USAGE_SIGNATURE;
import static com.ledger.appletcharon.Constants.KEY_USAGE_VERIFICATION;
import static com.ledger.appletcharon.Constants.KEY_VERSION_01;
import static com.ledger.appletcharon.Constants.KEY_VERSION_11;
import static com.ledger.appletcharon.Constants.LEDGER_COMMAND_CLA;
import static com.ledger.appletcharon.Constants.MAX_CARD_NAME_LENGTH;
import static com.ledger.appletcharon.Constants.MAX_HW_PUBLIC_KEY_LENGTH;
import static com.ledger.appletcharon.Constants.RAM_BUFFER_SIZE;
import static com.ledger.appletcharon.Constants.SECURITY_LEVEL_MASK;
import static com.ledger.appletcharon.Constants.SN_LENGTH;
import static com.ledger.appletcharon.Constants.SW_FATAL_ERROR;
import static com.ledger.appletcharon.Constants.SW_INCORRECT_PARAMETERS;
import static com.ledger.appletcharon.Constants.SW_INCORRECT_SCP03;
import static com.ledger.appletcharon.Constants.SW_REFERENCE_DATA_NOT_FOUND;
import static com.ledger.appletcharon.Constants.SW_WRONG_LENGTH;
import static com.ledger.appletcharon.Constants.TAG_KEY_ID;
import static com.ledger.appletcharon.Constants.TAG_KEY_LENGTH;
import static com.ledger.appletcharon.Constants.TAG_KEY_PARAM_LENGTH;
import static com.ledger.appletcharon.Constants.TAG_KEY_TYPE;
import static com.ledger.appletcharon.Constants.TAG_KEY_USAGE;
import static com.ledger.appletcharon.Constants.TAG_KEY_VERSION;
import static com.ledger.appletcharon.Constants.UPGRADE_AUTHORIZATION_DENIED;
import static com.ledger.appletcharon.Constants.UPGRADE_AUTHORIZATION_GRANTED;

import org.globalplatform.Application;
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

public class AppletCharon extends Applet implements OnUpgradeListener, Application {
    // Hardware wallet info
    protected byte[] hwSerialNumber;

    // Card info
    protected byte[] serialNumber;
    protected byte[] cardName;
    protected byte cardNameLength;

    // PIN management
    protected PINManager pinManager;

    // Upgrade authorization state
    protected short[] upgradeAuthorizationState;

    // Seed management
    protected SeedManager seedManager;

    // Static certificate keys.
    protected ECPrivateKey certificatePrivateKey;
    protected ECPublicKey certificatePublicKey;
    protected ECPrivateKey issuerKey;
    protected byte[] hwStaticCertificatePublicKey;
    protected short[] hwStaticCertificatePublicKeyLength;

    // Secure channels (GP + Ledger)
    protected SecureChannel secureChannel;
    protected CapsuleCBC capsule;

    // Crypto utility
    protected CryptoUtil crypto;

    // Certificate management
    protected CertificatePKI cardCertificatePKI;
    protected EphemeralCertificate ephemeralCertificate;

    // State machines (life cycle and transient)
    protected AppletStateMachine appletFSM;
    protected TransientStateMachine transientFSM;

    // RAM buffer
    protected byte ramBuffer[];

    // FSM state buffer
    protected short[] stateBuffer;

    // Command processor
    private CommandProcessor commandProcessor;

    private FatalError fatalError;

    @Override
    public Element onSave() {
        // If the Lifecycle FSM state is "user personalized" (PIN and seed set) but the
        // upgrade authorization is not granted then the applet cannot be upgraded
        if (appletFSM.getCurrentState() == AppletStateMachine.STATE_USER_PERSONALIZED
                && upgradeAuthorizationState[0] != UPGRADE_AUTHORIZATION_GRANTED) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return null;
        } else {
            return UpgradeManager.createElement(Element.TYPE_SIMPLE, (short) 1, (short) 7).write(serialNumber)
                    .write(PINManager.save(this.pinManager)).write(SeedManager.save(this.seedManager)).write(certificatePrivateKey)
                    .write(certificatePublicKey).write(CertificatePKI.save(this.cardCertificatePKI)).write(this.cardNameLength)
                    .write(this.cardName);
        }
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
        if (root.canReadObject() == (short) 7) {
            serialNumber = (byte[]) root.readObject();
            PINManager pinManager = PINManager.restore((Element) root.readObject());
            if (pinManager != null) {
                this.pinManager = pinManager;
            }
            SeedManager seedManager = SeedManager.restore((Element) root.readObject());
            if (seedManager != null) {
                this.seedManager = seedManager;
            }
            certificatePrivateKey = (ECPrivateKey) root.readObject();
            certificatePublicKey = (ECPublicKey) root.readObject();
            CertificatePKI cardCertificatePKI = CertificatePKI.restore((Element) root.readObject());
            if (cardCertificatePKI != null) {
                this.cardCertificatePKI = cardCertificatePKI;
            }
            this.cardNameLength = (byte) root.readByte();
            this.cardName = (byte[]) root.readObject();
        }
    }

    @Override
    public void onConsolidate() {
        seedManager.setCryptoUtil(crypto);

        if (cardCertificatePKI.isCertificateSet()) {
            appletFSM.transition(AppletStateMachine.EVENT_SET_CERTIFICATE);
            appletFSM.transition(AppletStateMachine.EVENT_FACTORY_TESTS_PASSED);
        }
        if (seedManager.isSeedSet() && pinManager.getPINStatus() == PINManager.PIN_STATUS_ACTIVATED) {
            appletFSM.transition(AppletStateMachine.EVENT_SET_SEED);
        }
        transientFSM.setOnSelectState();
        this.enableFatalErrorHandling();
    }

    /**
     * Selects the applet. Initializes the transient state machine (in locked
     * state).
     */
    @Override
    public boolean select() {
        secureChannel = null;
        upgradeAuthorizationState[0] = UPGRADE_AUTHORIZATION_DENIED;
        transientFSM.setOnSelectState();
        // Clear PIN if personalization was not completed in the previous session
        // (PIN was set but not the seed)
        pinManager.unsetPIN();
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
     * Only this class's install method should create the applet object.
     */
    protected AppletCharon(byte[] bArray, short bOffset, byte bLength) {
        // Create the FSM
        appletFSM = new AppletStateMachine();
        transientFSM = new TransientStateMachine(appletFSM);
        secureChannel = null;
        pinManager = new PINManager();
        crypto = new CryptoUtil();
        crypto.initCurve(CryptoUtil.SECP256K1);
        seedManager = new SeedManager();
        seedManager.setCryptoUtil(crypto);
        cardCertificatePKI = new CertificatePKI();
        ephemeralCertificate = new EphemeralCertificate(crypto, CARD_CERT_ROLE);
        capsule = new CapsuleCBC();
        // Initialize Issuer key
        issuerKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, crypto.getCurve().getCurveLength(), false);
        crypto.getCurve().setCurveParameters(issuerKey);
        ramBuffer = JCSystem.makeTransientByteArray(RAM_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        stateBuffer = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        hwSerialNumber = JCSystem.makeTransientByteArray(HW_SN_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        hwStaticCertificatePublicKey = JCSystem.makeTransientByteArray(MAX_HW_PUBLIC_KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        hwStaticCertificatePublicKeyLength = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        cardName = new byte[MAX_CARD_NAME_LENGTH];
        upgradeAuthorizationState = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        commandProcessor = new CommandProcessor(this, ramBuffer, stateBuffer);
        fatalError = new FatalError(this);
        serialNumber = new byte[SN_LENGTH];

        if (UpgradeManager.isUpgrading() == false) {
            certificatePrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, crypto.getCurve().getCurveLength(),
                    false);
            certificatePublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, crypto.getCurve().getCurveLength(),
                    false);
            // Initialize the fatal error handler
            enableFatalErrorHandling();
        }
        register(bArray, ((short) (bOffset + 1)), bArray[bOffset]);
    }

    private void enableFatalErrorHandling() {
        pinManager.setFatalError(fatalError);
        seedManager.setFatalError(fatalError);
        appletFSM.setFatalError(fatalError);
        transientFSM.setFatalError(fatalError);
        fatalError.setInitDone();
    }

    public void throwFatalError() {
        try {
            // Reset card name length
            cardNameLength = 0;
            // Reset seed
            seedManager.clearSeedOnFatalError();
            // Reset PIN
            pinManager.resetPINOnFatalError();
            // Reset secure channel
            secureChannel = null;
        } catch (Exception e) {
            // Ignore all other exceptions
        } finally {
            // Reset FSM states (lifecycle : attested, transient : initialized)
            appletFSM.setStateOnFatalError();
            transientFSM.setStateOnFatalError();
            ISOException.throwIt(SW_FATAL_ERROR);
        }
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

    public void processData(byte[] baBuffer, short sOffset, short sLength) {
        short dataOffset;
        short dataLength;
        byte tlvTag;
        byte tlvLength;
        byte securityLevel;
        short dgi;

        // Get current persistent and transient states
        short pState = appletFSM.getCurrentState();
        short tState = transientFSM.getCurrentState();

        // Check FSM states
        if (pState != AppletStateMachine.STATE_FABRICATION || tState != TransientStateMachine.STATE_IDLE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        secureChannel = GPSystem.getSecureChannel();
        securityLevel = secureChannel.getSecurityLevel();

        if ((securityLevel & SecureChannel.C_MAC) != SecureChannel.C_MAC) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        if (sLength < ISO7816.OFFSET_CDATA) {
            ISOException.throwIt(SW_WRONG_LENGTH);
            return;
        }

        dataOffset = (short) ISO7816.OFFSET_CDATA;
        dgi = Util.getShort(baBuffer, dataOffset);

        // Skip DGI two bytes
        dataOffset += 2;
        dataLength = (short) (sLength - ISO7816.OFFSET_CDATA - 2);

        // DGI
        switch (dgi) {
        case DGI_TAG_PRIVATE_KEY_VALUE:
            tlvLength = baBuffer[dataOffset];
            if ((securityLevel & (SecureChannel.C_MAC | SecureChannel.C_DECRYPTION)) != (SecureChannel.C_MAC
                    | SecureChannel.C_DECRYPTION)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return;
            }
            if (tlvLength != CryptoUtil.SECP256K1_PRIVATE_KEY_LEN) {
                ISOException.throwIt(SW_INCORRECT_PARAMETERS);
                return;
            }
            issuerKey.setS(baBuffer, (short) (dataOffset + 1), CryptoUtil.SECP256K1_PRIVATE_KEY_LEN);
            // Erase key value from APDU buffer
            Util.arrayFillNonAtomic(baBuffer, (short) (dataOffset + 1), (short) CryptoUtil.SECP256K1_PRIVATE_KEY_LEN, (byte) 0xFF);
            break;

        case DGI_TAG_PUBLIC_KEY_VALUE:
            tlvLength = baBuffer[dataOffset];
            if ((securityLevel & (SecureChannel.C_MAC | SecureChannel.C_DECRYPTION)) != (SecureChannel.C_MAC
                    | SecureChannel.C_DECRYPTION)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return;
            }
            if (tlvLength != CryptoUtil.SECP256K1_PUBLIC_KEY_LEN) {
                ISOException.throwIt(SW_INCORRECT_PARAMETERS);
                return;
            }
            cardCertificatePKI.setIssuerPublicKey(baBuffer, (short) (dataOffset + 1), CryptoUtil.SECP256K1_PUBLIC_KEY_LEN);
            // Erase key value from APDU buffer
            Util.arrayFillNonAtomic(baBuffer, (short) (dataOffset + 1), (short) CryptoUtil.SECP256K1_PUBLIC_KEY_LEN, (byte) 0xFF);
            break;

        case DGI_TAG_KEY_CRT:
            while (dataLength > 0) {
                // At least the 'TL' bytes of the 'TLV'
                if (dataLength < 2) {
                    ISOException.throwIt(SW_INCORRECT_PARAMETERS);
                    return;
                }

                tlvTag = baBuffer[(short) dataOffset];
                tlvLength = baBuffer[(short) (dataOffset + 1)];

                // Check if 'L' value is consistent with remaining data length
                if ((tlvLength + 2) > dataLength) {
                    ISOException.throwIt(SW_INCORRECT_PARAMETERS);
                    return;
                }

                // Check length
                if (tlvLength != TAG_KEY_PARAM_LENGTH) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }

                switch (tlvTag) {
                case TAG_KEY_USAGE:
                    if ((baBuffer[(short) (dataOffset + 2)] != KEY_USAGE_SIGNATURE)
                            && (baBuffer[(short) (dataOffset + 2)] != KEY_USAGE_VERIFICATION)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }
                    break;

                case TAG_KEY_TYPE:
                    if ((baBuffer[(short) (dataOffset + 2)] != KEY_TYPE_PRIVATE_ECC)
                            && (baBuffer[(short) (dataOffset + 2)] != KEY_TYPE_PUBLIC_ECC)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }
                    break;

                case TAG_KEY_LENGTH:
                    if ((baBuffer[(short) (dataOffset + 2)] != CryptoUtil.SECP256K1_PRIVATE_KEY_LEN)
                            && (baBuffer[(short) (dataOffset + 2)] != CryptoUtil.SECP256K1_PUBLIC_KEY_LEN)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }
                    break;

                case TAG_KEY_ID:
                    if (baBuffer[(short) (dataOffset + 2)] != CryptoUtil.SECP256K1) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }
                    break;

                case TAG_KEY_VERSION:
                    if ((baBuffer[(short) (dataOffset + 2)] != KEY_VERSION_01) && (baBuffer[(short) (dataOffset + 2)] != KEY_VERSION_11)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }
                    break;

                default:
                    // Tag not found
                    ISOException.throwIt((short) (tlvTag));
                    return;
                }
                // Compute new remaining length after processing the current TLV
                dataLength = (short) (dataLength - 2 - tlvLength);
                dataOffset = (short) (dataOffset + 2 + tlvLength);
            }
            break;

        case (short) GET_STATUS_SERIAL_NUMBER_TAG:
            tlvLength = baBuffer[dataOffset];
            if ((securityLevel & (SecureChannel.C_MAC | SecureChannel.C_DECRYPTION)) != (SecureChannel.C_MAC
                    | SecureChannel.C_DECRYPTION)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return;
            }
            if (tlvLength != SN_LENGTH) {
                ISOException.throwIt(SW_INCORRECT_PARAMETERS);
                return;
            }
            Util.arrayCopy(baBuffer, (short) (dataOffset + 1), serialNumber, (short) 0, SN_LENGTH);
            break;

        default:
            ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
            return;
        }
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

        // Check if the APDU is a Ledger command
        if (buffer[ISO7816.OFFSET_CLA] != LEDGER_COMMAND_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Check if the instruction is GET_STATUS before checking the security level
        if (buffer[ISO7816.OFFSET_INS] != INS_GET_STATUS) {
            // For any other command than GP commands and GET_STATUS, check the security
            // level
            if (!checkSecurityLevel()) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }

        // Use GP API to unwrap data from secure channel.
        try {
            if (cdatalength > 0) {
                buffer[ISO7816.OFFSET_CLA] = GP_CLA_EXTERNAL_AUTHENTICATE;
                cdatalength = secureChannel.unwrap(buffer, (short) 0, (short) (cdatalength + APDU_HEADER_SIZE));
                buffer[ISO7816.OFFSET_CLA] = LEDGER_COMMAND_CLA;
            }
        } catch (Exception e) {
            ISOException.throwIt((short) SW_INCORRECT_SCP03);
        }

        // Get current persistent state
        stateBuffer[0] = appletFSM.getCurrentState();
        stateBuffer[1] = transientFSM.getCurrentState();

        cdatalength = commandProcessor.processCommand(buffer, cdatalength);

        // Add status word before wrapping response buffer
        buffer[(short) (cdatalength)] = (byte) 0x90;
        buffer[(short) (cdatalength + 1)] = (byte) 0x00;
        cdatalength += 2;
        // Wrap buffer with secure channel
        if (secureChannel != null) {
            cdatalength = secureChannel.wrap(buffer, (short) 0, cdatalength);
        }
        // Send the response
        apdu.setOutgoingAndSend((short) 0, cdatalength);
    }

}
