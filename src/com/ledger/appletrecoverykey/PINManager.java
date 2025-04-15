package com.ledger.appletrecoverykey;

import static com.ledger.appletrecoverykey.Constants.SW_FATAL_ERROR_DURING_INIT;
import static com.ledger.appletrecoverykey.Constants.SW_INCORRECT_PARAMETERS;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

public class PINManager {
    private static final byte PIN_MIN_SIZE = 4;
    private static final byte PIN_MAX_SIZE = 8;
    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte PIN_DATA_LENGTH_OFFSET = 0;
    private static final byte PIN_DATA_OFFSET = 1;

    protected static final byte PIN_STATUS_NOT_SET = 0;
    protected static final byte PIN_STATUS_SET = 1;
    protected static final byte PIN_STATUS_ACTIVATED = 2;
    protected static final byte PIN_STATUS_INVALID = 3;

    private OwnerPIN pin;
    private byte pinStatus;
    private FatalError fatalError;

    public PINManager() {
        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_SIZE);
        setPinStatus(PIN_STATUS_NOT_SET);
    }

    private boolean isValidState(byte state) {
        switch (state) {
        case PIN_STATUS_NOT_SET:
        case PIN_STATUS_SET:
        case PIN_STATUS_ACTIVATED:
        case PIN_STATUS_INVALID:
            return true;
        default:
            return false;
        }
    }

    private void setPinStatus(byte status) {
        JCSystem.beginTransaction();
        try {
            if (!isValidState(status)) {
                JCSystem.abortTransaction();
                throwFatalError();
            }
            pinStatus = status;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            throwFatalError();
        }
    }

    public void createPIN(byte[] buffer) {
        if (getPINStatus() != PIN_STATUS_NOT_SET) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte pinLength = buffer[PIN_DATA_LENGTH_OFFSET];
        // Check that the PIN length is valid (4-8 bytes)
        if (pinLength < PIN_MIN_SIZE || pinLength > PIN_MAX_SIZE) {
            ISOException.throwIt(SW_INCORRECT_PARAMETERS);
        }
        pin.update(buffer, (short) PIN_DATA_OFFSET, pinLength);
        if (!pin.check(buffer, (short) PIN_DATA_OFFSET, pinLength)) {
            throwFatalError();
        }
        setPinStatus(PIN_STATUS_SET);
    }

    public boolean verifyPIN(byte[] buffer) {
        if (getPINStatus() != PIN_STATUS_ACTIVATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte pinLength = buffer[PIN_DATA_LENGTH_OFFSET];
        // Check that the PIN length is valid (4-8 bytes)
        if (pinLength < PIN_MIN_SIZE || pinLength > PIN_MAX_SIZE) {
            ISOException.throwIt(SW_INCORRECT_PARAMETERS);
        }
        return pin.check(buffer, (short) PIN_DATA_OFFSET, buffer[PIN_DATA_LENGTH_OFFSET]);
    }

    public byte getTriesRemaining() {
        if (getPINStatus() != PIN_STATUS_ACTIVATED) {
            return 0;
        }
        return pin.getTriesRemaining();
    }

    public byte activatePIN() {
        if (getPINStatus() != PIN_STATUS_SET) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        setPinStatus(PIN_STATUS_ACTIVATED);
        return 0;
    }

    public void unsetPIN() {
        if (getPINStatus() == PIN_STATUS_SET) {
            setPinStatus(PIN_STATUS_NOT_SET);
        }
    }

    public void resetPIN() {
        if (getPINStatus() != PIN_STATUS_ACTIVATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        setPinStatus(PIN_STATUS_NOT_SET);
    }

    public void setFatalError(FatalError fatalError) {
        this.fatalError = fatalError;
    }

    private void throwFatalError() {
        if (fatalError != null) {
            fatalError.throwIt();
        } else {
            ISOException.throwIt(SW_FATAL_ERROR_DURING_INIT);
        }
    }

    public void resetPINOnFatalError() {
        // !!!!! WARNING !!!!!
        // ======================================
        // This method should only be called from
        // the applet's fatal error handler.
        // ======================================
        pinStatus = PIN_STATUS_NOT_SET;
    }

    public void changePIN(byte[] buffer) {
        if (getPINStatus() != PIN_STATUS_ACTIVATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte pinLength = buffer[PIN_DATA_LENGTH_OFFSET];
        if (pinLength < PIN_MIN_SIZE || pinLength > PIN_MAX_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        pin.update(buffer, (short) PIN_DATA_OFFSET, pinLength);
    }

    public byte getPINStatus() {
        if (!isValidState(pinStatus)) {
            throwFatalError();
        }
        return pinStatus;
    }

    static Element save(PINManager pinManager) {
        if (pinManager == null || pinManager.getPINStatus() != PIN_STATUS_ACTIVATED) {
            return null;
        }
        return UpgradeManager.createElement(Element.TYPE_SIMPLE, (short) 1, (short) 1).write(pinManager.pinStatus).write(pinManager.pin);
    }

    static PINManager restore(Element element) {
        if (element == null) {
            return null;
        }
        PINManager pinManager = new PINManager();
        pinManager.pinStatus = element.readByte();
        pinManager.pin = (OwnerPIN) element.readObject();
        return pinManager;
    }
}
