package com.ledger.appletcharon;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

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
    private byte[] pinBuffer;
    private byte pinLength;

    public PINManager() {
        pin = null;
        pinBuffer = null;
        pinLength = 0;
    }

    protected void createPIN(byte[] buffer) {
        // Check if PIN is already set (either in persistent or transient memory)
        if (pin != null || pinBuffer != null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        pinLength = buffer[PIN_DATA_LENGTH_OFFSET];
        // Check that the PIN length is valid (4-8 bytes)
        if (pinLength < PIN_MIN_SIZE || pinLength > PIN_MAX_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (pinBuffer == null) {
            // Store PIN in transient memory
            pinBuffer = JCSystem.makeTransientByteArray((short) pinLength, JCSystem.CLEAR_ON_DESELECT);
        }
        // Copy PIN to transient memory
        Util.arrayCopyNonAtomic(buffer, (short) PIN_DATA_OFFSET, pinBuffer, (short) 0, pinLength);
    }

    protected boolean verifyPIN(byte[] buffer) {
        if (pin == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        pinLength = buffer[PIN_DATA_LENGTH_OFFSET];
        return pin.check(buffer, (short) PIN_DATA_OFFSET, pinLength);
    }

    protected byte getTriesRemaining() {
        if (pin == null) {
            return 0;
        }
        return pin.getTriesRemaining();
    }

    protected byte activatePIN() {
        if (pinBuffer == null || pin != null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Create the PIN
        pin = new OwnerPIN(PIN_TRY_LIMIT, pinLength);
        // Set the PIN
        pin.update(pinBuffer, (short) 0, pinLength);
        // Verify the PIN
        if (!pin.check(pinBuffer, (short) 0, pinLength)) {
            // This should not happen
            ISOException.throwIt((short) (com.ledger.appletcharon.AppletCharon.SW_PIN_COUNTER_CHANGED + pin.getTriesRemaining()));
        }
        return 0;
    }

    protected void changePIN(byte[] buffer) {
        if (pin == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        pinLength = buffer[PIN_DATA_LENGTH_OFFSET];
        if (pinLength < PIN_MIN_SIZE || pinLength > PIN_MAX_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        pin.update(buffer, (short) PIN_DATA_OFFSET, pinLength);
    }

    protected byte getPINStatus() {
        if (pin == null && pinBuffer == null) {
            return PIN_STATUS_NOT_SET;
        } else if (pin == null && pinBuffer != null && pinLength >= PIN_MIN_SIZE && pinLength <= PIN_MAX_SIZE) {
            return PIN_STATUS_SET;
        } else if (pin != null) {
            return PIN_STATUS_ACTIVATED;
        } else {
            return PIN_STATUS_INVALID;
        }
    }

    protected void clearPINFromRam() {
        if (pinBuffer != null) {
            Util.arrayFillNonAtomic(pinBuffer, (short) 0, (short) pinBuffer.length, (byte) 0);
            pinBuffer = null;
            JCSystem.requestObjectDeletion();
        }
        pinLength = 0;
    }

    protected void resetPIN() {
        pin = null;
        pinBuffer = null;
        pinLength = 0;
        JCSystem.requestObjectDeletion();
    }
}
