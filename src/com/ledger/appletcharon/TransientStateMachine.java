package com.ledger.appletcharon;

import static com.ledger.appletcharon.Constants.SW_FATAL_ERROR_DURING_INIT;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

// Class that manages the transient states of the applet,
// The transient state machine is instantiated when a select
// command is received and is cleared when the applet is deselected.
//
// When instantiated, the state machine is in the locked state, then
// it can transition to the authenticated state if the certificate from
// the host is valid, and finally to the unlocked state if the user
// enters the correct PIN.
public class TransientStateMachine {
    // Constants for states returned by GET STATUS
    public static final byte GET_STATUS_STATE_IDLE = 0;
    public static final byte GET_STATUS_STATE_INITIALIZED = 1;
    public static final byte GET_STATUS_STATE_PIN_LOCKED = 2;
    public static final byte GET_STATUS_STATE_AUTHENTICATED = 3;
    public static final byte GET_STATUS_STATE_PIN_UNLOCKED = 4;

    // Constants for states
    public static final short STATE_IDLE = (short) 0xF8A5;
    public static final short STATE_INITIALIZED = (short) 0x8F45;
    public static final short STATE_PIN_LOCKED = (short) 0x5EE5;
    public static final short STATE_AUTHENTICATED = (short) 0x1D39;
    public static final short STATE_PIN_UNLOCKED = (short) 0x6DC2;

    // Constants for events
    public static final byte EVENT_SET_CERTIFICATE_AND_TESTS_PASSED = 0;
    public static final byte EVENT_CERT_VALID = 1;
    public static final byte EVENT_PIN_VERIFIED = 2;
    public static final byte EVENT_PIN_TRY_LIMIT_EXCEEDED = 3;
    public static final byte EVENT_APPLET_DESELECTED = 4;
    public static final byte EVENT_FACTORY_RESET = 5;

    private short currentState;
    private AppletStateMachine appletStateMachine;
    private FatalError fatalError;

    public TransientStateMachine(AppletStateMachine appletStateMachine) {
        this.appletStateMachine = appletStateMachine;
        setCurrentState(STATE_IDLE);
    }

    private boolean isValidState(short state) {
        switch (state) {
        case STATE_IDLE:
        case STATE_INITIALIZED:
        case STATE_PIN_LOCKED:
        case STATE_AUTHENTICATED:
        case STATE_PIN_UNLOCKED:
            return true;
        default:
            return false;
        }
    }

    private void setCurrentState(short newState) {
        JCSystem.beginTransaction();
        try {
            if (!isValidState(newState)) {
                JCSystem.abortTransaction();
                throwFatalError();
            }
            currentState = newState;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            throwFatalError();
        }
    }

    public void setOnSelectState() {
        short newState;
        short appletState = appletStateMachine.getCurrentState();

        if (appletState == AppletStateMachine.STATE_FABRICATION || appletState == AppletStateMachine.STATE_PENDING_TESTS) {
            newState = STATE_IDLE;
        } else if (appletState == AppletStateMachine.STATE_ATTESTED) {
            newState = STATE_INITIALIZED;
        } else {
            newState = STATE_PIN_LOCKED;
        }

        setCurrentState(newState);
    }

    public void transition(byte event) {
        short newState = currentState;

        switch (currentState) {
        case STATE_IDLE:
            if (event == EVENT_SET_CERTIFICATE_AND_TESTS_PASSED) {
                newState = STATE_INITIALIZED;
            }
            break;

        case STATE_INITIALIZED:
            if (event == EVENT_CERT_VALID) {
                newState = STATE_AUTHENTICATED;
            }
            break;

        case STATE_PIN_LOCKED:
            if (event == EVENT_CERT_VALID) {
                newState = STATE_AUTHENTICATED;
            }
            break;

        case STATE_AUTHENTICATED:
            if (event == EVENT_PIN_VERIFIED) {
                newState = STATE_PIN_UNLOCKED;
            } else if (event == EVENT_PIN_TRY_LIMIT_EXCEEDED) {
                newState = STATE_INITIALIZED;
            }
            break;

        case STATE_PIN_UNLOCKED:
            if (event == EVENT_APPLET_DESELECTED) {
                if (appletStateMachine.getCurrentState() == AppletStateMachine.STATE_USER_PERSONALIZED) {
                    newState = STATE_PIN_LOCKED;
                } else {
                    newState = STATE_INITIALIZED;
                }
            } else if (event == EVENT_FACTORY_RESET) {
                newState = STATE_INITIALIZED;
            }
            break;
        default:
            throwFatalError();
            break;
        }

        if (newState != currentState) {
            setCurrentState(newState);
        }
    }

    public short getCurrentState() {
        if (!isValidState(currentState)) {
            throwFatalError();
        }
        return currentState;
    }

    public byte getCurrentStateForGetStatus() {
        switch (currentState) {
        case STATE_IDLE:
            return GET_STATUS_STATE_IDLE;
        case STATE_INITIALIZED:
            return GET_STATUS_STATE_INITIALIZED;
        case STATE_PIN_LOCKED:
            return GET_STATUS_STATE_PIN_LOCKED;
        case STATE_AUTHENTICATED:
            return GET_STATUS_STATE_AUTHENTICATED;
        case STATE_PIN_UNLOCKED:
            return GET_STATUS_STATE_PIN_UNLOCKED;
        default:
            throwFatalError();
            return -1;
        }
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

    public void setStateOnFatalError() {
        // !!!!! WARNING !!!!!
        // ======================================
        // This method should only be called from
        // the applet's fatal error handler.
        // ======================================
        currentState = STATE_INITIALIZED;
    }
}