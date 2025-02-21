package com.ledger.appletcharon;

import static com.ledger.appletcharon.Constants.SW_FATAL_ERROR_DURING_INIT;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class AppletStateMachine {
    // Constants for states
    public static final byte STATE_FABRICATION = 0;
    public static final byte STATE_PENDING_TESTS = 1;
    public static final byte STATE_ATTESTED = 2;
    public static final byte STATE_USER_PERSONALIZED = 3;

    // Constants for events
    public static final byte EVENT_SET_CERTIFICATE = 0;
    public static final byte EVENT_FACTORY_TESTS_PASSED = 1;
    public static final byte EVENT_SET_SEED = 2;
    public static final byte EVENT_PIN_TRY_LIMIT_EXCEEDED = 3;
    public static final byte EVENT_FACTORY_RESET = 4;

    private byte currentState;
    private FatalError fatalError;

    public AppletStateMachine() {
        setCurrentState(STATE_FABRICATION);
    }

    private boolean isValidState(byte state) {
        switch (state) {
        case STATE_FABRICATION:
        case STATE_PENDING_TESTS:
        case STATE_ATTESTED:
        case STATE_USER_PERSONALIZED:
            return true;
        default:
            return false;
        }
    }

    private void setCurrentState(byte newState) {
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
            throw e;
        }
    }

    public void transition(byte event) {
        byte newState = currentState;

        switch (currentState) {
        case STATE_FABRICATION:
            if (event == EVENT_SET_CERTIFICATE) {
                newState = STATE_PENDING_TESTS;
            }
            break;
        case STATE_PENDING_TESTS:
            if (event == EVENT_FACTORY_TESTS_PASSED) {
                newState = STATE_ATTESTED;
            }
            break;
        case STATE_ATTESTED:
            if (event == EVENT_SET_SEED) {
                newState = STATE_USER_PERSONALIZED;
            }
            break;
        case STATE_USER_PERSONALIZED:
            if (event == EVENT_PIN_TRY_LIMIT_EXCEEDED || event == EVENT_FACTORY_RESET) {
                newState = STATE_ATTESTED;
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

    public byte getCurrentState() {
        if (!isValidState(currentState)) {
            throwFatalError();
        }
        return currentState;
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
        currentState = STATE_ATTESTED;
    }
}