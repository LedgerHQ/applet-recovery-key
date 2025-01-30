package com.ledger.appletcharon;

import static com.ledger.appletcharon.AppletCharon.staticThrowFatalError;

import javacard.framework.JCSystem;

public class AppletStateMachine {
    // Constants for states
    public static final byte STATE_FABRICATION = 0;
    public static final byte STATE_ATTESTED = 1;
    public static final byte STATE_USER_PERSONALIZED = 2;

    // Constants for events
    public static final byte EVENT_SET_CERTIFICATE = 0;
    public static final byte EVENT_SET_SEED = 1;
    public static final byte EVENT_PIN_TRY_LIMIT_EXCEEDED = 2;
    public static final byte EVENT_FACTORY_RESET = 3;

    private byte currentState;

    public AppletStateMachine() {
        setCurrentState(STATE_FABRICATION);
    }

    private boolean isValidState(byte state) {
        switch (state) {
        case STATE_FABRICATION:
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
                staticThrowFatalError();
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
            staticThrowFatalError();
            break;
        }

        if (newState != currentState) {
            setCurrentState(newState);
        }
    }

    public byte getCurrentState() {
        if (!isValidState(currentState)) {
            staticThrowFatalError();
        }
        return currentState;
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