package com.ledger.appletcharon;

// Class that manages the transient states of the applet,
// The transient state machine is instantiated when a select
// command is received and is cleared when the applet is deselected.
//
// When instantiated, the state machine is in the locked state, then
// it can transition to the authenticated state if the certificate from
// the host is valid, and finally to the unlocked state if the user
// enters the correct PIN.
import static com.ledger.appletcharon.AppletCharon.staticThrowFatalError;

import javacard.framework.JCSystem;

public class TransientStateMachine {
    // Constants for states
    public static final byte STATE_IDLE = 0;
    public static final byte STATE_INITIALIZED = 1;
    public static final byte STATE_PIN_LOCKED = 2;
    public static final byte STATE_AUTHENTICATED = 3;
    public static final byte STATE_PIN_UNLOCKED = 4;

    // Constants for events
    public static final byte EVENT_SET_CERTIFICATE = 0;
    public static final byte EVENT_CERT_VALID = 1;
    public static final byte EVENT_PIN_VERIFIED = 2;
    public static final byte EVENT_PIN_TRY_LIMIT_EXCEEDED = 2;
    public static final byte EVENT_APPLET_DESELECTED = 3;
    public static final byte EVENT_FACTORY_RESET = 4;

    private byte currentState;
    private AppletStateMachine appletStateMachine;

    public TransientStateMachine(AppletStateMachine appletStateMachine) {
        this.appletStateMachine = appletStateMachine;
        setCurrentState(STATE_IDLE);
    }

    private boolean isValidState(byte state) {
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
            staticThrowFatalError();
        }
    }

    public void setOnSelectState() {
        byte newState;
        byte appletState = appletStateMachine.getCurrentState();

        if (appletState == AppletStateMachine.STATE_FABRICATION) {
            newState = STATE_IDLE;
        } else if (appletState == AppletStateMachine.STATE_ATTESTED) {
            newState = STATE_INITIALIZED;
        } else {
            newState = STATE_PIN_LOCKED;
        }

        setCurrentState(newState);
    }

    public void transition(byte event) {
        byte newState = currentState;

        switch (currentState) {
        case STATE_IDLE:
            if (event == EVENT_SET_CERTIFICATE) {
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
        currentState = STATE_INITIALIZED;
    }
}