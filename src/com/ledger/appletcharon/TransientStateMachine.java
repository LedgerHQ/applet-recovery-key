package com.ledger.appletcharon;

// Class that manages the transient states of the applet,
// The transient state machine is instantiated when a select
// command is received and is cleared when the applet is deselected.
//
// When instantiated, the state machine is in the locked state, then
// it can transition to the authenticated state if the certificate from
// the host is valid, and finally to the unlocked state if the user
// enters the correct PIN.
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
        currentState = STATE_IDLE;
    }

    public void setOnSelectState() {
        if (appletStateMachine.getCurrentState() == AppletStateMachine.STATE_FABRICATION) {
            currentState = STATE_IDLE;
        } else if (appletStateMachine.getCurrentState() == AppletStateMachine.STATE_ATTESTED) {
            currentState = STATE_INITIALIZED;
        } else {
            currentState = STATE_PIN_LOCKED;
        }
    }

    public void transition(byte event) {
        switch (currentState) {
        case STATE_IDLE:
            if (event == EVENT_SET_CERTIFICATE) {
                currentState = STATE_INITIALIZED;
            }
            break;
        case STATE_INITIALIZED:
            if (event == EVENT_CERT_VALID) {
                currentState = STATE_AUTHENTICATED;
            }
            break;
        case STATE_PIN_LOCKED:
            if (event == EVENT_CERT_VALID) {
                currentState = STATE_AUTHENTICATED;
            }
        case STATE_AUTHENTICATED:
            if (event == EVENT_PIN_VERIFIED) {
                currentState = STATE_PIN_UNLOCKED;
            } else if (event == EVENT_PIN_TRY_LIMIT_EXCEEDED) {
                currentState = STATE_INITIALIZED;
            }
            break;
        case STATE_PIN_UNLOCKED:
            if (event == EVENT_APPLET_DESELECTED) {
                if (appletStateMachine.getCurrentState() == AppletStateMachine.STATE_USER_PERSONALIZED) {
                    currentState = STATE_PIN_LOCKED;
                } else {
                    currentState = STATE_INITIALIZED;
                }
            } else if (event == EVENT_FACTORY_RESET) {
                currentState = STATE_INITIALIZED;
            }
            break;
        }
    }

    public byte getCurrentState() {
        return currentState;
    }
}