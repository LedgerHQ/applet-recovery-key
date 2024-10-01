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
    public static final byte STATE_LOCKED = 0;
    public static final byte STATE_AUTHENTICATED = 1;
    public static final byte STATE_UNLOCKED = 2;

    // Constants for events
    public static final byte EVENT_CERT_VALID = 0;
    public static final byte EVENT_PIN_VERIFIED = 1;
    public static final byte EVENT_APPLET_DESELECTED = 2;

    private byte currentState;

    public TransientStateMachine() {
        currentState = STATE_LOCKED;
    }

    public void transition(byte event) {
        switch (currentState) {
        case STATE_LOCKED:
            if (event == EVENT_CERT_VALID) {
                currentState = STATE_AUTHENTICATED;
            }
            break;
        case STATE_AUTHENTICATED:
            if (event == EVENT_PIN_VERIFIED) {
                currentState = STATE_UNLOCKED;
            }
            break;
        case STATE_UNLOCKED:
            if (event == EVENT_APPLET_DESELECTED) {
                currentState = STATE_LOCKED;
            }
            break;
        }
    }

    public byte getCurrentState() {
        return currentState;
    }
}