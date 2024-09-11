package com.ledger.appletcharon;

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
    // Constants for states
    public static final byte STATE_LOCKED = 0;
    public static final byte STATE_AUTHENTICATED = 1;
    public static final byte STATE_UNLOCKED = 2;

    // Constants for events
    public static final byte EVENT_CERT_VALID = 0;
    public static final byte EVENT_PIN_VERIFIED = 1;

    private byte[] currentState;

    public TransientStateMachine() {
        currentState = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        currentState[0] = STATE_LOCKED;
    }

    public void transition(byte event) {
        switch (currentState[0]) {
        case STATE_LOCKED:
            if (event == EVENT_CERT_VALID) {
                currentState[0] = STATE_AUTHENTICATED;
            }
            break;
        case STATE_AUTHENTICATED:
            if (event == EVENT_PIN_VERIFIED) {
                currentState[0] = STATE_UNLOCKED;
            }
            break;
        case STATE_UNLOCKED:
            // No transitions from unlocked state
            // The transient state machine is instantiated
            // when a select command is received
            // and is cleared when the applet is deselected.
            break;
        }
    }

    public byte getCurrentState() {
        return currentState[0];
    }
}