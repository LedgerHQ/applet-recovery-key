package com.ledger.appletcharon;

public class AppletStateMachine {
    // Constants for states
    public static final byte STATE_FABRICATION = 0;
    public static final byte STATE_ATTESTED = 1;
    public static final byte STATE_USER_PERSONALIZED = 2;

    // Constants for events
    public static final byte EVENT_SET_CERTIFICATE = 0;
    public static final byte EVENT_CREATE_BACKUP = 1;

    private byte currentState;

    public AppletStateMachine() {
        currentState = STATE_FABRICATION;
    }

    public void transition(byte event) {
        switch (currentState) {
        case STATE_FABRICATION:
            if (event == EVENT_SET_CERTIFICATE) {
                currentState = STATE_ATTESTED;
            }
            break;
        case STATE_ATTESTED:
            if (event == EVENT_CREATE_BACKUP) {
                currentState = STATE_USER_PERSONALIZED;
            }
            break;
        case STATE_USER_PERSONALIZED:
            // No transitions from user personalized state yet...
            // Maybe the FSM should go back to attested if the user
            // enters too many wrong PINs or go to a new blocked state.
            break;
        }
    }

    public byte getCurrentState() {
        return currentState;
    }
}