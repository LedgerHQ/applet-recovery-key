package com.ledger.appletcharon;

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
            if (event == EVENT_SET_SEED) {
                currentState = STATE_USER_PERSONALIZED;
            }
            break;
        case STATE_USER_PERSONALIZED:
            if (event == EVENT_PIN_TRY_LIMIT_EXCEEDED || event == EVENT_FACTORY_RESET) {
                currentState = STATE_ATTESTED;
            }
            break;
        }
    }

    public byte getCurrentState() {
        return currentState;
    }
}