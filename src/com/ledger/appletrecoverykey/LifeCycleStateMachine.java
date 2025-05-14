/**
 * SPDX-FileCopyrightText: © 2024 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

package com.ledger.appletrecoverykey;

import static com.ledger.appletrecoverykey.Constants.SW_FATAL_ERROR_DURING_INIT;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class LifeCycleStateMachine {
    // Constants for states returned by GET STATUS
    public static final byte GET_STATUS_STATE_FABRICATION = 0;
    public static final byte GET_STATUS_STATE_PENDING_TESTS = 1;
    public static final byte GET_STATUS_STATE_ATTESTED = 2;
    public static final byte GET_STATUS_STATE_USER_PERSONALIZED = 3;

    // Constants for states
    public static final short STATE_FABRICATION = (short) 0xCB39;
    public static final short STATE_PENDING_TESTS = (short) 0x7CA0;
    public static final short STATE_ATTESTED = (short) 0xD593;
    public static final short STATE_USER_PERSONALIZED = (short) 0xCDED;

    // Constants for events
    public static final byte EVENT_SET_CERTIFICATE = 0;
    public static final byte EVENT_FACTORY_TESTS_PASSED = 1;
    public static final byte EVENT_SET_SEED = 2;
    public static final byte EVENT_PIN_TRY_LIMIT_EXCEEDED = 3;
    public static final byte EVENT_FACTORY_RESET = 4;

    private short currentState;
    private FatalError fatalError;

    public LifeCycleStateMachine() {
        setCurrentState(STATE_FABRICATION);
    }

    private boolean isValidState(short state) {
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
            throw e;
        }
    }

    public void transition(byte event) {
        short newState = currentState;

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

    public short getCurrentState() {
        if (!isValidState(currentState)) {
            throwFatalError();
        }
        return currentState;
    }

    public byte getCurrentStateForGetStatus() {
        switch (currentState) {
        case STATE_FABRICATION:
            return GET_STATUS_STATE_FABRICATION;
        case STATE_PENDING_TESTS:
            return GET_STATUS_STATE_PENDING_TESTS;
        case STATE_ATTESTED:
            return GET_STATUS_STATE_ATTESTED;
        case STATE_USER_PERSONALIZED:
            return GET_STATUS_STATE_USER_PERSONALIZED;
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
        currentState = STATE_ATTESTED;
    }
}