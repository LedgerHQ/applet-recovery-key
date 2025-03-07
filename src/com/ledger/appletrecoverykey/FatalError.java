package com.ledger.appletrecoverykey;

import static com.ledger.appletrecoverykey.Constants.SW_FATAL_ERROR_DURING_INIT;

import javacard.framework.ISOException;

public class FatalError {
    private AppletRecoveryKey applet;
    private boolean initDone;

    public FatalError(AppletRecoveryKey applet) {
        this.applet = applet;
        initDone = false;
    }

    public void throwIt() {
        if (!initDone) {
            ISOException.throwIt(SW_FATAL_ERROR_DURING_INIT);
        } else {
            applet.throwFatalError();
        }
    }

    public void setInitDone() {
        this.initDone = true;
    }

}
