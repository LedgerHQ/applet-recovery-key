package com.ledger.appletcharon;

import static com.ledger.appletcharon.Constants.SW_FATAL_ERROR_DURING_INIT;

import javacard.framework.ISOException;

public class FatalError {
    private AppletCharon applet;
    private boolean initDone;

    public FatalError(AppletCharon applet) {
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
