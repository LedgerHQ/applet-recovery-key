/**
 * SPDX-FileCopyrightText: © 2024 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

package com.ledger.appletrecoverykey;

public final class Version {
    protected static final byte APPLET_MAJOR_VERSION = (byte) 0x01;
    protected static final byte APPLET_MINOR_VERSION = (byte) 0x00;
    // CAP file version format does not support patch version
    // Beware if you update the patch, it means the CAP file version (major.minor)
    // will still remain unchanged and it won't reflect the changes in the
    // applet code.
    protected static final byte APPLET_PATCH_VERSION = (byte) 0x00;
}
