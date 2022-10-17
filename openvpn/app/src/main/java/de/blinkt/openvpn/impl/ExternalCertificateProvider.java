/*
 * Copyright (c) 2012-2022 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.impl;

import android.os.Bundle;

public interface ExternalCertificateProvider {

    byte[] getSignedData(String alias, byte[] data);

    byte[] getCertificateChain(String alias);

    Bundle getCertificateMetaData(String alias);

    byte[] getSignedDataWithExtra(String alias, byte[] data, Bundle extra);
}
