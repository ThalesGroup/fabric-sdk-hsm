/*
 *  Copyright (C) 2018 SafeNet. All rights reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdkintegration;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.HashMap;
import java.util.Map;

import com.safenetinc.luna.provider.key.LunaKey;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

/**
 * A local file-based key value store with private keys in an HSM.
 */
public class SampleHSMStore extends SampleStore implements Serializable {

    private transient KeyStore keyStore;

    private final Map<String, SampleUser> members = new HashMap<>();

    public SampleHSMStore(File file) {
        super(file);
    }

    /**
     * Loads a LunaKeyStore for the given tokenLabel and authenticates to the HSM using given password
     *
     * @param tokenLabel
     * @param password
     */
    public void loadKeyStore(String tokenLabel, String password) {
        try {
            ByteArrayInputStream is1 = new ByteArrayInputStream(("tokenlabel:" + tokenLabel).getBytes());
            keyStore = KeyStore.getInstance("Luna");
            keyStore.load(is1, password.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the user with a given name
     *
     * @param name
     * @param org
     * @param mspId
     * @param certificateFile
     * @return user
     * @throws IOException
     */
    public SampleUser getMember(String name, String org, String mspId, File certificateFile) throws IOException {
        // Try to get the SampleUser state from the cache
        SampleUser sampleUser = members.get(SampleUser.toKeyValStoreName(name, org));
        if (null != sampleUser) {
            return sampleUser;
        }

        // Create the SampleUser and try to restore it's state from the key value store (if found).
        sampleUser = new SampleUser(name, org, this, null);
        sampleUser.setMspId(mspId);

        String certificate = new String(IOUtils.toByteArray(new FileInputStream(certificateFile)), "UTF-8");
        sampleUser.setEnrollment(new SampleHSMStoreEnrollment(certificate, null));
        sampleUser.saveState();

        return sampleUser;
    }

    /**
     * Sets the enrollment for the user as a SampleHSMStoreEnrollement
     *
     * @param user
     * @param enrollment
     * @param persistPrivateKeyInHSM if this is true, the key will be persisted as a token object in the HSM
     */
    public void setUserSampleHSMStoreEnrollment(SampleUser user, Enrollment enrollment, boolean persistPrivateKeyInHSM) {
        String certificate = enrollment.getCert();
        if (persistPrivateKeyInHSM) {
            try {
                byte[] ski = getSKIFromCertificate(certificate);
                String alias = Hex.toHexString(ski);
                LunaKey privateKey = (LunaKey) enrollment.getKey();
                privateKey.MakePersistent(alias);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        user.setEnrollment(new SampleHSMStoreEnrollment(certificate, enrollment.getKey()));
    }

    class SampleHSMStoreEnrollment implements Enrollment, Serializable {

        private static final long serialVersionUID = -2784835212445309006L;
        private transient PrivateKey privateKey;
        private final String certificate;

        SampleHSMStoreEnrollment(String certificate, PrivateKey privateKey) {
            this.certificate = certificate;
            this.privateKey = privateKey;
        }

        @Override
        public PrivateKey getKey() {
            if (privateKey != null) {
                return privateKey;
            }
            try {
                byte[] ski = getSKIFromCertificate(certificate);
                String alias = Hex.toHexString(ski);
                privateKey = (PrivateKey) keyStore.getKey(alias, null);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return privateKey;
        }

        @Override
        public String getCert() {
            return certificate;
        }

    }

    public static byte[] getUncompressedECPoint(ECPublicKey publicKey, ECPoint point) {
        int keySizeBytes = (publicKey.getParams().getOrder().bitLength() + Byte.SIZE - 1) / Byte.SIZE;
        final byte[] uncompressedPoint = new byte[1 + 2 * keySizeBytes];
        int offset = 0;
        uncompressedPoint[offset++] = 0x04;
        byte[] x = point.getAffineX().toByteArray();
        if (x.length <= keySizeBytes) {
            System.arraycopy(x, 0, uncompressedPoint, offset + keySizeBytes - x.length, x.length);
        } else if (x.length == keySizeBytes + 1 && x[0] == 0) {
            System.arraycopy(x, 1, uncompressedPoint, offset, keySizeBytes);
        }
        offset += keySizeBytes;

        byte[] y = point.getAffineY().toByteArray();
        if (y.length <= keySizeBytes) {
            System.arraycopy(y, 0, uncompressedPoint, offset + keySizeBytes - y.length, y.length);
        } else if (y.length == keySizeBytes + 1 && y[0] == 0) {
            System.arraycopy(y, 1, uncompressedPoint, offset, keySizeBytes);
        }
        return uncompressedPoint;
    }

    public static byte[] getSKIFromCertificate(String certString) throws Exception {
        CryptoPrimitives cryptoPrimitives = (CryptoPrimitives) CryptoSuite.Factory.getCryptoSuite();
        X509Certificate cert = (X509Certificate) cryptoPrimitives.bytesToCertificate(certString.getBytes());
        ECPublicKey publicKey = (ECPublicKey) cert.getPublicKey();
        ECPoint point = publicKey.getW();

        byte[] uncompressedPoint = getUncompressedECPoint(publicKey, point);

        MessageDigest digest = MessageDigest.getInstance("SHA256");
        digest.update(uncompressedPoint);
        byte[] ski = digest.digest();
        return ski;
    }

}