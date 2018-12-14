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

import com.safenetinc.luna.provider.LunaProvider;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.junit.Test;

import java.nio.file.Paths;
import java.security.Security;
import java.util.Properties;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Test end to end scenario with private keys in a SafeNet HSM.
 */
public class End2endHSMIT extends End2endIT {

    private static final String TOKEN_LABEL = "fabric-sdk";
    private static final String PARTITION_PASSWORD = "userpin";

    static
    {
        Security.addProvider(new LunaProvider());
        System.setProperty(Config.SECURITY_PROVIDER_CLASS_NAME, "com.safenetinc.luna.provider.LunaProvider");
    }

    {
        testName = "End2endHSMIT";
    }

    private static final TestConfig testConfig = TestConfig.getConfig();

    @Test
    public void setup() throws Exception {
        if (sampleStoreFile.exists()) {
            sampleStoreFile.delete();
        }

        sampleStore = new SampleHSMStore(sampleStoreFile);

        ((SampleHSMStore) sampleStore).loadKeyStore(TOKEN_LABEL, PARTITION_PASSWORD);

        enrollUsersSetup(sampleStore);
        runFabricTest(sampleStore);
    }


    /**
     * Will register and enroll users persisting them to samplestore.
     *
     * @param sampleStore
     * @throws Exception
     */
    public void enrollUsersSetup(SampleStore sampleStore) throws Exception {

        SampleHSMStore sampleHSMStore = (SampleHSMStore) sampleStore;

        out("***** Enrolling Users *****");
        for (SampleOrg sampleOrg : testConfig.getIntegrationTestsSampleOrgs()) {

            HFCAClient ca = sampleOrg.getCAClient();

            final String orgName = sampleOrg.getName();
            final String mspid = sampleOrg.getMSPID();
            ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            if (testConfig.isRunningFabricTLS()) {
                final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
                enrollmentRequestTLS.addHost("localhost");
                enrollmentRequestTLS.setProfile("tls");
                final Enrollment enroll = ca.enroll("admin", "adminpw", enrollmentRequestTLS);
                final String tlsCertPEM = enroll.getCert();
                final String tlsKeyPEM = getPEMStringFromPrivateKey(enroll.getKey());

                final Properties tlsProperties = new Properties();

                tlsProperties.put("clientKeyBytes", tlsKeyPEM.getBytes(UTF_8));
                tlsProperties.put("clientCertBytes", tlsCertPEM.getBytes(UTF_8));
                clientTLSProperties.put(sampleOrg.getName(), tlsProperties);

                sampleHSMStore.storeClientPEMTLCertificate(sampleOrg, tlsCertPEM);
                sampleHSMStore.storeClientPEMTLSKey(sampleOrg, tlsKeyPEM);
            }

            HFCAInfo info = ca.info();
            assertNotNull(info);
            String infoName = info.getCAName();
            if (infoName != null && !infoName.isEmpty()) {
                assertEquals(ca.getCAName(), infoName);
            }

            SampleUser admin = sampleHSMStore.getMember(TEST_ADMIN_NAME, orgName);
            if (!admin.isEnrolled()) {
                Enrollment enrollment = ca.enroll(admin.getName(), "adminpw");
                sampleHSMStore.setUserSampleHSMStoreEnrollment(admin, enrollment, false);
                admin.setMspId(mspid);
            }

            SampleUser user = sampleHSMStore.getMember(testUser1, sampleOrg.getName());
            if (!user.isRegistered()) {
                RegistrationRequest rr = new RegistrationRequest(user.getName(), "org1.department1");
                user.setEnrollmentSecret(ca.register(rr, admin));
            }
            if (!user.isEnrolled()) {
                Enrollment enrollment = ca.enroll(user.getName(), user.getEnrollmentSecret());
                sampleHSMStore.setUserSampleHSMStoreEnrollment(user, enrollment, false);
                user.setMspId(mspid);
            }

            final String sampleOrgName = sampleOrg.getName();
            final String sampleOrgDomainName = sampleOrg.getDomainName();

            SampleUser peerOrgAdmin = sampleHSMStore.getMember(sampleOrgName + "Admin", sampleOrgName, sampleOrg.getMSPID(),
                    Paths.get(testConfig.getTestChannelPath(), "crypto-config/peerOrganizations/", sampleOrgDomainName,
                            format("/users/Admin@%s/msp/signcerts/Admin@%s-cert.pem", sampleOrgDomainName, sampleOrgDomainName)).toFile());

            sampleOrg.setPeerAdmin(peerOrgAdmin);

            sampleOrg.addUser(user);
            sampleOrg.setAdmin(admin);
        }
    }

}
