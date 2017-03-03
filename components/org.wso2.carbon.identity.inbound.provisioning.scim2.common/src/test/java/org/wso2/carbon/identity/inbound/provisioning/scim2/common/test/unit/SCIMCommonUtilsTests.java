/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.inbound.provisioning.scim2.common.test.unit;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.mgt.IdentityStore;
import org.wso2.carbon.identity.mgt.exception.DomainException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.impl.Domain;
import org.wso2.carbon.identity.mgt.impl.IdentityStoreImpl;
import org.wso2.carbon.identity.mgt.impl.JDBCUniqueIdResolver;

import java.util.ArrayList;
import java.util.List;

/**
 * Unit tests for SCIM Common Utils.
 */
public class SCIMCommonUtilsTests {

    private IdentityStore identityStore;

    @BeforeMethod
    public void getIdentityStoreInstance() {

        try {
            List<Domain> domains = new ArrayList<>();
            Domain newDomain = new Domain(1, "PRIMARY", 1, new JDBCUniqueIdResolver());
            domains.add(newDomain);
            identityStore = new IdentityStoreImpl(domains);
        } catch (IdentityStoreException | DomainException e) {
            Assert.assertNotNull(identityStore, "Failed in retrieving a IdentityStore instance.");
        }
    }

    @Test
    public void testRemoveDomainFromName() {
        String domainUnawareName = SCIMCommonUtils.removeDomainFromName("PRIMARY/user1");
        Assert.assertEquals(domainUnawareName, "user1", "Failed in removing domain from the name.");
    }

    @Test
    public void testRemoveDomainFromNameWithoutDomainSeparator() {
        String domainUnawareName = SCIMCommonUtils.removeDomainFromName("user1");
        Assert.assertEquals(domainUnawareName, "user1", "Failed in removing domain from the name.");
    }

    @Test
    public void testExtractDomainFromName() {
        String domainName = null;
        try {
            domainName = SCIMCommonUtils.extractDomainFromName("PRIMARY/user1", identityStore);
        } catch (IdentityStoreException e) {
            return;
        }
        Assert.assertEquals(domainName, "PRIMARY", "Failed in extracting domain from the name.");
    }

    @Test
    public void testExtractDomainFromNameWithoutDomainSeparator() {
        String domainName = null;
        try {
            domainName = SCIMCommonUtils.extractDomainFromName("user1", identityStore);
        } catch (IdentityStoreException e) {
            return;
        }
        Assert.assertEquals(domainName, "PRIMARY", "Failed in extracting domain from the name.");
    }
}
