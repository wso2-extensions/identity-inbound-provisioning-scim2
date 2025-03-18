/*
 * Copyright (c) 2017, WSO2 LLC. (http://www.wso2.org)
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.impl;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.testng.annotations.Listeners;
import org.mockito.testng.MockitoTestNGListener;
import org.wso2.carbon.identity.scim2.common.internal.component.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.test.utils.CommonTestUtils;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.scim2.common.utils.SCIMConfigProcessor;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.extensions.UserManager;

import java.nio.file.Paths;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyInt;

/**
 * Contains the unit test cases for IdentitySCIMManager.
 */
@Listeners(MockitoTestNGListener.class)
public class IdentitySCIMManagerTest {

    @Mock
    RealmService realmService;

    @Mock
    TenantManager mockedTenantManager;

    @Mock
    UserRealm mockedUserRealm;

    private SCIMConfigProcessor scimConfigProcessor;
    private IdentitySCIMManager identitySCIMManager;

    private MockedStatic<SCIMCommonUtils> scimCommonUtils;
    private MockedStatic<SCIMCommonComponentHolder> scimCommonComponentHolder;

    @BeforeMethod
    public void setUp() throws Exception {
        scimCommonUtils = mockStatic(SCIMCommonUtils.class);
        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMUserURL()).thenReturn("http://scimUserUrl:9443");

        scimCommonComponentHolder = mockStatic(SCIMCommonComponentHolder.class);
        scimConfigProcessor = SCIMConfigProcessor.getInstance();
        String filePath = Paths
                .get(System.getProperty("user.dir"), "src", "test", "resources", "charon-config-test.xml").toString();
        scimConfigProcessor.buildConfigFromFile(filePath);
        identitySCIMManager = IdentitySCIMManager.getInstance();

        CommonTestUtils.initPrivilegedCarbonContext();
    }

    @AfterMethod
    public void tearDown() {
        scimCommonComponentHolder.close();
        scimCommonUtils.close();
    }

    @Test
    public void testGetInstance() throws Exception {

        assertNotNull(identitySCIMManager, "Returning a null");
        assertNotNull(identitySCIMManager, "Returning a null");
    }

    @Test
    public void testGetEncoder() throws Exception {

        assertNotNull(identitySCIMManager.getEncoder());
    }

    @Test
    public void testGetUserManager() throws Exception {

        when(SCIMCommonComponentHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(mockedUserRealm);
        UserManager userManager = identitySCIMManager.getUserManager();
        assertNotNull(userManager);
    }

    @Test
    public void testGetUserManagerWithException() throws Exception {

        try {
            when(SCIMCommonComponentHolder.getRealmService()).thenReturn(null);
            identitySCIMManager.getUserManager();
            fail("getUserManager() method should have thrown a CharonException");
        } catch (CharonException e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testGetUserManagerWithException2() throws Exception {

        when(SCIMCommonComponentHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getTenantId(anyString())).thenThrow(new UserStoreException());

        try {
            identitySCIMManager.getUserManager();
            fail("getUserManager() method should have thrown a CharonException");
        } catch (CharonException e) {
            assertNotNull(e);
        }
    }
}
