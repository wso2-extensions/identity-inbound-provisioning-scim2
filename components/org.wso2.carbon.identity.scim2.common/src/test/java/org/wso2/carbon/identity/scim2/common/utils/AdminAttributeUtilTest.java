/*
 * Copyright (c) 2017-2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.utils;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.stratos.common.util.ClaimsMgtUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Map;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

public class AdminAttributeUtilTest {

    @Mock
    RealmService realmService;

    @Mock
    UserRealm userRealm;

    @Mock
    UserStoreManager userStoreManager;

    AdminAttributeUtil adminAttributeUtil;

    private MockedStatic<SCIMCommonComponentHolder> scimCommonComponentHolder;
    private MockedStatic<ClaimsMgtUtil> claimsMgtUtil;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        adminAttributeUtil = new AdminAttributeUtil();
        scimCommonComponentHolder = mockStatic(SCIMCommonComponentHolder.class);
        claimsMgtUtil = mockStatic(ClaimsMgtUtil.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        scimCommonComponentHolder.close();
        claimsMgtUtil.close();
        identityTenantUtil.close();
    }

    @DataProvider(name = "testUpdateAdminUserData")
    public Object[][] testUpdateAdminUserData() {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "testUpdateAdminUserData")
    public void testUpdateAdminUser(boolean validateSCIMID) throws Exception {
        String adminUsername = "admin";

        scimCommonComponentHolder.when(() -> SCIMCommonComponentHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isSCIMEnabled()).thenReturn(true);
        claimsMgtUtil.when(() -> ClaimsMgtUtil.getAdminUserNameFromTenantId(eq(realmService), anyInt())).thenReturn(adminUsername);
        identityTenantUtil.when(() -> IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(userStoreManager.getUserClaimValue(anyString(), anyString(), anyString())).thenReturn("");

        ArgumentCaptor<Map> argument = ArgumentCaptor.forClass(Map.class);
        adminAttributeUtil.updateAdminUser(1, validateSCIMID);
        verify(userStoreManager).setUserClaimValues(anyString(), argument.capture(), anyString());
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testUpdateAdminUser1() throws Exception {
        scimCommonComponentHolder.when(() -> SCIMCommonComponentHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());

        adminAttributeUtil.updateAdminUser(1, true);
        verify(userStoreManager.isSCIMEnabled());
    }
}
