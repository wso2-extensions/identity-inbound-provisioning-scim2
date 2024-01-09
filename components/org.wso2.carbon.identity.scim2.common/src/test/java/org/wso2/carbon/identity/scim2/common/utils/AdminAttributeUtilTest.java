/*
 * Copyright (c) 2017, WSO2 LLC. (http://www.wso2.org).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.scim2.common.utils;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.stratos.common.util.ClaimsMgtUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Map;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({SCIMCommonComponentHolder.class, ClaimsMgtUtil.class, IdentityTenantUtil.class, UserCoreUtil.class,
        IdentityUtil.class, SCIMCommonUtils.class, AdminAttributeUtil.class})
public class AdminAttributeUtilTest extends PowerMockTestCase {

    @Mock
    RealmService realmService;

    @Mock
    UserRealm userRealm;

    @Mock
    UserStoreManager userStoreManager;

    AdminAttributeUtil adminAttributeUtil;

    @BeforeMethod
    public void setUp() throws Exception {
        adminAttributeUtil = new AdminAttributeUtil();
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

        mockStatic(SCIMCommonComponentHolder.class);
        mockStatic(ClaimsMgtUtil.class);
        mockStatic(IdentityTenantUtil.class);
        when(SCIMCommonComponentHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isSCIMEnabled()).thenReturn(true);
        when(ClaimsMgtUtil.getAdminUserNameFromTenantId(eq(realmService), anyInt())).thenReturn(adminUsername);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(userStoreManager.getUserClaimValue(anyString(), anyString(), anyString())).thenReturn("");

        ArgumentCaptor<Map> argument = ArgumentCaptor.forClass(Map.class);
        adminAttributeUtil.updateAdminUser(1, validateSCIMID);
        verify(userStoreManager).setUserClaimValues(anyString(), argument.capture(), anyString());
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testUpdateAdminUser1() throws Exception {
        mockStatic(SCIMCommonComponentHolder.class);
        mockStatic(ClaimsMgtUtil.class);
        mockStatic(IdentityTenantUtil.class);
        when(SCIMCommonComponentHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());

        adminAttributeUtil.updateAdminUser(1, true);
        verify(userStoreManager.isSCIMEnabled());
    }
}
