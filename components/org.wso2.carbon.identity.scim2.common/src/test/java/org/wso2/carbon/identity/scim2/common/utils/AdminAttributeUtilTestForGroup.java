/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.stratos.common.util.ClaimsMgtUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

@PrepareForTest({SCIMCommonComponentHolder.class, ClaimsMgtUtil.class, IdentityTenantUtil.class, UserCoreUtil.class,
        IdentityUtil.class, SCIMCommonUtils.class, AdminAttributeUtil.class})
public class AdminAttributeUtilTestForGroup extends PowerMockTestCase {

    @Mock
    RealmService realmService;

    @Mock
    RealmConfiguration realmConfiguration;

    @Mock
    UserRealm userRealm;

    @Mock
    AbstractUserStoreManager userStoreManager;

    @Mock
    SCIMGroupHandler scimGroupHandler;

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

    @DataProvider(name = "testUpdateAdminGroupData")
    public Object[][] testUpdateAdminGroupData() {
        return new Object[][]{
                {"testDomain"},
                {null}
        };
    }

    @Test(dataProvider = "testUpdateAdminGroupData")
    public void testUpdateAdminGroup(String domainName) throws Exception {
        String roleNameWithDomain = "TESTDOMAIN/admin";

        mockStatic(SCIMCommonComponentHolder.class);
        mockStatic(ClaimsMgtUtil.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(UserCoreUtil.class);
        mockStatic(IdentityUtil.class);
        mockStatic(SCIMCommonUtils.class);
        when(SCIMCommonComponentHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isSCIMEnabled()).thenReturn(true);
        when(userStoreManager.getTenantId()).thenReturn(1);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(userStoreManager.isRoleAndGroupSeparationEnabled()).thenReturn(true);
        when(realmConfiguration.getAdminRoleName()).thenReturn("admin");
        when(UserCoreUtil.getDomainName((RealmConfiguration) anyObject())).thenReturn(domainName);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("TESTDOMAIN");
        when(UserCoreUtil.addDomainToName(anyString(), anyString())).thenReturn(roleNameWithDomain);
        when(SCIMCommonUtils.getGroupNameWithDomain(anyString())).thenReturn(roleNameWithDomain);
        whenNew(SCIMGroupHandler.class).withAnyArguments().thenReturn(scimGroupHandler);

        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        adminAttributeUtil.updateAdminGroup(1);
        verify(scimGroupHandler).addMandatoryAttributes(argument.capture());

        assertEquals(argument.getValue(), roleNameWithDomain);
    }

    @Test(expectedExceptions = IdentitySCIMException.class)
    public void testUpdateAdminGroup1() throws Exception {
        String roleNameWithDomain = "TESTDOMAIN/admin";

        mockStatic(SCIMCommonComponentHolder.class);
        mockStatic(ClaimsMgtUtil.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(UserCoreUtil.class);
        mockStatic(IdentityUtil.class);
        mockStatic(SCIMCommonUtils.class);
        when(SCIMCommonComponentHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isSCIMEnabled()).thenReturn(true);
        when(userStoreManager.getTenantId()).thenReturn(1);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(realmConfiguration.getAdminRoleName()).thenReturn("admin");
        when(UserCoreUtil.getDomainName((RealmConfiguration) anyObject())).thenReturn("testDomain");
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("TESTDOMAIN");
        when(UserCoreUtil.addDomainToName(anyString(), anyString())).thenReturn(roleNameWithDomain);
        when(SCIMCommonUtils.getGroupNameWithDomain(anyString())).thenReturn(roleNameWithDomain);
        whenNew(SCIMGroupHandler.class).withAnyArguments().thenReturn(scimGroupHandler);
        when(scimGroupHandler.isGroupExisting(anyString())).thenThrow(new IdentitySCIMException("testException"));

        adminAttributeUtil.updateAdminGroup(1);
        verify(scimGroupHandler.isGroupExisting(anyString()));
    }

}
