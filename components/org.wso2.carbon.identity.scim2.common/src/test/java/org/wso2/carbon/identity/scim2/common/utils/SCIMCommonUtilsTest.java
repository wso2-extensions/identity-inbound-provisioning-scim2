/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.scim2.common.utils;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.DefaultServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.test.utils.CommonTestUtils;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class SCIMCommonUtilsTest {

    private static final String ID = "8a439cf6-3c6b-47d2-94bf-34d072495af3";
    private static final String SCIM_URL = "https://localhost:9443/scim2";
    private String scimUserLocation = SCIM_URL + SCIMCommonConstants.USERS;
    private String scimGroupLocation = SCIM_URL + SCIMCommonConstants.GROUPS;
    private String scimServiceProviderConfig = SCIM_URL + SCIMCommonConstants.SERVICE_PROVIDER_CONFIG;
    private String scimResourceType = SCIM_URL + SCIMCommonConstants.RESOURCE_TYPE;

    @Mock
    ServiceURL serviceURL;

    @Mock
    ServiceURL serviceURL1;

    @Mock
    DefaultServiceURLBuilder defaultServiceURLBuilder;

    @Mock
    DefaultServiceURLBuilder defaultServiceURLBuilder1;

    private MockedStatic<UserCoreUtil> userCoreUtil;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<ServiceURLBuilder> serviceURLBuilder;
    private MockedStatic<IdentityUtil> identityUtil;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        identityUtil = mockStatic(IdentityUtil.class);
        userCoreUtil = mockStatic(UserCoreUtil.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
        identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(SCIM_URL);
        identityUtil.when(() -> IdentityUtil.getPrimaryDomainName()).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        serviceURLBuilder.when(() -> ServiceURLBuilder.create()).thenReturn(defaultServiceURLBuilder);
        when(defaultServiceURLBuilder.build()).thenReturn(serviceURL);
        when(defaultServiceURLBuilder.addPath(SCIMCommonConstants.SCIM2_ENDPOINT)).thenReturn
                (defaultServiceURLBuilder1);
        when(defaultServiceURLBuilder1.build()).thenReturn(serviceURL1);
        when(serviceURL1.getAbsolutePublicURL()).thenReturn("https://localhost:9443/scim2");
        when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443");
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomainFromContext()).thenReturn("carbon.super");
    }

    @AfterMethod
    public void tearDown() {
        identityUtil.close();
        userCoreUtil.close();
        identityTenantUtil.close();
        serviceURLBuilder.close();
        System.clearProperty(CarbonBaseConstants.CARBON_HOME);
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMUserURL(boolean isTenantQualifyURLEnabled) throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimUserURL = SCIMCommonUtils.getSCIMUserURL(ID);
        assertEquals(scimUserURL, scimUserLocation + "/" + ID);
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMUserURLForNullId(boolean isTenantQualifyURLEnabled) throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimUserURL = SCIMCommonUtils.getSCIMUserURL(null);
        assertEquals(scimUserURL, null);
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMGroupURL(boolean isTenantQualifyURLEnabled) throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimGroupURL = SCIMCommonUtils.getSCIMGroupURL(ID);
        assertEquals(scimGroupURL, scimGroupLocation + "/" + ID);
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMGroupURLForNullId(boolean isTenantQualifyURLEnabled) throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimGroupURL = SCIMCommonUtils.getSCIMGroupURL(null);
        assertEquals(scimGroupURL, null);
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMServiceProviderConfigURL(boolean isTenantQualifyURLEnabled) throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimServiceProviderConfigURL = SCIMCommonUtils.getSCIMServiceProviderConfigURL(ID);
        assertEquals(scimServiceProviderConfigURL, scimServiceProviderConfig);
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMUserURL1(boolean isTenantQualifyURLEnabled) throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimUsersURL = SCIMCommonUtils.getSCIMUserURL();
        assertEquals(scimUsersURL, scimUserLocation);
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMGroupURL1(boolean isTenantQualifyURLEnabled) throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimGroupsURL = SCIMCommonUtils.getSCIMGroupURL();
        assertEquals(scimGroupsURL, scimGroupLocation);
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMServiceProviderConfigURL1(boolean isTenantQualifyURLEnabled) throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimServiceProviderConfigURL = SCIMCommonUtils.getSCIMServiceProviderConfigURL();
        assertEquals(scimServiceProviderConfigURL, scimServiceProviderConfig);
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMResourceTypeURL(boolean isTenantQualifyURLEnabled) throws Exception {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimResourceTypeURL = SCIMCommonUtils.getSCIMResourceTypeURL();
        assertEquals(scimResourceTypeURL, scimResourceType);
    }

    @DataProvider(name = "groupNames")
    public Object[][] getGroupNames() {
        return new Object[][]{
                {null, null},
                {"TESTDOMAIN/testGroup", "TESTDOMAIN/testGroup"},
                {"testGroup", UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME + CarbonConstants.DOMAIN_SEPARATOR + "testGroup"}
        };
    }

    @Test(dataProvider = "groupNames")
    public void testGetGroupNameWithDomain(String paramValue, String expectedResult) throws Exception {
        assertEquals(SCIMCommonUtils.getGroupNameWithDomain(paramValue), expectedResult);
    }

    @DataProvider(name = "groupNamesWithDomain")
    public Object[][] getGroupNamesWithDomain() {
        return new Object[][]{
                {null, null},
                {"TESTDOMAIN/testGroup", "TESTDOMAIN/testGroup"},
                {UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME + "/testGroup", "testGroup"},
                {"testGroup", "testGroup"}
        };
    }

    @Test(dataProvider = "groupNamesWithDomain")
    public void testGetPrimaryFreeGroupName(String groupName, String expectedResult) throws Exception {
        assertEquals(SCIMCommonUtils.getPrimaryFreeGroupName(groupName), expectedResult);
    }

    @DataProvider(name = "threadLocalData")
    public Object[][] threadLocalData() {
        return new Object[][]{
                {true, true},
                {false, false}
        };
    }

    @Test
    public void testUnsetThreadLocalToSkipSetUserClaimsListeners() throws Exception {
        SCIMCommonUtils.unsetThreadLocalToSkipSetUserClaimsListeners();
        assertNull(SCIMCommonUtils.getThreadLocalToSkipSetUserClaimsListeners());
    }

    @Test(dataProvider = "threadLocalData")
    public void testGetThreadLocalToSkipSetUserClaimsListeners(Boolean value, Boolean expectedResult) throws Exception {
        SCIMCommonUtils.setThreadLocalToSkipSetUserClaimsListeners(value);
        assertEquals(SCIMCommonUtils.getThreadLocalToSkipSetUserClaimsListeners(), expectedResult);
    }

    @Test(dataProvider = "threadLocalData")
    public void testSetThreadLocalToSkipSetUserClaimsListeners(Boolean value, Boolean expectedResult) throws Exception {
        SCIMCommonUtils.setThreadLocalToSkipSetUserClaimsListeners(value);
        assertEquals(SCIMCommonUtils.getThreadLocalToSkipSetUserClaimsListeners(), expectedResult);
    }

    @Test
    public void testUnsetThreadLocalIsManagedThroughSCIMEP() throws Exception {
        SCIMCommonUtils.unsetThreadLocalIsManagedThroughSCIMEP();
        assertNull(SCIMCommonUtils.getThreadLocalIsManagedThroughSCIMEP());
    }

    @Test(dataProvider = "threadLocalData")
    public void testGetThreadLocalIsManagedThroughSCIMEP(Boolean value, Boolean expectedResult) throws Exception {
        SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(value);
        assertEquals(SCIMCommonUtils.getThreadLocalIsManagedThroughSCIMEP(), expectedResult);
    }

    @Test(dataProvider = "threadLocalData")
    public void testSetThreadLocalIsManagedThroughSCIMEP(Boolean value, Boolean expectedResult) throws Exception {
        SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(value);
        assertEquals(SCIMCommonUtils.getThreadLocalIsManagedThroughSCIMEP(), expectedResult);
    }

    @Test
    public void testGetGlobalConsumerId() throws Exception {
        String tenantDomain = "testTenantDomain";
        CommonTestUtils.initPrivilegedCarbonContext(tenantDomain);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);
        assertEquals(SCIMCommonUtils.getGlobalConsumerId(), tenantDomain);
    }

    @Test
    public void testGetUserConsumerId() throws Exception {
        String userConsumerId = "testConsumerId";
        CommonTestUtils.initPrivilegedCarbonContext();
        userCoreUtil.when(() -> UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn(userConsumerId);

        assertEquals(SCIMCommonUtils.getUserConsumerId(), userConsumerId);
    }

    @DataProvider(name = "tenantURLQualifyData")
    public Object[][] tenantURLQualifyData() {
        return new Object[][]{
                {true},
                {false}
        };
    }

}
