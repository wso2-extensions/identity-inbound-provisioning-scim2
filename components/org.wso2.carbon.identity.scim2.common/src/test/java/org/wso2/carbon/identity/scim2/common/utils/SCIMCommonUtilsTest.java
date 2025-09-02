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

package org.wso2.carbon.identity.scim2.common.utils;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.DefaultServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.internal.component.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.test.utils.CommonTestUtils;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

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

    @Mock
    ConfigurationManager configurationManager;

    private MockedStatic<UserCoreUtil> userCoreUtil;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<ServiceURLBuilder> serviceURLBuilder;
    private MockedStatic<IdentityUtil> identityUtil;
    private MockedStatic<SCIMCommonComponentHolder> scimComponentHolder;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        identityUtil = mockStatic(IdentityUtil.class);
        userCoreUtil = mockStatic(UserCoreUtil.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
        scimComponentHolder = mockStatic(SCIMCommonComponentHolder.class);
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
        scimComponentHolder.close();
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
    public void testUnsetThreadLocalIsSCIMAgentFlow() throws Exception {
        SCIMCommonUtils.unsetThreadLocalIsSCIMAgentFlow();
        assertNull(SCIMCommonUtils.getThreadLocalIsSCIMAgentFlow());
    }

    @Test(dataProvider = "threadLocalData")
    public void testGetThreadLocalIsSCIMAgentFlow(Boolean value, Boolean expectedResult) throws Exception {
        SCIMCommonUtils.setThreadLocalIsSCIMAgentFlow(value);
        assertEquals(SCIMCommonUtils.getThreadLocalIsSCIMAgentFlow(), expectedResult);
    }

    @Test(dataProvider = "threadLocalData")
    public void testSetThreadLocalIsSCIMAgentFlow(Boolean value, Boolean expectedResult) throws Exception {
        SCIMCommonUtils.setThreadLocalIsSCIMAgentFlow(value);
        assertEquals(SCIMCommonUtils.getThreadLocalIsSCIMAgentFlow(), expectedResult);
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

    @DataProvider
    public Object[][] getServerWideUserEndpointMaxLimitEnabledData() {
        return new Object[][]{
                {"", true},
                {null, true},
                {"true", true},
                {"false", false},
        };
    }

    @Test(dataProvider = "getServerWideUserEndpointMaxLimitEnabledData")
    public void testIsConsiderServerWideUserEndpointMaxLimitEnabled(Object value, boolean isExpectedResultTrue) {

        identityUtil.when(() -> IdentityUtil.getProperty(SCIMCommonConstants.CONSIDER_SERVER_WIDE_MAX_LIMIT_ENABLED))
                .thenReturn(value);
        if (isExpectedResultTrue) {
            assertTrue(SCIMCommonUtils.isConsiderServerWideUserEndpointMaxLimitEnabled());
        } else {
            assertFalse(SCIMCommonUtils.isConsiderServerWideUserEndpointMaxLimitEnabled());
        }
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMAgentURL(boolean isTenantQualifyURLEnabled) throws Exception {
        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String expectedAgentURL = SCIM_URL + SCIMCommonConstants.AGENTS_ENDPOINT;
        String scimAgentURL = SCIMCommonUtils.getSCIMAgentURL();
        assertEquals(scimAgentURL, expectedAgentURL);
    }
    
    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMUserURL_AgentFlowContext(boolean isTenantQualifyURLEnabled) throws Exception {
        // Simulate agent flow context
        SCIMCommonUtils.setThreadLocalIsSCIMAgentFlow(true);
        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String expectedAgentUserURL = SCIM_URL + SCIMCommonConstants.AGENTS_ENDPOINT + "/" + ID;
        String scimUserURL = SCIMCommonUtils.getSCIMUserURL(ID);
        assertEquals(scimUserURL, expectedAgentUserURL);
        SCIMCommonUtils.unsetThreadLocalIsSCIMAgentFlow();
    }

    @Test(dataProvider = "tenantURLQualifyData")
    public void testGetSCIMUserURL_AgentFlowContext_NullId(boolean isTenantQualifyURLEnabled) throws Exception {
        SCIMCommonUtils.setThreadLocalIsSCIMAgentFlow(true);
        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifyURLEnabled);
        String scimUserURL = SCIMCommonUtils.getSCIMUserURL(null);
        assertNull(scimUserURL);
        SCIMCommonUtils.unsetThreadLocalIsSCIMAgentFlow();
    }

    @DataProvider
    public Object[][] conflictOnClaimUniquenessViolationData() {
        return new Object[][]{
                // Config store value, server config value, expected result.

                // Config store has values - should use config store, ignore server config.
                {"true", "false", true},          // Config store "true" takes priority.
                {"false", "true", false},         // Config store "false" takes priority.
                {"TRUE", "false", true},          // Config store uppercase "TRUE".
                {"False", "true", false},         // Config store mixed case "False".
                {" ", "true", true},              // Config store whitespace.
                {" ", "false", false},            // Config store whitespace.
                {"invalid", "true", false},       // Config store invalid value.

                // Config store not available - should fall back to server config.
                {null, "true", true},             // Fallback to server "true".
                {null, "false", false},           // Fallback to server "false".
                {null, "TRUE", true},             // Fallback to server uppercase.
                {null, "invalid", false},         // Fallback to server invalid value.
                {null, "", false},                // Fallback to server empty string.
                {null, null, false}               // No config anywhere - default false.
        };
    }

    @Test(dataProvider = "conflictOnClaimUniquenessViolationData",
            description = "Test various config store and server config combinations.")
    public void testIsConflictOnClaimUniquenessViolationEnabled(String configStoreValue, String serverConfigValue,
                                                                boolean expectedResult) throws Exception {

        scimComponentHolder.when(SCIMCommonComponentHolder::getConfigurationManager).thenReturn(configurationManager);

        if (configStoreValue != null) {
            // Config store has a value.
            when(configurationManager.getResource(
                    SCIMCommonConstants.RESOURCE_TYPE_COMPATIBILITY_SETTINGS,
                    SCIMCommonConstants.RESOURCE_NAME_SCIM2,
                    true
            )).thenReturn(createMockResource(SCIMCommonConstants.ATTRIBUTE_NAME_CONFLICT_ON_CLAIM_UNIQUENESS_VIOLATION,
                    configStoreValue));
        } else {
            // Config store doesn't have the value - trigger fallback.
            when(configurationManager.getResource(
                    SCIMCommonConstants.RESOURCE_TYPE_COMPATIBILITY_SETTINGS,
                    SCIMCommonConstants.RESOURCE_NAME_SCIM2,
                    true
            )).thenReturn(null);
        }

        // Setup server-level configuration (fallback).
        identityUtil.when(() ->
                        IdentityUtil.getProperty(SCIMCommonConstants.SCIM2_CONFLICT_ON_CLAIM_UNIQUENESS_VIOLATION))
                .thenReturn(serverConfigValue);

        boolean result = SCIMCommonUtils.isConflictOnClaimUniquenessViolationEnabled();
        assertEquals(result, expectedResult);
    }

    @DataProvider
    public Object[][] serverConfigFallbackData() {
        return new Object[][]{
                {"true", true},
                {"false", false}
        };
    }

    @Test(dataProvider = "serverConfigFallbackData",
            description = "Test fallback to server config when configuration store throws exception.")
    public void testIsConflictOnClaimUniquenessViolationEnabled_ConfigStoreException(String serverConfigValue,
                                                                                     boolean expectedResult)
            throws Exception {

        scimComponentHolder.when(SCIMCommonComponentHolder::getConfigurationManager).thenReturn(configurationManager);
        when(configurationManager.getResource(
                SCIMCommonConstants.RESOURCE_TYPE_COMPATIBILITY_SETTINGS,
                SCIMCommonConstants.RESOURCE_NAME_SCIM2,
                true
        )).thenThrow(new ConfigurationManagementException());

        identityUtil.when(() ->
                        IdentityUtil.getProperty(SCIMCommonConstants.SCIM2_CONFLICT_ON_CLAIM_UNIQUENESS_VIOLATION))
                .thenReturn(serverConfigValue);

        boolean result = SCIMCommonUtils.isConflictOnClaimUniquenessViolationEnabled();
        assertEquals(result, expectedResult);
    }

    @Test(dataProvider = "serverConfigFallbackData",
            description = "Test fallback to server config when configuration resource has null attributes.")
    public void testIsConflictOnClaimUniquenessViolationEnabled_ConfigStoreResourceWithNullAttributes(
            String serverConfigValue, boolean expectedResult) throws Exception {

        scimComponentHolder.when(SCIMCommonComponentHolder::getConfigurationManager).thenReturn(configurationManager);
        when(configurationManager.getResource(
                SCIMCommonConstants.RESOURCE_TYPE_COMPATIBILITY_SETTINGS,
                SCIMCommonConstants.RESOURCE_NAME_SCIM2,
                true
        )).thenReturn(createMockResource(null, null));

        identityUtil.when(() ->
                        IdentityUtil.getProperty(SCIMCommonConstants.SCIM2_CONFLICT_ON_CLAIM_UNIQUENESS_VIOLATION))
                .thenReturn(serverConfigValue);

        boolean result = SCIMCommonUtils.isConflictOnClaimUniquenessViolationEnabled();
        assertEquals(result, expectedResult);
    }

    @Test(dataProvider = "serverConfigFallbackData",
            description = "Test fallback to server config when configuration resource has different attributes.")
    public void testIsConflictOnClaimUniquenessViolationEnabled_ConfigStoreResourceWithDifferentAttribute(
            String serverConfigValue, boolean expectedResult) throws Exception {

        scimComponentHolder.when(SCIMCommonComponentHolder::getConfigurationManager).thenReturn(configurationManager);
        when(configurationManager.getResource(
                SCIMCommonConstants.RESOURCE_TYPE_COMPATIBILITY_SETTINGS,
                SCIMCommonConstants.RESOURCE_NAME_SCIM2,
                true
        )).thenReturn(createMockResource("someOtherAttribute", "someOtherValue"));

        identityUtil.when(() ->
                        IdentityUtil.getProperty(SCIMCommonConstants.SCIM2_CONFLICT_ON_CLAIM_UNIQUENESS_VIOLATION))
                .thenReturn(serverConfigValue);

        boolean result = SCIMCommonUtils.isConflictOnClaimUniquenessViolationEnabled();
        assertEquals(result, expectedResult);
    }


    /**
     * Helper method to create a mock Resource with specified attributes.
     *
     * @param key   Attribute key.
     * @param value Attribute value.
     * @return Mock Resource object with the specified attributes.
     */
    private Resource createMockResource(String key, String value) {
        Resource mockResource = new Resource();

        if (key == null) {
            mockResource.setAttributes(Collections.emptyList());
        } else {
            Attribute mockAttribute = new Attribute();
            mockAttribute.setKey(key);
            mockAttribute.setValue(value);
            mockResource.setAttributes(Collections.singletonList(mockAttribute));
        }

        return mockResource;
    }
}
