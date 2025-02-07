/*
 * Copyright (c) 2017-2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.scim2.common.listener;

import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.api.Permission;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.common.UserStore;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;


public class SCIMUserOperationListenerTest {

    private final String CARBON_SUPER = "carbon.super";
    private String userName = "testUser";
    private String userId = "e235e3b6-49a3-45ad-a2b8-097733ee73ff";
    private Object credential = new Object();
    private String roleName = "testRole";
    private String[] roleList = new String[]{"testRole1, testRole2"};
    private String[] userList = new String[]{"testUser1, testUser2"};
    private Permission[] permissions = new Permission[0];
    private Map<String, String> claims = new HashMap<>();
    private String profile = "testProfile";
    private String claimURI = "http://wso2.org/claims/country";
    private String claimValue = "dummyValue";
    private String domainName = "testDomain";
    private boolean isAuthenticated = true;
    SCIMUserOperationListener scimUserOperationListener;

    @Mock
    UserStoreManager userStoreManager;

    @Mock
    ClaimMetadataManagementService claimMetadataManagementService;

    @Mock
    UserStore userStore;

    @Mock
    GroupDAO groupDAO;

    private MockedStatic<UserCoreUtil> userCoreUtil;
    private MockedStatic<SCIMCommonUtils> scimCommonUtils;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<IdentityUtil> identityUtil;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        scimUserOperationListener = spy(new SCIMUserOperationListener());
        userCoreUtil = mockStatic(UserCoreUtil.class);
        scimCommonUtils = mockStatic(SCIMCommonUtils.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityUtil = mockStatic(IdentityUtil.class);
        SCIMCommonComponentHolder.setClaimManagementService(claimMetadataManagementService);
        when(userStoreManager.getTenantId()).thenReturn(-1234);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(CARBON_SUPER);
    }

    @AfterMethod
    public void tearDown() {
        userCoreUtil.close();
        scimCommonUtils.close();
        identityTenantUtil.close();
        identityUtil.close();
    }

    @DataProvider(name = "testGetExecutionOrderIdData")
    public Object[][] testGetExecutionOrderIdData() {

        return new Object[][]{
                {10, 10},
                {IdentityCoreConstants.EVENT_LISTENER_ORDER_ID, 90}
        };
    }

    @Test(dataProvider = "testGetExecutionOrderIdData")
    public void testGetExecutionOrderId(int orderID, int expectedResult) throws Exception {
        when(scimUserOperationListener.getOrderId()).thenReturn(orderID);
        assertEquals(scimUserOperationListener.getExecutionOrderId(), expectedResult);
    }

    @Test
    public void testDoPreAuthenticate() throws Exception {
        assertTrue(scimUserOperationListener.doPreAuthenticate(userName, credential, userStoreManager));
    }

    @Test
    public void testDoPostAuthenticate() throws Exception {
        assertTrue(scimUserOperationListener.doPostAuthenticate(userName, isAuthenticated, userStoreManager));
    }

    @DataProvider(name = "testDoPreAddUserData")
    public Object[][] testDoPreAddUserData() {

        return new Object[][]{
                {true, true},
                {false, false},
                {true, false},
                {false, true}
        };
    }

    @Test(dataProvider = "testDoPreAddUserData")
    public void testDoPreAddUser(boolean isEnabled, boolean isSCIMEnabled) throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(isEnabled);
        when(userStoreManager.isSCIMEnabled()).thenReturn(isSCIMEnabled);

        assertTrue(scimUserOperationListener.doPreAddUserWithID(userId, credential, roleList, claims, profile,
                userStoreManager));
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPreAddUser1() throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());

        scimUserOperationListener.doPreAddUserWithID(userName, credential, roleList, claims, profile, userStoreManager);
    }

    @Test
    public void testDoPostAddUser() throws Exception {

        User user = new User(userId);
        assertTrue(scimUserOperationListener.doPostAddUserWithID(user, credential, roleList, claims, profile,
                userStoreManager));
    }

    @Test
    public void testDoPreUpdateCredential() throws Exception {
        assertTrue(scimUserOperationListener.doPreUpdateCredentialWithID(userId, credential, credential,
                userStoreManager));
    }

    @Test
    public void testDoPostUpdateCredential() throws Exception {
        assertTrue(scimUserOperationListener.doPostUpdateCredentialWithID(userId, credential, userStoreManager));
    }

    @Test
    public void testDoPreUpdateCredentialByAdmin() throws Exception {
        assertTrue(scimUserOperationListener.doPreUpdateCredentialByAdminWithID(userId, credential,
                userStoreManager));
    }

    @Test(dataProvider = "testDoPreAddUserData")
    public void testDoPostUpdateCredentialByAdmin(boolean isEnabled, boolean isSCIMEnabled)
            throws Exception {

        when(scimUserOperationListener.isEnable()).thenReturn(isEnabled);
        when(userStoreManager.isSCIMEnabled()).thenReturn(isSCIMEnabled);
        assertTrue(scimUserOperationListener.doPostUpdateCredentialByAdminWithID(userId, credential, userStoreManager));
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPostUpdateCredentialByAdmin1() throws Exception {

        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());
        scimUserOperationListener.doPostUpdateCredentialByAdminWithID(userId, credential, userStoreManager);
    }

    @Test
    public void testDoPreDeleteUser() throws Exception {
        assertTrue(scimUserOperationListener.doPreDeleteUserWithID(userId, userStoreManager));
    }

    @Test
    public void testDoPostDeleteUser() throws Exception {
        assertTrue(scimUserOperationListener.doPostDeleteUserWithID(userId, userStoreManager));
    }

    @Test
    public void testDoPreSetUserClaimValue() throws Exception {

        assertTrue(scimUserOperationListener.doPreSetUserClaimValueWithID(userId, claimURI, claimValue, profile,
                userStoreManager));
    }

    @Test
    public void testDoPostSetUserClaimValue() throws Exception {
        assertTrue(scimUserOperationListener.doPostSetUserClaimValueWithID(userId, userStoreManager));
    }

    @Test(dataProvider = "testDoPreAddUserData")
    public void testDoPreSetUserClaimValues(boolean isEnabled, boolean isSCIMEnabled) throws Exception {

        when(scimUserOperationListener.isEnable()).thenReturn(isEnabled);
        when(userStoreManager.isSCIMEnabled()).thenReturn(isSCIMEnabled);

        identityUtil.when(() -> IdentityUtil.getProperty(FrameworkConstants.ENABLE_JIT_PROVISION_ENHANCE_FEATURE)).thenReturn("false");

        assertTrue(scimUserOperationListener.
                doPreSetUserClaimValuesWithID(userId, claims, profile, userStoreManager));
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPreSetUserClaimValues1() throws Exception {

        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());
        scimUserOperationListener.doPreSetUserClaimValuesWithID(userId, claims, profile, userStoreManager);
    }

    @Test
    public void testDoPostSetUserClaimValues() throws Exception {
        assertTrue(scimUserOperationListener.doPostSetUserClaimValuesWithID(userId, claims, profile, userStoreManager));
    }

    @Test
    public void testDoPreDeleteUserClaimValues() throws Exception {
        assertTrue(scimUserOperationListener.doPreDeleteUserClaimValuesWithID(userId, roleList, userName,
                userStoreManager));
    }

    @Test
    public void testDoPostDeleteUserClaimValues() throws Exception {
        assertTrue(scimUserOperationListener.doPostDeleteUserClaimValuesWithID(userId, userStoreManager));
    }

    @Test
    public void testDoPreDeleteUserClaimValue() throws Exception {
        assertTrue(scimUserOperationListener.doPreDeleteUserClaimValueWithID(anyString(), anyString(), anyString(),
                eq(userStoreManager)));
    }

    @Test
    public void testDoPostDeleteUserClaimValue() throws Exception {
        assertTrue(scimUserOperationListener.doPostDeleteUserClaimValueWithID(userId, userStoreManager));
    }

    @DataProvider(name = "testDoPostAddRoleData")
    public Object[][] testDoPostAddRoleData() {

        return new Object[][]{
                {true, true, true, domainName},
                {true, true, false, null},
                {false, false, true, domainName},
                {true, false, false, domainName},
                {false, true, true, domainName}
        };
    }

    @Test(dataProvider = "testDoPostAddRoleData")
    public void testDoPostAddRole(boolean isEnabled, boolean isSCIMEnabled, boolean isGroupExisting, String domainName)
            throws Exception {
        mockTestEnvironment(isEnabled, isSCIMEnabled, domainName);
        when(groupDAO.isExistingGroup(anyString(), anyInt())).thenReturn(isGroupExisting);

        assertTrue(scimUserOperationListener.doPostAddRole(roleName, userList, permissions, userStoreManager));
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPostAddRole1() throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());

        scimUserOperationListener.doPostAddRoleWithID(roleName, userList, permissions, userStoreManager);
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPostAddRole2() throws Exception {

        mockTestEnvironment(true, true, domainName);
        try (MockedConstruction<GroupDAO> mockedGroupDAO = Mockito.mockConstruction(GroupDAO.class,
                (mock, context) -> {
                    when(mock.isExistingGroup(anyString(), anyInt()))
                            .thenThrow(new IdentitySCIMException("IdentitySCIMException"));
                })) {
            scimUserOperationListener.doPostAddRoleWithID(roleName, userList, permissions, userStoreManager);
        }
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPreDeleteRole1() throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());

        scimUserOperationListener.doPreDeleteRole(roleName, userStoreManager);
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPreDeleteRole2() throws Exception {

        mockTestEnvironment(true, true, domainName);
        try (MockedConstruction<GroupDAO> mockedGroupDAO = Mockito.mockConstruction(GroupDAO.class,
                (mock, context) -> {
                    when(mock.isExistingGroup(nullable(String.class), anyInt()))
                            .thenThrow(new IdentitySCIMException("IdentitySCIMException"));
                })) {
            scimUserOperationListener.doPreDeleteRole(roleName, userStoreManager);
        }
    }

    @Test
    public void testDoPostDeleteRole() throws Exception {
        assertTrue(scimUserOperationListener.doPostDeleteRole(roleName, userStoreManager));
    }

    @Test
    public void testDoPreUpdateRoleName() throws Exception {
        assertTrue(scimUserOperationListener.doPreUpdateRoleName(anyString(), anyString(), eq(userStoreManager)));
    }

    @DataProvider(name = "testDoPostUpdateRoleNameData")
    public Object[][] testDoPostUpdateRoleNameData() {

        return new Object[][]{
                {true, true, domainName},
                {true, true, null},
                {false, false, domainName},
                {true, false, domainName},
                {false, true, domainName}
        };
    }

    @Test(dataProvider = "testDoPostUpdateRoleNameData")
    public void testDoPostUpdateRoleName(boolean isEnabled, boolean isSCIMEnabled, String domainName) throws Exception {
        mockTestEnvironment(isEnabled, isSCIMEnabled, domainName);
        try (MockedConstruction<GroupDAO> mockedGroupDAO = Mockito.mockConstruction(GroupDAO.class,
                (mock, context) -> {
                    when(mock.isExistingGroup(anyString(), anyInt())).thenReturn(true);
                })) {
            assertTrue(scimUserOperationListener.doPostUpdateRoleName(roleName, roleName, userStoreManager));
        }
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPostUpdateRoleName1() throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());

        scimUserOperationListener.doPostUpdateRoleName(roleName, roleName, userStoreManager);
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPostUpdateRoleName2() throws Exception {

        mockTestEnvironment(true, true, domainName);
        try (MockedConstruction<GroupDAO> mockedGroupDAO = Mockito.mockConstruction(GroupDAO.class,
                (mock, context) -> {
                    when(mock.isExistingGroup(anyString(), anyInt()))
                            .thenThrow(new IdentitySCIMException("IdentitySCIMException"));
                })) {
            scimUserOperationListener.doPostUpdateRoleName(roleName, roleName, userStoreManager);
        }
    }

    @DataProvider(name = "testDoPostUpdateRoleNameForUniqueGroupIdFlag")
    public Object[][] testDoPostUpdateRoleNameForUniqueGroupIdFlag() {

        return new Object[][]{
                {true}, {false}
        };
    }

    @Test(dataProvider = "testDoPostUpdateRoleNameForUniqueGroupIdFlag")
    public void testDoPostUpdateRoleNameForUniqueGroupIdFlag(boolean isUniqueGroupIdEnabled) throws Exception {

        try (MockedConstruction<GroupDAO> mockedGroupDAO = Mockito.mockConstruction(GroupDAO.class,
                (mock, context) -> {
                    when(mock.isExistingGroup(anyString(), anyInt())).thenReturn(true);
                })) {
            AbstractUserStoreManager mockUserStoreManager = Mockito.mock(AbstractUserStoreManager.class);
            when(mockUserStoreManager.isSCIMEnabled()).thenReturn(true);
            when(mockUserStoreManager.isUniqueGroupIdEnabled()).thenReturn(isUniqueGroupIdEnabled);
            when(scimUserOperationListener.isEnable()).thenReturn(true);

            userCoreUtil.when(() -> UserCoreUtil.addDomainToName(anyString(), anyString()))
                    .thenReturn(domainName);

            assertTrue(scimUserOperationListener.doPostUpdateRoleName(roleName, roleName, mockUserStoreManager));

            GroupDAO groupDAO = mockedGroupDAO.constructed().stream()
                    .findFirst()
                    .orElse(null);

            if (isUniqueGroupIdEnabled) {
                assertNull(groupDAO, "GroupDAO instance should have not been created");
            } else {
                assertNotNull(groupDAO, "GroupDAO instance should have been created");
                Mockito.verify(groupDAO, Mockito.times(1)).updateRoleName(anyInt(), anyString(), anyString());
            }
        }
    }

    @Test
    public void testDoPreUpdateUserListOfRole() throws Exception {
        assertTrue(scimUserOperationListener.doPreUpdateUserListOfRole(anyString(), any(String[].class),
                any(String[].class), eq(userStoreManager)));
    }

    @Test
    public void testDoPostUpdateUserListOfRole() throws Exception {
        assertTrue(scimUserOperationListener.doPostUpdateUserListOfRole(anyString(), any(String[].class),
                any(String[].class), eq(userStoreManager)));
    }

    @Test
    public void testDoPreUpdateRoleListOfUser() throws Exception {
        assertTrue(scimUserOperationListener.doPreUpdateRoleListOfUser(anyString(), any(String[].class),
                any(String[].class), eq(userStoreManager)));
    }

    @Test
    public void testDoPostUpdateRoleListOfUser() throws Exception {
        assertTrue(scimUserOperationListener.doPostUpdateRoleListOfUser(anyString(), any(String[].class),
                any(String[].class), eq(userStoreManager)));
    }

    @DataProvider(name = "testSCIMAttributesData")
    public Object[][] testSCIMAttributesData() {

        Map<String, String> claimsMap1 = new HashMap<>();

        String id = UUID.randomUUID().toString();
        claimsMap1.put(SCIMConstants.CommonSchemaConstants.ID_URI, id);

        return new Object[][]{
                {claimsMap1},
                {claimsMap1},
                {null}
        };
    }

    @Test(dataProvider = "testSCIMAttributesData")
    public void testGetSCIMAttributes(Map<String, String> claimsMap) throws Exception {
        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, "http://wso2.org/claims/userid");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.CREATED_URI, "http://wso2.org/claims/created");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI,
                "http://wso2.org/claims/modified");
        scimToLocalClaimsMap.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, "http://wso2.org/claims/username");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI,
                "http://wso2.org/claims/resourceType");
        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        assertNotNull(scimUserOperationListener.getSCIMAttributes(userName, claimsMap));
    }

    @Test(dataProvider = "testSCIMAttributesData")
    public void testPopulateSCIMAttributes(Map<String, String> claimsMap) throws Exception {
        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, "http://wso2.org/claims/userid");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.CREATED_URI, "http://wso2.org/claims/created");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI,
                "http://wso2.org/claims/modified");
        scimToLocalClaimsMap.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, "http://wso2.org/claims/username");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI,
                "http://wso2.org/claims/resourceType");
        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        assertNotNull(scimUserOperationListener.populateSCIMAttributes(userName, claimsMap));
    }

    private void mockTestEnvironment(boolean isEnabled, boolean isSCIMEnabled, String domainName) throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(isEnabled);
        when(userStoreManager.isSCIMEnabled()).thenReturn(isSCIMEnabled);
        userCoreUtil.when(() -> UserCoreUtil.getDomainName((RealmConfiguration) any())).thenReturn(domainName);
        userCoreUtil.when(() -> UserCoreUtil.addDomainToName(anyString(), anyString())).thenReturn("testRoleNameWithDomain");
        scimCommonUtils.when(() ->SCIMCommonUtils.getGroupNameWithDomain(anyString())).thenReturn("testRoleNameWithDomain");
    }
}
