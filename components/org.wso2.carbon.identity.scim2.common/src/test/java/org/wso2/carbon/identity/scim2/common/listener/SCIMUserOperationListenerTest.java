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

package org.wso2.carbon.identity.scim2.common.listener;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.api.Permission;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.UserStore;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

@PrepareForTest({UserCoreUtil.class, SCIMGroupHandler.class, SCIMCommonUtils.class})
public class SCIMUserOperationListenerTest extends PowerMockTestCase {

    private String userName = "testUser";
    private Object credential = new Object();
    private String roleName = "testRole";
    private String[] roleList = new String[]{"testRole1, testRole2"};
    private String[] userList = new String[]{"testUser1, testUser2"};
    private Permission[] permissions = new Permission[0];
    private Map<String, String> claims = new HashMap<>();
    private String profile = "testProfile";
    private boolean isAuthenticated = true;
    SCIMUserOperationListener scimUserOperationListener;

    @Mock
    UserStoreManager userStoreManager;

    @Mock
    UserStore userStore;

    @Mock
    GroupDAO groupDAO;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        scimUserOperationListener = spy(new SCIMUserOperationListener());
        mockStatic(UserCoreUtil.class);
        mockStatic(SCIMCommonUtils.class);
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

        assertTrue(scimUserOperationListener.doPreAddUser(userName, credential, roleList, claims, profile,
                userStoreManager));
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPreAddUser1() throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());

        scimUserOperationListener.doPreAddUser(userName, credential, roleList, claims, profile, userStoreManager);
    }

    @Test
    public void testDoPostAddUser() throws Exception {
        assertTrue(scimUserOperationListener.doPostAddUser(userName, credential, roleList, claims, profile,
                userStoreManager));
    }

    @Test
    public void testDoPreUpdateCredential() throws Exception {
        assertTrue(scimUserOperationListener.doPreUpdateCredential(userName, credential, credential, userStoreManager));
    }

    @Test
    public void testDoPostUpdateCredential() throws Exception {
        assertTrue(scimUserOperationListener.doPostUpdateCredential(userName, credential, userStoreManager));
    }

    @Test
    public void testDoPreUpdateCredentialByAdmin() throws Exception {
        assertTrue(scimUserOperationListener.doPreUpdateCredentialByAdmin(userName, credential, userStoreManager));
    }

    @Test(dataProvider = "testDoPreAddUserData")
    public void testDoPostUpdateCredentialByAdmin(boolean isEnabled, boolean isSCIMEnabled)
            throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(isEnabled);
        when(userStoreManager.isSCIMEnabled()).thenReturn(isSCIMEnabled);

        assertTrue(scimUserOperationListener.doPostUpdateCredentialByAdmin(userName, credential, userStoreManager));
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPostUpdateCredentialByAdmin1() throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());
        scimUserOperationListener.doPostUpdateCredentialByAdmin(userName, credential, userStoreManager);
    }

    @Test
    public void testDoPreDeleteUser() throws Exception {
        assertTrue(scimUserOperationListener.doPreDeleteUser(userName, userStoreManager));
    }

    @Test
    public void testDoPostDeleteUser() throws Exception {
        assertTrue(scimUserOperationListener.doPostDeleteUser(userName, userStoreManager));
    }

    @Test
    public void testDoPreSetUserClaimValue() throws Exception {
        assertTrue(scimUserOperationListener.doPreSetUserClaimValue(eq(userName), anyString(), anyString(), anyString(),
                eq(userStoreManager)));
    }

    @Test
    public void testDoPostSetUserClaimValue() throws Exception {
        assertTrue(scimUserOperationListener.doPostSetUserClaimValue(userName, userStoreManager));
    }

    @Test(dataProvider = "testDoPreAddUserData")
    public void testDoPreSetUserClaimValues(boolean isEnabled, boolean isSCIMEnabled) throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(isEnabled);
        when(userStoreManager.isSCIMEnabled()).thenReturn(isSCIMEnabled);

        assertTrue(scimUserOperationListener.doPreSetUserClaimValues(userName, claims, profile, userStoreManager));
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPreSetUserClaimValues1() throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());
        scimUserOperationListener.doPreSetUserClaimValues(userName, claims, profile, userStoreManager);
    }

    @Test
    public void testDoPostSetUserClaimValues() throws Exception {
        assertTrue(scimUserOperationListener.doPostSetUserClaimValues(userName, claims, profile, userStoreManager));
    }

    @Test
    public void testDoPreDeleteUserClaimValues() throws Exception {
        assertTrue(scimUserOperationListener.doPreDeleteUserClaimValues(userName, roleList, userName,
                userStoreManager));
    }

    @Test
    public void testDoPostDeleteUserClaimValues() throws Exception {
        assertTrue(scimUserOperationListener.doPostDeleteUserClaimValues(userName, userStoreManager));
    }

    @Test
    public void testDoPreDeleteUserClaimValue() throws Exception {
        assertTrue(scimUserOperationListener.doPreDeleteUserClaimValue(anyString(), anyString(), anyString(),
                eq(userStoreManager)));
    }

    @Test
    public void testDoPostDeleteUserClaimValue() throws Exception {
        assertTrue(scimUserOperationListener.doPostDeleteUserClaimValue(userName, userStoreManager));
    }

    @Test
    public void testDoPreAddRole() throws Exception {
        assertTrue(scimUserOperationListener.doPreAddRole(userName, roleList, permissions, userStoreManager));
    }

    @DataProvider(name = "testDoPostAddRoleData")
    public Object[][] testDoPostAddRoleData() {
        return new Object[][]{
                {true, true, true, "testDomain"},
                {true, true, false, null},
                {false, false, true, "testDomain"},
                {true, false, false, "testDomain"},
                {false, true, true, "testDomain"}
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

        scimUserOperationListener.doPostAddRole(roleName, userList, permissions, userStoreManager);
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPostAddRole2() throws Exception {
        mockTestEnvironment(true, true, "testDomain");
        when(groupDAO.isExistingGroup(anyString(), anyInt())).thenThrow(new IdentitySCIMException
                ("IdentitySCIMException"));

        scimUserOperationListener.doPostAddRole(roleName, userList, permissions, userStoreManager);
    }

    @Test(dataProvider = "testDoPostAddRoleData")
    public void testDoPreDeleteRole(boolean isEnabled, boolean isSCIMEnabled, boolean isGroupExisting,
                                    String domainName) throws Exception {
        mockTestEnvironment(isEnabled, isSCIMEnabled, domainName);
        when(groupDAO.isExistingGroup(anyString(), anyInt())).thenReturn(isGroupExisting);

        assertTrue(scimUserOperationListener.doPreDeleteRole(roleName, userStoreManager));
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPreDeleteRole1() throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());

        scimUserOperationListener.doPreDeleteRole(roleName, userStoreManager);
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPreDeleteRole2() throws Exception {
        mockTestEnvironment(true, true, "testDomain");
        when(groupDAO.isExistingGroup(anyString(), anyInt())).thenThrow(new IdentitySCIMException
                ("IdentitySCIMException"));

        scimUserOperationListener.doPreDeleteRole(roleName, userStoreManager);
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
                {true, true, "testDomain"},
                {true, true, null},
                {false, false, "testDomain"},
                {true, false, "testDomain"},
                {false, true, "testDomain"}
        };
    }

    @Test(dataProvider = "testDoPostUpdateRoleNameData")
    public void testDoPostUpdateRoleName(boolean isEnabled, boolean isSCIMEnabled, String domainName) throws Exception {
        mockTestEnvironment(isEnabled, isSCIMEnabled, domainName);
        when(groupDAO.isExistingGroup(anyString(), anyInt())).thenReturn(true);

        assertTrue(scimUserOperationListener.doPostUpdateRoleName(roleName, roleName, userStoreManager));
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPostUpdateRoleName1() throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(true);
        when(userStoreManager.isSCIMEnabled()).thenThrow(new UserStoreException());

        scimUserOperationListener.doPostUpdateRoleName(roleName, roleName, userStoreManager);
    }

    @Test(expectedExceptions = UserStoreException.class)
    public void testDoPostUpdateRoleName2() throws Exception {
        mockTestEnvironment(true, true, "testDomain");
        when(groupDAO.isExistingGroup(anyString(), anyInt())).thenThrow(new IdentitySCIMException("IdentitySCIMException"));

        scimUserOperationListener.doPostUpdateRoleName(roleName, roleName, userStoreManager);
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

        Map<String, String> claimsMap2 = claimsMap1;
        String id = UUID.randomUUID().toString();
        claimsMap2.put(SCIMConstants.CommonSchemaConstants.ID_URI, id);

        return new Object[][]{
                {claimsMap1},
                {claimsMap2},
                {null}
        };
    }

    @Test(dataProvider = "testSCIMAttributesData")
    public void testGetSCIMAttributes(Map<String, String> claimsMap) throws Exception {
        mockStatic(SCIMCommonUtils.class);
        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, "http://wso2.org/claims/userid");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.CREATED_URI, "http://wso2.org/claims/created");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, "http://wso2.org/claims/modified");
        scimToLocalClaimsMap.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, "http://wso2.org/claims/username");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI, "http://wso2.org/claims/resourceType");
        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        assertNotNull(scimUserOperationListener.getSCIMAttributes(userName, claimsMap));
    }

    @Test(dataProvider = "testSCIMAttributesData")
    public void testPopulateSCIMAttributes(Map<String, String> claimsMap) throws Exception {
        mockStatic(SCIMCommonUtils.class);
        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, "http://wso2.org/claims/userid");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.CREATED_URI, "http://wso2.org/claims/created");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, "http://wso2.org/claims/modified");
        scimToLocalClaimsMap.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, "http://wso2.org/claims/username");
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI, "http://wso2.org/claims/resourceType");
        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        assertNotNull(scimUserOperationListener.populateSCIMAttributes(userName, claimsMap));
    }

    private void mockTestEnvironment(boolean isEnabled, boolean isSCIMEnabled, String domainName) throws Exception {
        when(scimUserOperationListener.isEnable()).thenReturn(isEnabled);
        when(userStoreManager.isSCIMEnabled()).thenReturn(isSCIMEnabled);
        whenNew(GroupDAO.class).withNoArguments().thenReturn(groupDAO);
        when(UserCoreUtil.getDomainName((RealmConfiguration) anyObject())).thenReturn(domainName);
        when(UserCoreUtil.addDomainToName(anyString(), anyString())).thenReturn("testRoleNameWithDomain");
        when(SCIMCommonUtils.getGroupNameWithDomain(anyString())).thenReturn("testRoleNameWithDomain");
    }

}

