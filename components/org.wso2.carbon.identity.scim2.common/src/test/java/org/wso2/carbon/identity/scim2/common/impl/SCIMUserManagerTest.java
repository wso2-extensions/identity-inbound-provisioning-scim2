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

package org.wso2.carbon.identity.scim2.common.impl;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.ObjectFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.utils.AttributeMapper;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMAttributeSchema;
import java.util.HashMap;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyMap;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;

import static org.testng.Assert.assertEquals;

/*
 * Unit tests for SCIMUserManager
 */
@PrepareForTest({SCIMGroupHandler.class, IdentityUtil.class, SCIMUserSchemaExtensionBuilder.class, SCIMAttributeSchema.class,AttributeMapper.class})
@PowerMockIgnore("java.sql.*")
public class SCIMUserManagerTest extends PowerMockTestCase {

    @Mock
    private UserStoreManager mockedUserStoreManager;

    @Mock
    private ClaimManager mockedClaimManager;

    @Mock
    private GroupDAO mockedGroupDAO;

    @Mock
    private SCIMAttributeSchema mockedScimAttributeSchema;

    @Mock
    private RealmConfiguration mockedRealmConfig;

    @Mock
    private User mockedUser;

    @BeforeMethod
    public void setUp() throws Exception {

       initMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testCreateUser() throws Exception {

    }

    @Test
    public void testGetUser() throws Exception {
    }

    @Test
    public void testDeleteUser() throws Exception {
    }

    @Test
    public void testListUsersWithGET() throws Exception {
    }

    @Test
    public void testListUsersWithPost() throws Exception {
    }

    @Test
    public void testUpdateUser() throws Exception {
    }

    @DataProvider(name = "data")
    public Object[][] data() {

        String CoreClaimUri1;
        String testMappedAttributesCore1;

        String CoreClaimUri2;
        String testMappedAttributesCore2;

        String UserClaimUri1;
        String testMappedAttributesUser1;

        String UserClaimUri2;
        String testMappedAttributesUser2;

        Claim claim1 = new Claim();
        Claim claim2 = new Claim();
        Claim claim3 = new Claim();
        Claim claim4 = new Claim();

        CoreClaimUri1 =  "testCoreClaimURI1";
        claim1.setClaimUri(CoreClaimUri1);
        testMappedAttributesCore1 = "MappedAttributesCore1";

        CoreClaimUri2 =  "testCoreClaimURI2";
        claim2.setClaimUri(CoreClaimUri2);
        testMappedAttributesCore2 = "MappedAttributesCore2";

        UserClaimUri1 =  "testUserClaimURI1";
        claim3.setClaimUri(UserClaimUri1);
        testMappedAttributesUser1 = "MappedAttributesUser1";

        UserClaimUri2 =  "testUserClaimURI2";
        claim4.setClaimUri(UserClaimUri2);
        testMappedAttributesUser2 = "MappedAttributesUser2";

        ClaimMapping cMap1 = new ClaimMapping(claim1, testMappedAttributesCore1);
        ClaimMapping cMap2 = new ClaimMapping(claim2, testMappedAttributesCore2);
        ClaimMapping cMap3 = new ClaimMapping(claim3, testMappedAttributesUser1);
        ClaimMapping cMap4 = new ClaimMapping(claim4, testMappedAttributesUser2);

        ClaimMapping[] coreClaims = new ClaimMapping[]{cMap1, cMap2, cMap3, cMap4};

        HashMap<String,Boolean> requiredAttributes = new HashMap<String, Boolean>() {
            {
                put("test1.test",true);
            }
        };

        String[] roles = new String[]{"role1","role2","role3"};


        return new Object[][]{
                {coreClaims,requiredAttributes,roles}

        };
    }

    @Test(dataProvider = "data")
    public void testGetMe(Object[] cMap, HashMap<String,Boolean> required, String[] userRoles) throws Exception {

        when(mockedClaimManager.getAllClaimMappings(anyString())).thenReturn((ClaimMapping[]) cMap);

        SCIMUserSchemaExtensionBuilder sb = spy(new SCIMUserSchemaExtensionBuilder());

        mockStatic(SCIMUserSchemaExtensionBuilder.class);

        when(SCIMUserSchemaExtensionBuilder.getInstance()).thenReturn(sb);
        when(sb.getExtensionSchema()).thenReturn(mockedScimAttributeSchema);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn("testPrimaryDomain");

        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockedUserStoreManager);

        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(true);

        when(mockedUserStoreManager.getRoleListOfUser(anyString())).thenReturn(userRoles);

        mockStatic(AttributeMapper.class);
        when(AttributeMapper.constructSCIMObjectFromAttributes(anyMap(),anyInt())).thenReturn(mockedUser);

        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(mockedRealmConfig.getEveryOneRoleName()).thenReturn("roleName");

        when(mockedUserStoreManager.getTenantId()).thenReturn(1234567);

        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        Assert.assertNotNull(scimUserManager.getMe("testUserName", required));

    }

    @Test
    public void testCreateMe() throws Exception {
    }

    @Test
    public void testDeleteMe() throws Exception {
    }

    @Test
    public void testUpdateMe() throws Exception {
    }

    @Test
    public void testCreateGroup() throws Exception {
    }

    @Test(dataProvider = "groupName")
    public void testGetGroup(Object roleName, String userStoreDomain, Object expected) throws Exception {

        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);
        when(mockedGroupDAO.getGroupNameById(anyInt(), anyString())).thenReturn((String) roleName);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);

        Group result = scimUserManager.getGroup("1234567", new HashMap<String, Boolean>());

        String actual = null;
        if(result != null){
            actual = result.getDisplayName();
        }
        assertEquals(actual, expected);

    }

    @DataProvider(name = "groupName")
    public Object[][] groupName() throws Exception {

        Group group = new Group();
        group.setDisplayName("roleName");
        return new Object[][]{
                {null, "userStoreDomain",null},
                {"roleName", null, "roleName"},

        };
    }

    @Test(dataProvider = "getGroupException")
    public void testGetGroupWithExceptions(String roleName, String userStoreDomain) throws Exception {

        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);
        when(mockedGroupDAO.getGroupNameById(anyInt(), anyString())).thenReturn((String) roleName);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        try {
            scimUserManager.getGroup("1234567", new HashMap<String, Boolean>());
        } catch (CharonException e) {
            assertEquals(e.getDetail(),"Error in retrieving the group");
        }

    }

    @DataProvider(name = "getGroupException")
    public Object[][] getGroupException() {

        return new Object[][]{
                { "testRole", "testDomainName" },

        };
    }

    @Test
    public void testDeleteGroup() throws Exception {
    }

    @Test
    public void testListGroupsWithGET() throws Exception {
    }

    @Test
    public void testUpdateGroup() throws Exception {
    }

    @Test
    public void testListGroupsWithPost() throws Exception {
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}