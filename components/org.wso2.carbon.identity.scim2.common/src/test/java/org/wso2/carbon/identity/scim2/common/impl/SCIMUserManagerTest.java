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
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.utils.AttributeMapper;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMAttributeSchema;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.ExpressionNode;
import org.wso2.charon3.core.utils.codeutils.Node;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/*
 * Unit tests for SCIMUserManager
 */
@PrepareForTest({SCIMGroupHandler.class, IdentityUtil.class, SCIMUserSchemaExtensionBuilder.class, SCIMAttributeSchema.class, AttributeMapper.class})
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

    @Mock
    private RealmConfiguration mockRealmConfig;

    @Mock
    private IdentityUtil mockIdentityUtil;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
    }

    @DataProvider(name = "ClaimData")
    public Object[][] data() {

        String coreClaimUri1;
        String testMappedAttributesCore1;

        String coreClaimUri2;
        String testMappedAttributesCore2;

        String userClaimUri1;
        String testMappedAttributesUser1;

        String userClaimUri2;
        String testMappedAttributesUser2;

        Claim claim1 = new Claim();
        Claim claim2 = new Claim();
        Claim claim3 = new Claim();
        Claim claim4 = new Claim();

        coreClaimUri1 = "testCoreClaimURI1";
        claim1.setClaimUri(coreClaimUri1);
        testMappedAttributesCore1 = "MappedAttributesCore1";

        coreClaimUri2 = "testCoreClaimURI2";
        claim2.setClaimUri(coreClaimUri2);
        testMappedAttributesCore2 = "MappedAttributesCore2";

        userClaimUri1 = "testUserClaimURI1";
        claim3.setClaimUri(userClaimUri1);
        testMappedAttributesUser1 = "MappedAttributesUser1";

        userClaimUri2 = "testUserClaimURI2";
        claim4.setClaimUri(userClaimUri2);
        testMappedAttributesUser2 = "MappedAttributesUser2";

        ClaimMapping cMap1 = new ClaimMapping(claim1, testMappedAttributesCore1);
        ClaimMapping cMap2 = new ClaimMapping(claim2, testMappedAttributesCore2);
        ClaimMapping cMap3 = new ClaimMapping(claim3, testMappedAttributesUser1);
        ClaimMapping cMap4 = new ClaimMapping(claim4, testMappedAttributesUser2);

        ClaimMapping[] coreClaims = new ClaimMapping[]{cMap1, cMap2, cMap3, cMap4};

        HashMap<String, Boolean> requiredAttributes = new HashMap<String, Boolean>() {
            {
                put("test1.test", true);
            }
        };

        String[] roles = new String[]{"role1", "role2", "role3"};

        return new Object[][]{
                {coreClaims, requiredAttributes, roles}
        };
    }

    @Test(dataProvider = "ClaimData")
    public void testGetMe(Object[] cMap, HashMap<String, Boolean> required, String[] userRoles) throws Exception {

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
        when(AttributeMapper.constructSCIMObjectFromAttributes(anyMap(), anyInt())).thenReturn(mockedUser);
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(mockedRealmConfig.getEveryOneRoleName()).thenReturn("roleName");
        when(mockedUserStoreManager.getTenantId()).thenReturn(1234567);
        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        assertNotNull(scimUserManager.getMe("testUserName", required));
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
        if (result != null) {
            actual = result.getDisplayName();
        }
        assertEquals(actual, expected);
    }

    @DataProvider(name = "groupName")
    public Object[][] groupName() throws Exception {

        Group group = new Group();
        group.setDisplayName("roleName");
        return new Object[][]{
                {null, "userStoreDomain", null},
                {"roleName", null, "roleName"}
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
            assertEquals(e.getDetail(), "Error in retrieving the group");
        }
    }

    @DataProvider(name = "getGroupException")
    public Object[][] getGroupException() {

        return new Object[][]{
                {"testRole", "testDomainName"}
        };
    }

    @DataProvider(name = "groupNameWithFilters")
    public Object[][] groupNameWithFilters() throws Exception {

        return new Object[][]{
                {"filter "+SCIMConstants.CommonSchemaConstants.CREATED_URI+" eq 2018/12/01",
                        "testRole", "testDomainName"},
                {"filter "+SCIMConstants.GroupSchemaConstants.DISPLAY_URI+" eq testUser",
                        "testRole", "testDomainName"}
        };
    }

    @Test(dataProvider = "groupNameWithFilters")
    public void testListGroupsWithFilter(String filter, String roleName, String userStoreDomain) throws Exception {

        ExpressionNode node = new ExpressionNode(filter);
        List<String> list = new ArrayList<>();
        list.add(roleName);
        Map<String, Boolean> requiredAttributes = null;
        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);
        when(mockedGroupDAO.getGroupNameList(anyString(), anyString(), anyInt())).thenReturn(list.toArray(new String[0]));
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);

        when(mockedUserStoreManager.isExistingRole(anyString(), anyBoolean())).thenReturn(true);
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfig);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(true);
        when(mockedUserStoreManager.getUserList(anyString(), anyString(),
                anyString())).thenReturn(list.toArray(new String[0]));
        when(mockedUserStoreManager.getRoleListOfUser(anyString())).thenReturn(list.toArray(new String[0]));

        whenNew(RealmConfiguration.class).withAnyArguments().thenReturn(mockRealmConfig);
        when(mockRealmConfig.getAdminRoleName()).thenReturn("admin");
        when(mockRealmConfig.isPrimary()).thenReturn(false);
        when(mockRealmConfig.getUserStoreProperty(anyString())).thenReturn("value");
        when(mockRealmConfig.getEveryOneRoleName()).thenReturn("admin");

        when(mockIdentityUtil.extractDomainFromName(anyString())).thenReturn("value");
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        List<Object> roleList = scimUserManager.listGroupsWithGET(node, 1, 1, null, null,
                requiredAttributes);

        assertEquals(roleList.size(), 2);

    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
