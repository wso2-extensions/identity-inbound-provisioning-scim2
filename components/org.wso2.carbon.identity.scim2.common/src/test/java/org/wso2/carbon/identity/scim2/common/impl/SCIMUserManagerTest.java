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
import org.powermock.api.mockito.PowerMockito;
import org.powermock.api.support.membermodification.MemberModifier;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.test.utils.CommonTestUtils;
import org.wso2.carbon.identity.scim2.common.utils.AttributeMapper;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.testutil.Whitebox;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMAttributeSchema;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.ExpressionNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.anySet;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

/*
 * Unit tests for SCIMUserManager
 */
@PrepareForTest({SCIMGroupHandler.class, IdentityUtil.class, SCIMUserSchemaExtensionBuilder.class,
        SCIMAttributeSchema.class, AttributeMapper.class, ClaimMetadataHandler.class, SCIMCommonUtils.class,
        IdentityTenantUtil.class, AbstractUserStoreManager.class, Group.class, UserCoreUtil.class})
@PowerMockIgnore("java.sql.*")
public class SCIMUserManagerTest extends PowerMockTestCase {

    @Mock
    private AbstractUserStoreManager mockedUserStoreManager;

    @Mock
    private ClaimManager mockedClaimManager;

    @Mock
    private GroupDAO mockedGroupDAO;

    @Mock
    private SCIMAttributeSchema mockedSCIMAttributeSchema;

    @Mock
    private RealmConfiguration mockedRealmConfig;

    @Mock
    private User mockedUser;

    @Mock
    private RealmConfiguration mockRealmConfig;

    @Mock
    private IdentityUtil mockIdentityUtil;

    @Mock
    private ClaimMetadataHandler mockClaimMetadataHandler;

    @Mock
    private RealmService mockRealmService;

    @Mock
    private AbstractUserStoreManager secondaryUserStoreManager;


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
        when(sb.getExtensionSchema()).thenReturn(mockedSCIMAttributeSchema);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn("testPrimaryDomain");

        mockStatic(SCIMCommonUtils.class);
        when(SCIMCommonUtils.convertLocalToSCIMDialect(anyMap(), anyMap())).thenReturn(new HashMap<String, String>() {{
            put(SCIMConstants.CommonSchemaConstants.ID_URI, "1f70378a-69bb-49cf-aa51-a0493c09110c");
        }});

        mockedUserStoreManager = PowerMockito.mock(AbstractUserStoreManager.class);

        MemberModifier.field(AbstractUserStoreManager.class, "userStoreManagerHolder")
                .set(mockedUserStoreManager, new HashMap<String, UserStoreManager>());

        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(secondaryUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(true);
        when(mockedUserStoreManager.getRoleListOfUser(anyString())).thenReturn(userRoles);
        mockStatic(AttributeMapper.class);
        when(AttributeMapper.constructSCIMObjectFromAttributes(anyMap(), anyInt())).thenReturn(mockedUser);
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(mockedRealmConfig.getEveryOneRoleName()).thenReturn("roleName");
        when(mockedUserStoreManager.getTenantId()).thenReturn(1234567);
        org.wso2.carbon.user.core.common.User user = new org.wso2.carbon.user.core.common.User();
        user.setUsername("testUserName");
        user.setUserID(UUID.randomUUID().toString());
        List<org.wso2.carbon.user.core.common.User> users = new ArrayList<>();
        users.add(user);
        when(mockedUserStoreManager.getUserListWithID(eq(UserCoreClaimConstants.USERNAME_CLAIM_URI), anyString(),
                eq(UserCoreConstants.DEFAULT_PROFILE))).thenReturn(users);
        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);
        CommonTestUtils.initPrivilegedCarbonContext(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        mockStatic(ClaimMetadataHandler.class);
        when(ClaimMetadataHandler.getInstance()).thenReturn(mockClaimMetadataHandler);
        when(mockClaimMetadataHandler.getMappingsFromOtherDialectToCarbon(anyString(), anySet(), anyString()))
                .thenReturn(new HashSet<ExternalClaim>());

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

        MemberModifier.field(AbstractUserStoreManager.class, "userStoreManagerHolder")
                .set(mockedUserStoreManager, new HashMap<String, UserStoreManager>());

        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);
        when(mockedGroupDAO.getGroupNameById(anyInt(), anyString())).thenReturn(roleName);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        try {
            scimUserManager.getGroup("1234567", new HashMap<>());
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
                {"filter " + SCIMConstants.CommonSchemaConstants.CREATED_URI + " eq 2018/12/01",
                        "testRole", "testDomainName"},
                {"filter " + SCIMConstants.GroupSchemaConstants.DISPLAY_URI + " eq testUser",
                        "testRole", "testDomainName"}
        };
    }

    @Test(dataProvider = "groupNameWithFilters")
    public void testListGroupsWithFilter(String filter, String roleName, String userStoreDomain) throws Exception {

        ExpressionNode node = new ExpressionNode(filter);
        List<String> list = new ArrayList<>();
        list.add(roleName);

        List<org.wso2.carbon.user.core.common.User> users = new ArrayList<>();
        org.wso2.carbon.user.core.common.User user = new org.wso2.carbon.user.core.common.User();
        user.setUserID(UUID.randomUUID().toString());
        user.setUserStoreDomain(userStoreDomain);
        user.setUsername("testUser");
        users.add(user);

        Map<String, Boolean> requiredAttributes = null;
        Map<String, String> attributes = new HashMap<String, String>() {{
            put(SCIMConstants.CommonSchemaConstants.ID_URI, "1");
        }};
        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);
        when(mockedGroupDAO.getGroupNameList(anyString(), anyString(), anyInt(), anyString()))
                .thenReturn(list.toArray(new String[0]));
        mockStatic(IdentityUtil.class);
        when(mockedGroupDAO.isExistingGroup("testRole", 0)).thenReturn(true);
        when(mockedGroupDAO.getSCIMGroupAttributes(0, "testRole")).thenReturn(attributes);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);

        mockedUserStoreManager = PowerMockito.mock(AbstractUserStoreManager.class);

        MemberModifier.field(AbstractUserStoreManager.class, "userStoreManagerHolder")
                .set(mockedUserStoreManager, new HashMap<String, UserStoreManager>());

        when(mockedUserStoreManager.isExistingRole(anyString(), anyBoolean())).thenReturn(true);
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfig);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(true);
        when(mockedUserStoreManager.getUserListWithID(anyString(), anyString(), anyString())).thenReturn(users);
        when(mockedUserStoreManager.getRoleListOfUserWithID(anyString())).thenReturn(list);

        whenNew(RealmConfiguration.class).withAnyArguments().thenReturn(mockRealmConfig);
        when(mockRealmConfig.getAdminRoleName()).thenReturn("admin");
        when(mockRealmConfig.isPrimary()).thenReturn(false);
        when(mockRealmConfig.getUserStoreProperty(anyString())).thenReturn("value");
        when(mockRealmConfig.getEveryOneRoleName()).thenReturn("admin");

        when(mockIdentityUtil.extractDomainFromName(anyString())).thenReturn("value");

        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName",
                "http://wso2.org/claims/username");
        mockStatic(SCIMCommonUtils.class);
        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        List<Object> roleList = scimUserManager.listGroupsWithGET(node, 1, 1, null, null,
                null, requiredAttributes);

        assertEquals(roleList.size(), 2);

    }

    @Test(dataProvider = "listUser")
    public void testListUsersWithGET(List<org.wso2.carbon.user.core.common.User> users,
                                     boolean isScimEnabledForPrimary, boolean isScimEnabledForSecondary,
                                     int expectedResultCount) throws Exception {

        Map<String, String> scimToLocalClaimMap = new HashMap<>();
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName",
                "http://wso2.org/claims/username");
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:id", "http://wso2.org/claims/userid");

        mockStatic(SCIMCommonUtils.class);
        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimMap);
        when(SCIMCommonUtils.convertLocalToSCIMDialect(anyMap(), anyMap())).thenReturn(new HashMap<String, String>() {{
            put(SCIMConstants.CommonSchemaConstants.ID_URI, "1f70378a-69bb-49cf-aa51-a0493c09110c");
        }});

        mockedUserStoreManager = PowerMockito.mock(AbstractUserStoreManager.class);

        when(mockedUserStoreManager.getUserListWithID("http://wso2.org/claims/userid", "*", null)).thenReturn(users);
        when(mockedUserStoreManager.getRoleListOfUserWithID(anyString())).thenReturn(new ArrayList<>());
        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);
        when(mockedGroupDAO.listSCIMGroups()).thenReturn(anySet());
        when(mockedUserStoreManager.getSecondaryUserStoreManager("PRIMARY")).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(isScimEnabledForPrimary);
        when(mockedUserStoreManager.getSecondaryUserStoreManager("SECONDARY")).thenReturn(secondaryUserStoreManager);
        when(secondaryUserStoreManager.isSCIMEnabled()).thenReturn(isScimEnabledForSecondary);

        mockStatic(IdentityTenantUtil.class);

        when(IdentityTenantUtil.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getBootstrapRealmConfiguration()).thenReturn(mockedRealmConfig);

        HashMap<String, Boolean> requiredClaimsMap = new HashMap<>();
        requiredClaimsMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName", false);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        List<Object> result = scimUserManager.listUsersWithGET(null, 1, 0, null, null, requiredClaimsMap);
        assertEquals(expectedResultCount, result.size());
    }

    @DataProvider(name = "listUser")
    public Object[][] listUser() throws Exception {

        List<org.wso2.carbon.user.core.common.User> users = new ArrayList<org.wso2.carbon.user.core.common.User>() {{
            add(new org.wso2.carbon.user.core.common.User(UUID.randomUUID().toString(), "testUser1", "testUser1"));
            add(new org.wso2.carbon.user.core.common.User(UUID.randomUUID().toString(), "testUser2", "testUser2"));
        }};

        org.wso2.carbon.user.core.common.User user = new org.wso2.carbon.user.core.common.User();
        user.setUserID(UUID.randomUUID().toString());
        user.setUsername("testUser3");
        user.setUserStoreDomain("SECONDARY");

        users.add(user);

        return new Object[][]{

                // If SCIM is enabled for both primary and secondary, result should contain a total of 4 entries,
                // including the metadata in index position.
                {users, true, true, 4},

                // If SCIM is enabled for primary but not for secondary, result should contain 3 entries including
                // the metadata in index position and 2 users [testUser1, testUser2] from primary user-store domain.
                {users, true, false, 3},

                // If SCIM is enabled for secondary but not for primary, result should contain 2 entries including
                // the metadata in index position and 1 users [SECONDARY/testUser3] from secondary user-store domain.
                {users, false, true, 2},

                // If no users are present in user-stores, result should contain a single entry for metadata.
                {Collections.EMPTY_LIST, true, true, 1}
        };
    }

    @Test(dataProvider = "getSearchAttribute")
    public void testGetSearchAttribute(String attributeName, String attributeValue, String expectedValue)
            throws Exception {

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);

        String searchAttribute = Whitebox
                .invokeMethod(scimUserManager, "getSearchAttribute", attributeName, SCIMCommonConstants.CO,
                        attributeValue, "*");

        assertEquals(searchAttribute, expectedValue);
    }

    @DataProvider(name = "getSearchAttribute")
    public Object[][] getSearchAttribute() {

        return new Object[][]{
                {SCIMConstants.UserSchemaConstants.USER_NAME_URI, "user", "*user*"},
                {SCIMConstants.UserSchemaConstants.USER_NAME_URI, "PRIMARY/testUser", "PRIMARY/*testUser*"}
        };
    }

    @Test(dataProvider = "listApplicationRoles")
    public void testListApplicationRolesWithDomainParam(Map<String, Boolean> requiredAttributes, String[] roles,
                                                        Map<String, String> attributes) throws Exception {

        AbstractUserStoreManager abstractUserStoreManager = mock(AbstractUserStoreManager.class);
        when(abstractUserStoreManager.getRoleNames(anyString(), anyInt(), anyBoolean(), anyBoolean(), anyBoolean()))
                .thenReturn(roles);
        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);
        when(mockedGroupDAO.isExistingGroup(anyString(), anyInt())).thenReturn(true);
        when(mockedGroupDAO.getSCIMGroupAttributes(anyInt(), anyString())).thenReturn(attributes);
        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.isEveryoneRole("role", mockedRealmConfig)).thenReturn(false);
        mockStatic(SCIMCommonUtils.class);
        when(SCIMCommonUtils.getSCIMGroupURL()).thenReturn("https://localhost:9443/scim2/Groups");

        SCIMUserManager scimUserManager = new SCIMUserManager(abstractUserStoreManager, mockedClaimManager);
        List<Object> roleList = scimUserManager
                .listGroupsWithGET(null, 1, null, null, null, "Application", requiredAttributes);
        roleList.remove(0);//The first entry is the count of roles.
        assertEquals("Application/Apple", ((Group) roleList.get(0)).getDisplayName());
        assertEquals("Application/MyApp", ((Group) roleList.get(1)).getDisplayName());
        assertEquals(roleList.size(), 2);
    }

    @DataProvider(name = "listApplicationRoles")
    public Object[][] listApplicationRoles() {

        Map<String, Boolean> requiredAttributes = new HashMap<>();
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:Group:members.value", true);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:id", false);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.created", false);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.lastModified", false);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.version", false);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.location", false);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:externalId", false);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.resourceType", false);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:Group:members.$ref", true);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:Group:members.type", true);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:Group:members.display", true);
        requiredAttributes.put("urn:ietf:params:scim:schemas:core:2.0:Group:displayName", true);

        Map<String, String> attributes = new HashMap<>();
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:id", "25850849-eb62-476a-a3ff-641b81cbd251");

        String[] roles = {"Application/Apple", "Application/MyApp"};
        return new Object[][]{
                {requiredAttributes, roles, attributes}
        };
    }

    @Test(dataProvider = "applicationDomainWithFilters")
    public void testFilterApplicationRolesWithDomainParam(String filter, String[] roles, Map<String, String> attributes)
            throws Exception {

        ExpressionNode node = new ExpressionNode(filter);
        Map<String, Boolean> requiredAttributes = null;
        AbstractUserStoreManager abstractUserStoreManager = mock(AbstractUserStoreManager.class);
        when(abstractUserStoreManager.getRoleNames(anyString(), anyInt(), anyBoolean(), anyBoolean(), anyBoolean()))
                .thenReturn(roles);
        when(abstractUserStoreManager.isExistingRole(anyString(), anyBoolean())).thenReturn(true);
        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.isEveryoneRole("role", mockedRealmConfig)).thenReturn(false);
        whenNew(GroupDAO.class).withAnyArguments().thenReturn(mockedGroupDAO);
        when(mockedGroupDAO.isExistingGroup(anyString(), anyInt())).thenReturn(true);
        when(mockedGroupDAO.getSCIMGroupAttributes(anyInt(), anyString())).thenReturn(attributes);
        mockStatic(SCIMCommonUtils.class);
        when(SCIMCommonUtils.getSCIMGroupURL()).thenReturn("https://localhost:9443/scim2/Groups");

        SCIMUserManager scimUserManager = new SCIMUserManager(abstractUserStoreManager, mockedClaimManager);
        List<Object> roleList = scimUserManager
                .listGroupsWithGET(node, 1, null, null, null, "Application", requiredAttributes);
        roleList.remove(0);//The first entry is the count of roles.
        assertEquals("Application/MyApp", ((Group) roleList.get(0)).getDisplayName());
        assertEquals(roleList.size(), 1);
    }

    @DataProvider(name = "applicationDomainWithFilters")
    public Object[][] applicationDomainWithFilters() {

        String startsWithFilter = "filter urn:ietf:params:scim:schemas:core:2.0:Group:displayName sw My";
        String equalsFilter = "filter urn:ietf:params:scim:schemas:core:2.0:Group:displayName eq MyApp";
        String[] roles = {"Application/MyApp"};
        Map<String, String> attributes = new HashMap<>();
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:id", "25850849-eb62-476a-a3ff-641b81cbd251");

        return new Object[][]{
                {startsWithFilter, roles, attributes},
                {equalsFilter, roles, attributes}
        };
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
