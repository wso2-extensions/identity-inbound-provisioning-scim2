/*
 * Copyright (c) 2017, WSO2 LLC. (https://www.wso2.org)
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

package org.wso2.carbon.identity.scim2.common.impl;

import org.apache.commons.lang.StringUtils;
import org.json.JSONObject;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.common.model.InboundProvisioningConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.model.AttributeMapping;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreErrorResolver;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.common.PaginatedUserResponse;
import org.wso2.carbon.user.core.model.UniqueIDUserClaimSearchEntry;
import org.wso2.charon3.core.config.SCIMConfigConstants;
import org.wso2.charon3.core.config.SCIMSystemSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.plainobjects.UsersGetResponse;
import org.wso2.charon3.core.objects.plainobjects.GroupsGetResponse;
import org.wso2.carbon.identity.scim2.common.test.utils.CommonTestUtils;
import org.wso2.carbon.identity.scim2.common.utils.AttributeMapper;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.testutil.Whitebox;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.model.Condition;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.user.mgt.RolePermissionManagementService;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.MultiValuedAttribute;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.AbstractCharonException;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.schema.AttributeSchema;
import org.wso2.charon3.core.schema.SCIMAttributeSchema;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMDefinitions;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.utils.ResourceManagerUtil;
import org.wso2.charon3.core.utils.codeutils.ExpressionNode;
import org.wso2.charon3.core.utils.codeutils.FilterTreeManager;
import org.wso2.charon3.core.utils.codeutils.Node;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.charon3.core.schema.SCIMConstants.CUSTOM_EXTENSION_SCHEMA_URI;
import static org.wso2.charon3.core.schema.SCIMConstants.ENTERPRISE_USER_SCHEMA_URI;

/*
 * Unit tests for SCIMUserManager
 */
public class SCIMUserManagerTest {

    private static final String USERNAME_LOCAL_CLAIM = "http://wso2.org/claims/username";
    private static final String USERID_LOCAL_CLAIM = "http://wso2.org/claims/userid";
    private static final String ROLES_LOCAL_CLAIM = "http://wso2.org/claims/roles";
    private static final String EMAIL_ADDRESS_LOCAL_CLAIM = "http://wso2.org/claims/emailaddress";
    private static final String LASTNAME_LOCAL_CLAIM = "http://wso2.org/claims/lastname";
    private static final String GIVEN_NAME_LOCAL_CLAIM = "http://wso2.org/claims/givenname";
    private static final String NICK_AME_LOCAL_CLAIM = "http://wso2.org/claims/nickname";
    private static final String GROUPS_LOCAL_CLAIM = "http://wso2.org/claims/groups";
    private static final String DISPLAY_NAME_LOCAL_CLAIM = "http://wso2.org/claims/displayName";
    private static final String ADDRESS_LOCALITY_LOCAL_CLAIM = "http://wso2.org/claims/addresses.locality";
    private static final String ADDRESS_REGION_LOCAL_CLAIM = "http://wso2.org/claims/region";
    private static final String ADDRESS_LOCAL_CLAIM = "http://wso2.org/claims/addresses";
    private static final String USER_SCHEMA_ADDRESS_HOME = "urn:ietf:params:scim:schemas:core:2.0:User:addresses.home";
    private static final String USER_SCHEMA_ADDRESS_WORK= "urn:ietf:params:scim:schemas:core:2.0:User:addresses.work";
    private static final String MAX_LIMIT_RESOURCE_NAME = "user-response-limit";
    private static final String SHARED_PROFILE_VALUE_RESOLVING_METHOD_PROPERTY = "sharedProfileValueResolvingMethod";
    private static final String ATTRIBUTE_PROFILES_PROPERTY = "profiles";
    private static final String SUPPORTED_BY_DEFAULT_PROPERTY = "supportedByDefault";

    @Mock
    private AbstractUserStoreManager mockedUserStoreManager;
    @Mock
    private JDBCUserStoreManager mockedJDBCUserStoreManager;

    @Mock
    private ClaimManager mockedClaimManager;

    @Mock
    private GroupDAO mockedGroupDAO;

    @Mock
    private SCIMAttributeSchema mockedSCIMAttributeSchema;

    @Mock
    private AttributeSchema mockedAttributeSchema;

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

    @Mock
    private JDBCUserStoreManager secondaryUserStoreManagerJDBC;

    @Mock
    private ClaimMetadataManagementService mockClaimMetadataManagementService;

    @Mock
    private ApplicationManagementService applicationManagementService;

    @Mock
    private SCIMGroupHandler mockedSCIMGroupHandler;

    @Mock
    private ConfigurationManager mockedConfigurationManager;

    @Mock
    private RolePermissionManagementService mockedRolePermissionManagementService;
    private MockedStatic<SCIMUserSchemaExtensionBuilder> scimUserSchemaExtensionBuilder;
    private MockedStatic<SCIMSystemSchemaExtensionBuilder> scimSystemSchemaExtensionBuilder;
    private MockedStatic<IdentityUtil> identityUtil;
    private MockedStatic<SCIMCommonUtils> scimCommonUtils;
    private MockedStatic<AttributeMapper> attributeMapper;
    private MockedStatic<ClaimMetadataHandler> claimMetadataHandler;
    private MockedStatic<CarbonConstants> carbonConstants;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<ApplicationManagementService> applicationManagementServiceMockedStatic;
    private MockedStatic<SCIMCommonComponentHolder> scimCommonComponentHolder;
    private MockedStatic<ResourceManagerUtil> resourceManagerUtil;
    private MockedStatic<UserCoreUtil> userCoreUtil;

    @BeforeMethod
    public void setUpMethod() {
        initMocks(this);
        identityUtil = mockStatic(IdentityUtil.class);
        scimCommonUtils = mockStatic(SCIMCommonUtils.class);
        carbonConstants = mockStatic(CarbonConstants.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        applicationManagementServiceMockedStatic = mockStatic(ApplicationManagementService.class);
        scimCommonComponentHolder = mockStatic(SCIMCommonComponentHolder.class);
        scimUserSchemaExtensionBuilder = mockStatic(SCIMUserSchemaExtensionBuilder.class);
        scimSystemSchemaExtensionBuilder = mockStatic(SCIMSystemSchemaExtensionBuilder.class);
        claimMetadataHandler = mockStatic(ClaimMetadataHandler.class);
        resourceManagerUtil = mockStatic(ResourceManagerUtil.class);
        SCIMUserSchemaExtensionBuilder mockSCIMUserSchemaExtensionBuilder = mock(SCIMUserSchemaExtensionBuilder.class);
        SCIMSystemSchemaExtensionBuilder mockSCIMSystemSchemaExtensionBuilder = mock(SCIMSystemSchemaExtensionBuilder.class);
        scimUserSchemaExtensionBuilder.when(SCIMUserSchemaExtensionBuilder::getInstance).thenReturn(mockSCIMUserSchemaExtensionBuilder);
        when(mockSCIMUserSchemaExtensionBuilder.getExtensionSchema()).thenReturn(mockedSCIMAttributeSchema);
        when(mockedSCIMAttributeSchema.getURI()).thenReturn(ENTERPRISE_USER_SCHEMA_URI)
                .thenReturn(CUSTOM_EXTENSION_SCHEMA_URI);
        scimSystemSchemaExtensionBuilder.when(SCIMSystemSchemaExtensionBuilder::getInstance).thenReturn(mockSCIMSystemSchemaExtensionBuilder);
        when(mockSCIMSystemSchemaExtensionBuilder.getExtensionSchema()).thenReturn(mockedSCIMAttributeSchema);
    }

    @AfterMethod
    public void tearDown() {
        identityUtil.close();
        scimCommonUtils.close();
        carbonConstants.close();
        identityTenantUtil.close();
        applicationManagementServiceMockedStatic.close();
        scimCommonComponentHolder.close();
        scimUserSchemaExtensionBuilder.close();
        scimSystemSchemaExtensionBuilder.close();
        claimMetadataHandler.close();
        resourceManagerUtil.close();
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
        scimUserSchemaExtensionBuilder.when(SCIMUserSchemaExtensionBuilder::getInstance).thenReturn(sb);
        when(sb.getExtensionSchema()).thenReturn(mockedSCIMAttributeSchema);

        identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenReturn("testPrimaryDomain");

        scimCommonUtils.when(() -> SCIMCommonUtils.convertLocalToSCIMDialect(anyMap(), anyMap())).thenReturn(new HashMap<String, String>() {{
            put(SCIMConstants.CommonSchemaConstants.ID_URI, "1f70378a-69bb-49cf-aa51-a0493c09110c");
        }});

        mockedUserStoreManager = mock(AbstractUserStoreManager.class);

        Field userStoreManagerHolderField = AbstractUserStoreManager.class.getDeclaredField("userStoreManagerHolder");
        userStoreManagerHolderField.setAccessible(true);
        userStoreManagerHolderField.set(mockedUserStoreManager, new HashMap<String, UserStoreManager>());

        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(secondaryUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(true);
        when(mockedUserStoreManager.getRoleListOfUser(anyString())).thenReturn(userRoles);
        attributeMapper = mockStatic(AttributeMapper.class);
        attributeMapper.when(() -> AttributeMapper.constructSCIMObjectFromAttributes(any(), anyMap(), anyInt())).thenReturn(mockedUser);
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(mockedRealmConfig.getEveryOneRoleName()).thenReturn("roleName");
        when(mockedUserStoreManager.getTenantId()).thenReturn(1234567);
        org.wso2.carbon.user.core.common.User user = new org.wso2.carbon.user.core.common.User();
        user.setUsername("testUserName");
        user.setUserID(UUID.randomUUID().toString());
        when(mockedUserStoreManager.getUser(anyString(), nullable(String.class))).thenReturn(user);
        CommonTestUtils.initPrivilegedCarbonContext(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
        when(mockClaimMetadataHandler.getMappingsFromOtherDialectToCarbon(anyString(), anySet(), anyString()))
                .thenReturn(new HashSet<ExternalClaim>());

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        assertNotNull(scimUserManager.getMe("testUserName", required));
        attributeMapper.close();
    }

    @Test(dataProvider = "groupName")
    public void testGetGroup(String groupId, String roleName, String userStoreDomain, Object expected)
            throws Exception {

        when(mockedGroupDAO.getGroupNameById(anyInt(), anyString())).thenReturn(roleName);
        identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);
        when(mockedUserStoreManager.getGroup(groupId, null)).
                thenReturn(buildUserCoreGroupResponse(roleName, groupId, userStoreDomain));
        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMGroupURL()).thenReturn("https://localhost:9443/scim2/Groups");

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        Group result = scimUserManager.getGroup(groupId, new HashMap<>());
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
                {"123456", null, "userStoreDomain", null},
                {"567890", "roleName", null, "roleName"}
        };
    }

    @Test(dataProvider = "getGroupException")
    public void testGetGroupWithExceptions(String roleName, String userStoreDomain) throws Exception {

        AbstractUserStoreManager mockedUserStoreManager = mock(AbstractUserStoreManager.class);
        Field field = AbstractUserStoreManager.class.getDeclaredField("userStoreManagerHolder");
        field.setAccessible(true);
        field.set(mockedUserStoreManager, new HashMap<String, UserStoreManager>());

        when(mockedGroupDAO.getGroupNameById(anyInt(), anyString())).thenReturn(roleName);
        identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);

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
        when(mockedGroupDAO.getGroupNameList(anyString(), anyString(), anyInt(), anyString()))
                .thenReturn(list.toArray(new String[0]));
        when(mockedGroupDAO.isExistingGroup("testRole", 0)).thenReturn(true);
        when(mockedGroupDAO.getSCIMGroupAttributes(0, "testRole")).thenReturn(attributes);
        identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);

        mockedUserStoreManager = mock(AbstractUserStoreManager.class);

        AbstractUserStoreManager mockedUserStoreManager = mock(AbstractUserStoreManager.class);
        Field field = AbstractUserStoreManager.class.getDeclaredField("userStoreManagerHolder");
        field.setAccessible(true);
        field.set(mockedUserStoreManager, new HashMap<String, UserStoreManager>());

        when(mockedUserStoreManager.isExistingRole(anyString(), anyBoolean())).thenReturn(true);
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfig);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(true);
        when(mockedUserStoreManager.getUserListWithID(anyString(), anyString(), anyString())).thenReturn(users);
        when(mockedUserStoreManager.getRoleListOfUserWithID(anyString())).thenReturn(list);
        org.wso2.carbon.user.core.common.Group[] groupsArray = {buildUserCoreGroupResponse(roleName, "1234",
                "dummyDomain")};
        when(mockedUserStoreManager.listGroups(any(Condition.class), anyString(), anyInt(),
                anyInt(), nullable(String.class), nullable(String.class))).thenReturn(Arrays.asList(groupsArray.clone()));
        when(mockedUserStoreManager.getGroupByGroupName(roleName, null)).
                thenReturn(buildUserCoreGroupResponse(roleName, "123456789", null));
        when(mockRealmConfig.getAdminRoleName()).thenReturn("admin");
        when(mockRealmConfig.isPrimary()).thenReturn(false);
        when(mockRealmConfig.getUserStoreProperty(anyString())).thenReturn("value");
        when(mockRealmConfig.getEveryOneRoleName()).thenReturn("admin");

        when(mockIdentityUtil.extractDomainFromName(anyString())).thenReturn("value");

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;

        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName",
                "http://wso2.org/claims/username");
        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        GroupsGetResponse groupsResponse = scimUserManager.listGroupsWithGET(node, 1, 1, null, null,
                null, requiredAttributes);

        assertEquals(groupsResponse.getGroups().size(), 1);

    }

    @Test(dataProvider = "listUser")
    public void testListUsersWithGET(List<org.wso2.carbon.user.core.common.User> users,
                                     boolean isScimEnabledForPrimary, boolean isScimEnabledForSecondary,
                                     int expectedResultCount) throws Exception {

        Map<String, String> scimToLocalClaimMap = new HashMap<>();
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName",
                "http://wso2.org/claims/username");
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:id", "http://wso2.org/claims/userid");

        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimMap);
        scimCommonUtils.when(() -> SCIMCommonUtils.convertLocalToSCIMDialect(anyMap(), anyMap())).thenReturn(new HashMap<String, String>() {{
            put(SCIMConstants.CommonSchemaConstants.ID_URI, "1f70378a-69bb-49cf-aa51-a0493c09110c");
        }});

        when(mockedUserStoreManager.getUserListWithID("http://wso2.org/claims/userid", "*", null)).thenReturn(users);
        when(mockedUserStoreManager.getRoleListOfUserWithID(anyString())).thenReturn(new ArrayList<>());
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(mockedRealmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME))
                .thenReturn("PRIMARY");
        when(mockedUserStoreManager.getSecondaryUserStoreManager("PRIMARY")).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(isScimEnabledForPrimary);
        when(mockedUserStoreManager.getSecondaryUserStoreManager("SECONDARY")).thenReturn(secondaryUserStoreManager);
        when(secondaryUserStoreManager.isSCIMEnabled()).thenReturn(isScimEnabledForSecondary);

        identityTenantUtil.when(() -> IdentityTenantUtil.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getBootstrapRealmConfiguration()).thenReturn(mockedRealmConfig);

        HashMap<String, Boolean> requiredClaimsMap = new HashMap<>();
        requiredClaimsMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName", false);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        UsersGetResponse result = scimUserManager.listUsersWithGET(null, 1, 0, null, null, requiredClaimsMap);
        assertEquals(result.getUsers().size(), expectedResultCount);
    }

    @DataProvider(name = "listUser")
    public Object[][] listUser() throws Exception {

        List<org.wso2.carbon.user.core.common.User> users = new ArrayList<>();

        org.wso2.carbon.user.core.common.User user1 = new org.wso2.carbon.user.core.common.User();
        user1.setUserID(UUID.randomUUID().toString());
        user1.setUsername("testUser1");
        user1.setUserStoreDomain("PRIMARY");

        org.wso2.carbon.user.core.common.User user2 = new org.wso2.carbon.user.core.common.User();
        user2.setUserID(UUID.randomUUID().toString());
        user2.setUsername("testUser2");
        user2.setUserStoreDomain("PRIMARY");

        org.wso2.carbon.user.core.common.User user3 = new org.wso2.carbon.user.core.common.User();
        user3.setUserID(UUID.randomUUID().toString());
        user3.setUsername("testUser3");
        user3.setUserStoreDomain("SECONDARY");

        users.add(user1);
        users.add(user2);
        users.add(user3);

        return new Object[][]{

                // If SCIM is enabled for both primary and secondary, result should contain a total of 4 entries,
                // including the metadata in index position.
                {users, true, true, 3},

                // If SCIM is enabled for primary but not for secondary, result should contain 3 entries including
                // the metadata in index position and 2 users [testUser1, testUser2] from primary user-store domain.
                {users, true, false, 2},

                // If SCIM is enabled for secondary but not for primary, result should contain 2 entries including
                // the metadata in index position and 1 users [SECONDARY/testUser3] from secondary user-store domain.
                {users, false, true, 1},

                // If no users are present in user-stores, result should contain a single entry for metadata.
                {Collections.EMPTY_LIST, true, true, 0}
        };
    }

    @Test(dataProvider = "userInfoForFiltering")
    public void testFilteringUsersWithGET(List<org.wso2.carbon.user.core.common.User> users, String filter,
                                          int expectedResultCount, List<org.wso2.carbon.user.core.common.User>
                                                  filteredUsers) throws Exception {

        Map<String, String> scimToLocalClaimMap = new HashMap<>();
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName",
                "http://wso2.org/claims/username");
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:id", "http://wso2.org/claims/userid");
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:User:emails",
                "http://wso2.org/claims/emailaddress");
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:User:name.givenName",
                "http://wso2.org/claims/givenname");

        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimMap);
        scimCommonUtils.when(() -> SCIMCommonUtils.convertLocalToSCIMDialect(anyMap(), anyMap())).thenReturn(new HashMap<String, String>() {{
            put(SCIMConstants.CommonSchemaConstants.ID_URI, "1f70378a-69bb-49cf-aa51-a0493c09110c");
        }});

        mockedUserStoreManager = mock(AbstractUserStoreManager.class);

        when(mockedUserStoreManager.getUserListWithID("http://wso2.org/claims/userid", "*", null)).thenReturn(users);
        when(mockedUserStoreManager.getUserListWithID("http://wso2.org/claims/givenname", "testUser", "default"))
                .thenReturn(filteredUsers);
        when(mockedUserStoreManager.getUserListWithID(any(Condition.class), anyString(), anyString(), anyInt(),
                anyInt(), nullable(String.class), nullable(String.class))).thenReturn(filteredUsers);
        when(mockedUserStoreManager.getPaginatedUserListWithID(any(Condition.class), anyString(), anyString(), anyInt(),
                anyInt(), nullable(String.class), nullable(String.class)))
                .thenReturn(new PaginatedUserResponse(filteredUsers));
        when(mockedUserStoreManager.getRoleListOfUserWithID(anyString())).thenReturn(new ArrayList<>());
        when(mockedUserStoreManager.getSecondaryUserStoreManager("PRIMARY")).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(true);

        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(mockedRealmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST))
                .thenReturn("100");

        identityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(mockRealmService);
        when(mockRealmService.getBootstrapRealmConfiguration()).thenReturn(mockedRealmConfig);
        identityUtil.when(IdentityUtil::isGroupsVsRolesSeparationImprovementsEnabled).thenReturn(false);

        ClaimMapping[] claimMappings = getTestClaimMappings();
        when(mockedClaimManager.getAllClaimMappings(anyString())).thenReturn(claimMappings);

        HashMap<String, Boolean> requiredClaimsMap = new HashMap<>();
        requiredClaimsMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName", false);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);

        Node node = null;
        if (StringUtils.isNotBlank(filter)) {
            SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
            FilterTreeManager filterTreeManager = new FilterTreeManager(filter, schema);
            node = filterTreeManager.buildTree();
        }

        UsersGetResponse result = scimUserManager.listUsersWithGET(node, 1, null, null, null, null,
                requiredClaimsMap);
        assertEquals(result.getUsers().size(), expectedResultCount);
    }

    @Test
    public void testFilteringUsersOfGroupWithGET() throws org.wso2.carbon.user.api.UserStoreException,
            IOException, BadRequestException, NotImplementedException, CharonException {

        String domain = "PRIMARY";
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockedClaimManager);
        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        FilterTreeManager filterTreeManager = new FilterTreeManager("groups eq admin", schema);
        Node node = filterTreeManager.buildTree();

        org.wso2.carbon.user.core.common.User testUser1 = new org.wso2.carbon.user.core.common.User(UUID.randomUUID()
                .toString(), "testUser1", "testUser1");
        testUser1.setUserStoreDomain("PRIMARY");
        List<org.wso2.carbon.user.core.common.User> filteredUsers = new ArrayList<>();
        filteredUsers.add(testUser1);

        scimCommonUtils.when(() -> SCIMCommonUtils.convertLocalToSCIMDialect(anyMap(), anyMap())).thenReturn(new HashMap<String, String>() {{
            put(SCIMConstants.CommonSchemaConstants.ID_URI, "1f70378a-69bb-49cf-aa51-a0493c09110c");
        }});

        when(mockedUserStoreManager.getSecondaryUserStoreManager(domain)).thenReturn(mockedJDBCUserStoreManager);
        when(mockedJDBCUserStoreManager.isSCIMEnabled()).thenReturn(true);
        scimCommonUtils.when(SCIMCommonUtils::isGroupBasedUserFilteringImprovementsEnabled).thenReturn(true);

        when(mockedUserStoreManager.getRoleNames(anyString(), anyInt(), anyBoolean(), anyBoolean(), anyBoolean()))
                .thenReturn(new String[]{"admin"});

        ClaimMapping[] claimMappings = getTestClaimMappings();
        when(mockedClaimManager.getAllClaimMappings(anyString())).thenReturn(claimMappings);
        when(mockedUserStoreManager.getUserListWithID(any(), anyString(), anyString(), anyInt(), anyInt(), nullable(String.class), nullable(String.class))).thenReturn(filteredUsers);

        UsersGetResponse result = scimUserManager.listUsersWithGET(node, 1, filteredUsers.size(), null, null, domain, new HashMap<>());
        assertEquals(result.getUsers().size(), filteredUsers.size());

    }

    @DataProvider(name = "userInfoForFiltering")
    public Object[][] userInfoForFiltering() {

        List<org.wso2.carbon.user.core.common.User> users = new ArrayList<org.wso2.carbon.user.core.common.User>();

        org.wso2.carbon.user.core.common.User testUser1 = new org.wso2.carbon.user.core.common.User(UUID.randomUUID()
                .toString(), "testUser1", "testUser1");
        Map<String, String> testUser1Attributes = new HashMap<>();
        testUser1Attributes.put("http://wso2.org/claims/givenname", "testUser");
        testUser1Attributes.put("http://wso2.org/claims/emailaddress", "testUser1@wso2.com");
        testUser1.setAttributes(testUser1Attributes);
        testUser1.setUserStoreDomain("PRIMARY");
        users.add(testUser1);

        org.wso2.carbon.user.core.common.User testUser2 = new org.wso2.carbon.user.core.common.User(UUID.randomUUID()
                .toString(), "testUser2", "testUser2");
        Map<String, String> testUser2Attributes = new HashMap<>();
        testUser2Attributes.put("http://wso2.org/claims/givenname", "testUser");
        testUser2Attributes.put("http://wso2.org/claims/emailaddress", "testUser2@wso2.com");
        testUser2.setAttributes(testUser2Attributes);
        testUser2.setUserStoreDomain("PRIMARY");
        users.add(testUser2);

        return new Object[][]{

                {users, "name.givenName eq testUser", 2,
                        new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                            add(testUser2);
                        }}},
                {users, "name.givenName eq testUser and emails eq testUser1@wso2.com", 1,
                        new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                        }}}
        };
    }

    @Test(dataProvider = "getDataForFilterUsersWithPagination")
    public void testFilteringUsersWithGETWithPagination(List<org.wso2.carbon.user.core.common.User> users, String filter,
                                                        PaginatedUserResponse filteredUsersWithPagination,
                                                        PaginatedUserResponse filteredUsersWithoutPagination,
                                                        boolean isConsiderTotalRecordsForTotalResultOfLDAPEnabled,
                                                        boolean isConsiderMaxLimitForTotalResultEnabled,
                                                        String domain, int count, int configuredMaxLimit, int expectedResultCount,
                                                        int expectedTotalCount) throws Exception {

        Map<String, String> scimToLocalClaimMap = new HashMap<>();
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName",
                "http://wso2.org/claims/username");
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:id", "http://wso2.org/claims/userid");
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:User:emails",
                "http://wso2.org/claims/emailaddress");
        scimToLocalClaimMap.put("urn:ietf:params:scim:schemas:core:2.0:User:name.givenName",
                "http://wso2.org/claims/givenname");

        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimMap);
        scimCommonUtils.when(() -> SCIMCommonUtils.convertLocalToSCIMDialect(anyMap(), anyMap())).thenReturn(new HashMap<String, String>() {{
            put(SCIMConstants.CommonSchemaConstants.ID_URI, "1f70378a-69bb-49cf-aa51-a0493c09110c");
        }});

        mockedUserStoreManager = mock(AbstractUserStoreManager.class);

        when(mockedUserStoreManager.getUserListWithID(any(Condition.class), anyString(), anyString(), anyInt(),
                anyInt(), nullable(String.class), nullable(String.class)))
                .thenReturn(filteredUsersWithPagination.getFilteredUsers());

        when(mockedUserStoreManager.getPaginatedUserListWithID(any(Condition.class), anyString(), anyString(), eq(count),
                anyInt(), nullable(String.class), nullable(String.class))).thenReturn(filteredUsersWithPagination);

        when(mockedUserStoreManager.getPaginatedUserListWithID(any(Condition.class), anyString(), anyString(), eq(configuredMaxLimit),
                anyInt(), nullable(String.class), nullable(String.class))).thenReturn(filteredUsersWithoutPagination);

        when(mockedUserStoreManager.getPaginatedUserListWithID(any(Condition.class), anyString(), anyString(), eq(Integer.MAX_VALUE),
                anyInt(), nullable(String.class), nullable(String.class))).thenReturn(filteredUsersWithoutPagination);

        when(mockedUserStoreManager.getUsersCount(any(Condition.class), anyString(), anyString(), eq(count),
                anyInt(), anyBoolean())).thenReturn(filteredUsersWithPagination.getFilteredUsers().size());

        when(mockedUserStoreManager.getUsersCount(any(Condition.class), anyString(), anyString(), eq(configuredMaxLimit),
                anyInt(), anyBoolean())).thenReturn(filteredUsersWithoutPagination.getFilteredUsers().size());

        when(mockedUserStoreManager.getUsersCount(any(Condition.class), anyString(), anyString(), eq(Integer.MAX_VALUE),
                anyInt(), anyBoolean())).thenReturn(filteredUsersWithoutPagination.getFilteredUsers().size());

        when(mockedUserStoreManager.getRoleListOfUserWithID(anyString())).thenReturn(new ArrayList<>());

        if(domain.equals("PRIMARY")){
            when(mockedUserStoreManager.getSecondaryUserStoreManager(null)).thenReturn(mockedUserStoreManager);
        } else {
            when(mockedUserStoreManager.getSecondaryUserStoreManager(null)).thenReturn(secondaryUserStoreManager);
        }

        when(mockedUserStoreManager.getSecondaryUserStoreManager("PRIMARY")).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(true);
        when(mockedUserStoreManager.getSecondaryUserStoreManager("SECONDARY")).thenReturn(secondaryUserStoreManagerJDBC);
        when(secondaryUserStoreManager.isSCIMEnabled()).thenReturn(true);

        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(secondaryUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(secondaryUserStoreManagerJDBC.getRealmConfiguration()).thenReturn(mockedRealmConfig);

        when(mockedRealmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST))
                .thenReturn(Integer.toString(configuredMaxLimit));


        when(secondaryUserStoreManagerJDBC.countUsersWithClaims(anyString(), anyString())).thenReturn(
                Long.valueOf(users.size()));

        identityTenantUtil.when(() -> IdentityTenantUtil.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getBootstrapRealmConfiguration()).thenReturn(mockedRealmConfig);

        ClaimMapping[] claimMappings = getTestClaimMappings();
        when(mockedClaimManager.getAllClaimMappings(anyString())).thenReturn(claimMappings);

        HashMap<String, Boolean> requiredClaimsMap = new HashMap<>();
        requiredClaimsMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName", false);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager, mockClaimMetadataManagementService,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        Node node = null;
        if (StringUtils.isNotBlank(filter)) {
            SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
            FilterTreeManager filterTreeManager = new FilterTreeManager(filter, schema);
            node = filterTreeManager.buildTree();
        }

        scimCommonUtils.when(() -> SCIMCommonUtils.isConsiderTotalRecordsForTotalResultOfLDAPEnabled())
                .thenReturn(isConsiderTotalRecordsForTotalResultOfLDAPEnabled);
        scimCommonUtils.when(() -> SCIMCommonUtils.isConsiderMaxLimitForTotalResultEnabled())
                .thenReturn(isConsiderMaxLimitForTotalResultEnabled);

        Map<String, String> supportedByDefaultProperties = new HashMap<String, String>() {{
            put("SupportedByDefault", "true");
            put("ReadOnly", "true");
        }};

        String claimDialectUri = SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT;
        AttributeMapping usernameAttributePrimary = new AttributeMapping("PRIMARY", "http://wso2.org/claims/username");
        AttributeMapping usernameAttributeSecondary = new AttributeMapping("SECONDARY", "http://wso2.org/claims/username");
        List<AttributeMapping> usernameAttributeList = new ArrayList<>();
        usernameAttributeList.add(usernameAttributePrimary);
        usernameAttributeList.add(usernameAttributeSecondary);

        AttributeMapping givenNameAttributePrimary = new AttributeMapping("PRIMARY", "http://wso2.org/claims/givenname");
        AttributeMapping givenNameAttributeSecondary = new AttributeMapping("SECONDARY", "http://wso2.org/claims/givenname");
        List<AttributeMapping> givenNameAttributeList = new ArrayList<>();
        givenNameAttributeList.add(givenNameAttributePrimary);
        givenNameAttributeList.add(givenNameAttributeSecondary);

        AttributeMapping emailAttributePrimary = new AttributeMapping("PRIMARY", "http://wso2.org/claims/emailaddress");
        AttributeMapping emailAttributeSecondary = new AttributeMapping("SECONDARY", "http://wso2.org/claims/emailaddress");
        List<AttributeMapping> emailAttributeList = new ArrayList<>();
        emailAttributeList.add(emailAttributePrimary);
        emailAttributeList.add(emailAttributeSecondary);
        List<LocalClaim> localClaimList = new ArrayList<LocalClaim>() {{
            add(new LocalClaim(USERNAME_LOCAL_CLAIM, usernameAttributeList, null));
            add(new LocalClaim(GIVEN_NAME_LOCAL_CLAIM, givenNameAttributeList, supportedByDefaultProperties));
            add(new LocalClaim(EMAIL_ADDRESS_LOCAL_CLAIM, emailAttributeList, supportedByDefaultProperties));
        }};

        List<ExternalClaim> externalClaimList = new ArrayList<ExternalClaim>() {{
            add(new ExternalClaim(claimDialectUri, claimDialectUri + ":userName", USERNAME_LOCAL_CLAIM));
            add(new ExternalClaim(claimDialectUri, claimDialectUri + ":name.givenName", GIVEN_NAME_LOCAL_CLAIM));
            add(new ExternalClaim(claimDialectUri, claimDialectUri + ":emails", EMAIL_ADDRESS_LOCAL_CLAIM));
        }};

        when(mockClaimMetadataManagementService.getLocalClaims(anyString())).thenReturn(localClaimList);
        when(mockClaimMetadataManagementService.getExternalClaims(anyString(), anyString())).thenReturn(externalClaimList);
        CommonTestUtils.initPrivilegedCarbonContext();
        UsersGetResponse userResponse = scimUserManager.listUsersWithGET(node, 1, count, null, null, domain,
                requiredClaimsMap);

        assertEquals(expectedResultCount, userResponse.getUsers().size());
        assertEquals(expectedTotalCount, userResponse.getTotalUsers());
    }

    @DataProvider(name = "getDataForFilterUsersWithPagination")
    public Object[][] getDataForFilterUsersWithPagination() {

        List<org.wso2.carbon.user.core.common.User> users = new ArrayList<org.wso2.carbon.user.core.common.User>();
        org.wso2.carbon.user.core.common.User testUser1 = new org.wso2.carbon.user.core.common.User(UUID.randomUUID()
                .toString(), "testUser1", "testUser1");
        Map<String, String> testUser1Attributes = new HashMap<>();
        testUser1Attributes.put("http://wso2.org/claims/givenname", "testUser");
        testUser1Attributes.put("http://wso2.org/claims/emailaddress", "testUser1@wso2.com");
        testUser1.setAttributes(testUser1Attributes);
        users.add(testUser1);

        org.wso2.carbon.user.core.common.User testUser2 = new org.wso2.carbon.user.core.common.User(UUID.randomUUID()
                .toString(), "testUser2", "testUser2");
        Map<String, String> testUser2Attributes = new HashMap<>();
        testUser2Attributes.put("http://wso2.org/claims/givenname", "testUser");
        testUser2Attributes.put("http://wso2.org/claims/emailaddress", "testUser2@wso2.com");
        testUser2.setAttributes(testUser2Attributes);
        users.add(testUser2);

        org.wso2.carbon.user.core.common.User testUser3 = new org.wso2.carbon.user.core.common.User(UUID.randomUUID()
                .toString(), "testUser3", "testUser3");
        Map<String, String> testUser3Attributes = new HashMap<>();
        testUser3Attributes.put("http://wso2.org/claims/givenname", "testUser");
        testUser3Attributes.put("http://wso2.org/claims/emailaddress", "testUser3@wso2.com");
        testUser3.setAttributes(testUser3Attributes);
        users.add(testUser3);

        org.wso2.carbon.user.core.common.User testUser4 = new org.wso2.carbon.user.core.common.User(UUID.randomUUID()
                .toString(), "testUser4", "testUser4");
        Map<String, String> testUser4Attributes = new HashMap<>();
        testUser4Attributes.put("http://wso2.org/claims/givenname", "testUserNew");
        testUser4Attributes.put("http://wso2.org/claims/emailaddress", "testUser4@wso2.com");
        testUser4.setAttributes(testUser4Attributes);
        users.add(testUser4);

        org.wso2.carbon.user.core.common.User testUser5 = new org.wso2.carbon.user.core.common.User(UUID.randomUUID()
                .toString(), "testUser5", "testUser5");
        Map<String, String> testUser5Attributes = new HashMap<>();
        testUser5Attributes.put("http://wso2.org/claims/givenname", "testUserNew");
        testUser5Attributes.put("http://wso2.org/claims/emailaddress", "testUser2@wso2.com");
        testUser5.setAttributes(testUser5Attributes);
        users.add(testUser5);

        return new Object[][]{

                // Following are the arguments passed from the data provider respectively.
                // List of all the existing users in the user store.
                // Filter criteria.
                // Filtered user list for the given user criteria considering the pagination parameter.
                // Filtered user list for the given user criteria without considering the pagination parameter.
                // Whether the scim2.consider_total_records_for_total_results_of_ldap is enabled or not.
                // Whether the scim2.consider_max_limit_for_total_results is enabled or not.
                // Domain name.
                // Limit (items per page).
                // Configured value for PROPERTY_MAX_USER_LIST of the user store manager.
                // Length of the expected result array.
                // value of the 'totalResult'.

                {users, "name.givenName eq testUser",
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                            add(testUser2);
                        }}),
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                            add(testUser2);
                            add(testUser3);
                        }}),
                        true, false, "PRIMARY", 2, 4, 2, 3},
                {users, "name.givenName eq testUser",
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                            add(testUser2);
                        }}),
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                            add(testUser2);
                            add(testUser3);
                        }}),
                        false, false, "PRIMARY", 2, 4, 2, 2},

                {users, "name.givenName eq testUser",
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                            add(testUser2);
                        }}),
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                            add(testUser2);
                            add(testUser3);
                        }}),
                        true, false, "SECONDARY", 2, 4, 2, 3},
                {users, "name.givenName eq testUser",
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                            add(testUser2);
                        }}),
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser1);
                            add(testUser2);
                            add(testUser3);
                        }}),
                        true, true, "SECONDARY", 2, 4, 2, 3},

                {users, "name.givenName sw testUser and name.givenName co New",
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser4);
                        }}),
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser4);
                            add(testUser5);
                        }}),
                        true, false, "PRIMARY", 1, 4, 1, 2},
                {users, "name.givenName sw testUser and name.givenName co New",
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser4);
                        }}),
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser4);
                            add(testUser5);
                        }}),
                        false, false, "PRIMARY", 1, 4, 1, 1},

                {users, "name.givenName sw testUser and name.givenName co New",
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser4);
                        }}),
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser4);
                            add(testUser5);
                        }}),
                        true, false, "SECONDARY", 1, 4, 1, 2},
                {users, "name.givenName sw testUser and name.givenName co New",
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser4);
                        }}),
                        new PaginatedUserResponse(new ArrayList<org.wso2.carbon.user.core.common.User>() {{
                            add(testUser4);
                            add(testUser5);
                        }}),
                        false, false, "SECONDARY", 1, 4, 1, 2},

        };
    }

    private ClaimMapping[] getTestClaimMappings() {

        ClaimMapping[] claimMappings = new ClaimMapping[3];

        Claim claim1 = new Claim();
        claim1.setClaimUri("urn:ietf:params:scim:schemas:core:2.0:User:userName");
        ClaimMapping claimMapping1 = new ClaimMapping();
        claimMapping1.setClaim(claim1);
        claimMapping1.setMappedAttribute("PRIMARY", "http://wso2.org/claims/username");
        claimMapping1.setMappedAttribute("SECONDARY", "http://wso2.org/claims/username");
        claimMappings[0] = claimMapping1;

        Claim claim2 = new Claim();
        claim2.setClaimUri("urn:ietf:params:scim:schemas:core:2.0:User:emails");
        ClaimMapping claimMapping2 = new ClaimMapping();
        claimMapping2.setClaim(claim2);
        claimMapping2.setMappedAttribute("PRIMARY", "http://wso2.org/claims/emailaddress");
        claimMapping2.setMappedAttribute("SECONDARY", "http://wso2.org/claims/emailaddress");
        claimMappings[1] = claimMapping2;

        Claim claim3 = new Claim();
        claim3.setClaimUri("urn:ietf:params:scim:schemas:core:2.0:User:name.givenName");
        ClaimMapping claimMapping3 = new ClaimMapping();
        claimMapping3.setClaim(claim3);
        claimMapping3.setMappedAttribute("PRIMARY", "http://wso2.org/claims/givenname");
        claimMapping3.setMappedAttribute("SECONDARY", "http://wso2.org/claims/givenname");
        claimMappings[2] = claimMapping3;

        return claimMappings;
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
        for (String role : roles) {
            when(abstractUserStoreManager.getGroupByGroupName(role, null)).
                    thenReturn(buildUserCoreGroupResponse(role, "123456789", null));
        }
        when(mockedGroupDAO.isExistingGroup(anyString(), anyInt())).thenReturn(true);
        when(mockedGroupDAO.getSCIMGroupAttributes(anyInt(), anyString())).thenReturn(attributes);
        userCoreUtil = mockStatic(UserCoreUtil.class);
        userCoreUtil.when(() -> UserCoreUtil.isEveryoneRole("role", mockedRealmConfig)).thenReturn(false);
        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMGroupURL()).thenReturn("https://localhost:9443/scim2/Groups");

        try (MockedConstruction<SCIMGroupHandler> mocked = mockConstruction(SCIMGroupHandler.class,
                (mock, context) -> {
                    when(mock.listSCIMRoles()).thenReturn(new HashSet<>(Arrays.asList(roles)));
                })) {

            CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
            identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenReturn("Application");
            SCIMUserManager scimUserManager = new SCIMUserManager(abstractUserStoreManager, mockedClaimManager);
            GroupsGetResponse groupsResponse = scimUserManager
                    .listGroupsWithGET(null, 1, null, null, null, "Application", requiredAttributes);

            assertEquals(groupsResponse.getGroups().get(0).getDisplayName(), "Application/Apple");
            assertEquals(groupsResponse.getGroups().get(1).getDisplayName(), "Application/MyApp");
            assertEquals(groupsResponse.getGroups().size(), 2);
        }
        userCoreUtil.close();
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
        for(String role: roles){
            when(abstractUserStoreManager.getGroupByGroupName(role, null)).
                    thenReturn(buildUserCoreGroupResponse(role, "123456", "dummyDomain"));
        }
        userCoreUtil = mockStatic(UserCoreUtil.class);
        userCoreUtil.when(() -> UserCoreUtil.isEveryoneRole("role", mockedRealmConfig)).thenReturn(false);
        when(mockedGroupDAO.isExistingGroup(anyString(), anyInt())).thenReturn(true);
        when(mockedGroupDAO.getSCIMGroupAttributes(anyInt(), anyString())).thenReturn(attributes);
        scimCommonUtils.when(() -> SCIMCommonUtils.getSCIMGroupURL()).thenReturn("https://localhost:9443/scim2/Groups");

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenReturn("Application");
        SCIMUserManager scimUserManager = new SCIMUserManager(abstractUserStoreManager, mockedClaimManager);
        GroupsGetResponse groupsResponse = scimUserManager
                .listGroupsWithGET(node, 1, null, null, null, "Application", requiredAttributes);

        assertEquals(groupsResponse.getGroups().get(0).getDisplayName(), "Application/MyApp");
        assertEquals(groupsResponse.getGroups().size(), 1);
        userCoreUtil.close();
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

    @Test
    public void testGetEnterpriseUserSchemaWhenEnabled() throws Exception {

        String externalClaimURI = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

        Map<String, String> properties = new HashMap<String, String>() {{
            put("ReadOnly", "true");
            put("SupportedByDefault", "true");
            put("Description", "sample");
            put("Required", "true");
        }};
        Map<String, String> notSupportedByDefaultProperties = new HashMap<String, String>() {{
            put("ReadOnly", "true");
            put("SupportedByDefault", "false");
            put("Description", "sample");
            put("Required", "true");
        }};

        List<LocalClaim> localClaimMap = new ArrayList<LocalClaim>() {{
            add(new LocalClaim("sample/department", new ArrayList<AttributeMapping>(), properties));
            add(new LocalClaim("sample/organization", new ArrayList<AttributeMapping>(),
                    notSupportedByDefaultProperties));
            add(new LocalClaim("sample/manager", new ArrayList<AttributeMapping>(), properties));
        }};
        List<ExternalClaim> externalClaimMap = new ArrayList<ExternalClaim>() {{
            add(new ExternalClaim(externalClaimURI, externalClaimURI + ":department",
                    "sample/department"));
            add(new ExternalClaim(externalClaimURI, externalClaimURI + ":organization",
                    "sample/organization"));
            add(new ExternalClaim(externalClaimURI, externalClaimURI + ":manager",
                    "sample/manager"));
        }};

        when(mockClaimMetadataManagementService
                .getExternalClaims(SCIMCommonConstants.SCIM_ENTERPRISE_USER_CLAIM_DIALECT,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn(externalClaimMap);
        when(mockClaimMetadataManagementService.getLocalClaims(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(localClaimMap);
        scimCommonUtils.when(() -> SCIMCommonUtils.isUserExtensionEnabled()).thenReturn(true);

        SCIMUserSchemaExtensionBuilder sb = spy(new SCIMUserSchemaExtensionBuilder());
        scimUserSchemaExtensionBuilder.when(() -> SCIMUserSchemaExtensionBuilder.getInstance()).thenReturn(sb);
        when(sb.getExtensionSchema()).thenReturn(mockedSCIMAttributeSchema);
        when(mockedSCIMAttributeSchema.getSubAttributeSchema(anyString())).thenReturn(mockedAttributeSchema);
        when(mockedAttributeSchema.getType()).thenReturn(SCIMDefinitions.DataType.STRING);

        SCIMUserManager userManager = new SCIMUserManager(mockedUserStoreManager, mockClaimMetadataManagementService,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertEquals(userManager.getEnterpriseUserSchema().size(), 2);
    }

    @Test
    public void testGetEnterpriseUserSchemaWhenDisabled() throws Exception {

        scimCommonUtils.when(SCIMCommonUtils::isUserExtensionEnabled).thenReturn(false);
        SCIMUserManager userManager = new SCIMUserManager(mockedUserStoreManager, mockClaimMetadataManagementService,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNull(userManager.getEnterpriseUserSchema());
    }

    @Test
    public void testUpdateUserWithUsernameChange() throws Exception {

        // When IS supports username change through SCIM user
        // update this test will no longer be needed.

        User oldUser = new User();
        oldUser.setUserName("oldUser");

        User newUser = new User();
        newUser.setUserName("newUser");
        newUser.setId("newUserId");

        when(ApplicationManagementService.getInstance()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(null);

        SCIMUserManager scimUserManager = spy(new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME));
        resourceManagerUtil.when(() -> ResourceManagerUtil.getAllAttributeURIs(Mockito.any()))
                .thenReturn(new HashMap<>());
        doReturn(oldUser).when(scimUserManager).getUser(anyString(), anyMap());
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);

        boolean hasExpectedBehaviour = false;
        try {
            scimUserManager.updateUser(newUser, null);
        } catch (BadRequestException e) {
            if (ResponseCodeConstants.MUTABILITY.equals(e.getScimType())) {
                hasExpectedBehaviour = true;
            }
        }

        assertTrue(hasExpectedBehaviour, "UserName claim update is not properly handled.");
    }

    @Test
    public void testGetUserSchema() throws Exception {

        String claimDialectUri = SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT;

        Map<String, String> supportedByDefaultProperties = new HashMap<String, String>() {{
            put("SupportedByDefault", "true");
            put("ReadOnly", "true");
            put(ClaimConstants.SHARED_PROFILE_VALUE_RESOLVING_METHOD,
                    ClaimConstants.SharedProfileValueResolvingMethod.FROM_ORIGIN.getName());
        }};

        List<LocalClaim> localClaimList = new ArrayList<LocalClaim>() {{
            add(new LocalClaim(USERNAME_LOCAL_CLAIM, null, null));
            add(new LocalClaim(GIVEN_NAME_LOCAL_CLAIM, null, supportedByDefaultProperties));
            add(new LocalClaim(EMAIL_ADDRESS_LOCAL_CLAIM, null, supportedByDefaultProperties));
            add(new LocalClaim(NICK_AME_LOCAL_CLAIM, null, null));
        }};

        List<ExternalClaim> externalClaimList = new ArrayList<ExternalClaim>() {{
            add(new ExternalClaim(claimDialectUri, claimDialectUri + ":userName", USERNAME_LOCAL_CLAIM));
            add(new ExternalClaim(claimDialectUri, claimDialectUri + ":name.givenName", GIVEN_NAME_LOCAL_CLAIM));
            add(new ExternalClaim(claimDialectUri, claimDialectUri + ":emails", EMAIL_ADDRESS_LOCAL_CLAIM));
            add(new ExternalClaim(claimDialectUri, claimDialectUri + ":nickName", NICK_AME_LOCAL_CLAIM));
        }};

        when(mockClaimMetadataManagementService.getExternalClaims(SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn(externalClaimList);
        when(mockClaimMetadataManagementService.getLocalClaims(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(localClaimList);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        List<Attribute> list = scimUserManager.getUserSchema();
        assertEquals(list.size(), 3);
        // First item is emails claim.
        assertEquals(list.get(0).getName(), "emails");
        assertEquals(list.get(0).getAttributeProperties().get(SHARED_PROFILE_VALUE_RESOLVING_METHOD_PROPERTY),
                ClaimConstants.SharedProfileValueResolvingMethod.FROM_ORIGIN.getName());
        // Second item is name claim.
        assertEquals(list.get(1).getName(), "name");
        assertFalse(list.get(1).getAttributeProperties().containsKey(SHARED_PROFILE_VALUE_RESOLVING_METHOD_PROPERTY));
        assertEquals(list.get(1).getSubAttribute("givenName").getAttributeProperties()
                        .get(SHARED_PROFILE_VALUE_RESOLVING_METHOD_PROPERTY),
                ClaimConstants.SharedProfileValueResolvingMethod.FROM_ORIGIN.getName());
        // Third item is userName claim.
        assertEquals(list.get(2).getName(), "userName");
        assertFalse(list.get(2).getAttributeProperties().containsKey(SHARED_PROFILE_VALUE_RESOLVING_METHOD_PROPERTY));
    }

    @Test
    public void testGetUserSchemaWithAttributeProfiles() throws Exception {

        String claimDialectUri = SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT;

        String consoleProfile = "console";
        String endUserProfile = "endUser";

        Map<String, String> claimProperties1 = new HashMap<String, String>() {{
            put("SupportedByDefault", "true");
            put("ReadOnly", "true");
            put("Required", "false");
            put(buildAttributeProfileProperty(consoleProfile, ClaimConstants.SUPPORTED_BY_DEFAULT_PROPERTY), "false");
            put(buildAttributeProfileProperty(consoleProfile, ClaimConstants.REQUIRED_PROPERTY), "false");
            put(buildAttributeProfileProperty(endUserProfile, ClaimConstants.REQUIRED_PROPERTY), "true");
            put(buildAttributeProfileProperty(endUserProfile, ClaimConstants.READ_ONLY_PROPERTY), "false");
        }};

        Map<String, String> claimProperties2 = new HashMap<String, String>() {{
            put("SupportedByDefault", "false");
            put("ReadOnly", "false");
            put("Required", "false");
            put(buildAttributeProfileProperty(consoleProfile, ClaimConstants.SUPPORTED_BY_DEFAULT_PROPERTY), "true");
            put(buildAttributeProfileProperty(consoleProfile, ClaimConstants.READ_ONLY_PROPERTY), "true");
            put(buildAttributeProfileProperty(endUserProfile, ClaimConstants.REQUIRED_PROPERTY), "true");
            put(buildAttributeProfileProperty(endUserProfile, ClaimConstants.DISPLAY_NAME_PROPERTY), "invalid");
        }};

        List<LocalClaim> localClaimList = new ArrayList<LocalClaim>() {{
            add(new LocalClaim(EMAIL_ADDRESS_LOCAL_CLAIM, null, claimProperties1));
            add(new LocalClaim(GIVEN_NAME_LOCAL_CLAIM, null, claimProperties2));
        }};

        List<ExternalClaim> externalClaimList = new ArrayList<ExternalClaim>() {{
            add(new ExternalClaim(claimDialectUri, claimDialectUri + ":emails", EMAIL_ADDRESS_LOCAL_CLAIM));
            add(new ExternalClaim(claimDialectUri, claimDialectUri + ":name.givenName", GIVEN_NAME_LOCAL_CLAIM));
        }};

        when(mockClaimMetadataManagementService.getExternalClaims(SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn(externalClaimList);
        when(mockClaimMetadataManagementService.getLocalClaims(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(localClaimList);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        List<Attribute> userAttributes = scimUserManager.getUserSchema();
        
        assertEquals(userAttributes.size(), 2);

        // Emails - Simple attribute.
        assertEquals(userAttributes.get(0).getName(), "emails");
        assertTrue(userAttributes.get(0).getAttributeJSONProperties().containsKey(ATTRIBUTE_PROFILES_PROPERTY));

        JSONObject profiles1 = userAttributes.get(0).getAttributeJSONProperties().get(ATTRIBUTE_PROFILES_PROPERTY);
        assertTrue(profiles1.has(consoleProfile));
        assertTrue(profiles1.has(endUserProfile));
        assertTrue(((JSONObject) profiles1.get(consoleProfile)).has(SUPPORTED_BY_DEFAULT_PROPERTY));
        assertTrue(((JSONObject) profiles1.get(consoleProfile)).has(SCIMConfigConstants.REQUIRED));
        assertTrue(((JSONObject) profiles1.get(endUserProfile)).has(SCIMConfigConstants.REQUIRED));
        assertTrue(((JSONObject) profiles1.get(endUserProfile)).has(SCIMConfigConstants.MUTABILITY));

        // Given name - Complex attribute.
        assertEquals(userAttributes.get(1).getName(), "name");
        assertFalse(userAttributes.get(1).getAttributeProperties().containsKey(ATTRIBUTE_PROFILES_PROPERTY));
        assertTrue(userAttributes.get(1).getSubAttribute("givenName").getAttributeJSONProperties()
                .containsKey(ATTRIBUTE_PROFILES_PROPERTY));

        JSONObject profiles2 = userAttributes.get(1).getSubAttribute("givenName").getAttributeJSONProperties()
                .get(ATTRIBUTE_PROFILES_PROPERTY);
        assertTrue(profiles2.has(consoleProfile));
        assertTrue(profiles2.has(endUserProfile));
        assertTrue(((JSONObject) profiles2.get(consoleProfile)).has(SUPPORTED_BY_DEFAULT_PROPERTY));
        assertTrue(((JSONObject) profiles2.get(consoleProfile)).has(SCIMConfigConstants.MUTABILITY));
        assertTrue(((JSONObject) profiles2.get(endUserProfile)).has(SCIMConfigConstants.REQUIRED));
        assertTrue(((JSONObject) profiles2.get(endUserProfile)).has(SCIMConfigConstants.REQUIRED));
        assertFalse(((JSONObject) profiles2.get(endUserProfile)).has(ClaimConstants.DISPLAY_NAME_PROPERTY));
    }

    private String buildAttributeProfileProperty(String profileName, String property) {

        return ClaimConstants.PROFILES_CLAIM_PROPERTY_PREFIX + profileName + "." + property;
    }

    @Test(dataProvider = "groupPermission")
    public void testGetGroupPermissions(String roleName, String[] permission, Object expected) throws Exception {

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(SCIMCommonComponentHolder.getRolePermissionManagementService())
                .thenReturn(mockedRolePermissionManagementService);
        when(mockedRolePermissionManagementService.getRolePermissions(eq(roleName), anyInt())).thenReturn(permission);
        String[] actual = scimUserManager.getGroupPermissions(roleName);
        assertEquals(actual, expected);
    }

    @DataProvider(name = "groupPermission")
    public Object[][] groupPermission() throws Exception {

        String[] permission1 = new String[]{};
        String[] permission2 = new String[]{"/permission/admin/login"};
        return new Object[][]{
                {null, permission1, permission1},
                {"roleName", permission2, permission2}
        };
    }

    @DataProvider(name = "getUserConfigurations")
    public Object[][] getUserConfigurations() {

        String username = "user";
        String domainQualifiedUserName = "domainQualifiedUserName";
        String userId = "b53fe2f0-054d-43b5-a8f7-50043adb2198";
        String roles = "Internal/admin,Internal/everyone";
        String emailAddress = "admin@wso2.com";
        String lastName = "Administrator";
        String groups = "admin";
        String addressHome = "No:10, Temple Road, Colombo 04, Sri Lanka";
        String addressWork = "20, Palm Grove, Colombo 3, Sri Lanka";
        String address = "20, Palm Grove, Colombo 3, Sri Lanka";

        Map<String, String> userClaimValues1 = new HashMap<>();
        userClaimValues1.put(USERNAME_LOCAL_CLAIM , username);
        userClaimValues1.put(USERID_LOCAL_CLAIM, userId);
        userClaimValues1.put(EMAIL_ADDRESS_LOCAL_CLAIM , emailAddress);
        userClaimValues1.put(LASTNAME_LOCAL_CLAIM , lastName);
        userClaimValues1.put(ROLES_LOCAL_CLAIM , roles);
        userClaimValues1.put(GROUPS_LOCAL_CLAIM , groups);
        userClaimValues1.put(ADDRESS_LOCALITY_LOCAL_CLAIM , addressHome);
        userClaimValues1.put(ADDRESS_REGION_LOCAL_CLAIM , addressWork);

        Map<String, String> userClaimValues2 = new HashMap<>();
        userClaimValues2.put(USERNAME_LOCAL_CLAIM , username);
        userClaimValues2.put(USERID_LOCAL_CLAIM, userId);
        userClaimValues2.put(EMAIL_ADDRESS_LOCAL_CLAIM , emailAddress);
        userClaimValues2.put(LASTNAME_LOCAL_CLAIM , lastName);
        userClaimValues2.put(ADDRESS_LOCALITY_LOCAL_CLAIM , addressHome);
        userClaimValues2.put(ADDRESS_REGION_LOCAL_CLAIM , addressWork);
        userClaimValues2.put(ADDRESS_LOCAL_CLAIM , address);

        return new Object[][]{
                {true, userClaimValues1, true, true, "true", 8, 2, 1, "PRIMARY/" + username},
                {true, userClaimValues1, true, true, "false", 8, 2, 1, "PRIMARY/" + domainQualifiedUserName},
                {true, userClaimValues1, true, false, "true", 8, 2, 1, username},
                {true, userClaimValues1, true, false, "false", 8, 2, 1, domainQualifiedUserName},
                {false, userClaimValues2, true, true, "false", 8, 2, 1, "PRIMARY/" + domainQualifiedUserName},
                {false, userClaimValues2, true, false, "false", 8, 2, 1, domainQualifiedUserName},
                {false, userClaimValues2, false, true, "false", 7, 0, 2, "PRIMARY/" + domainQualifiedUserName},
                {false, userClaimValues2, false, false, "false", 7, 0, 2, domainQualifiedUserName},
        };
    }

    @Test(dataProvider = "getUserConfigurations")
    public void testGetUser(Boolean isGroupsVsRolesSeparationImprovementsEnabled, Map<String, String> userClaimValues,
                            Boolean isRoleAndGroupSeparationEnabled,
                            Boolean mandateDomainForUsernamesAndGroupNamesInResponse, String enableLoginIdentifiers,
                            int expectedNoOfAttributes, int expectedNoOfRoles, int expectedNoOfGroups,
                            String expectedUserName) throws Exception {

        String userId = "b53fe2f0-054d-43b5-a8f7-50043adb2198";
        String username = "user";
        String domainQualifiedUserName = "domainQualifiedUserName";
        String claimSeparator = ",";
        String userStoreDomainName = "PRIMARY";
        Map<String, Boolean> requiredAttributes = new HashMap<>();
        requiredAttributes.put(SCIMConstants.CommonSchemaConstants.ID_URI, true);
        requiredAttributes.put(SCIMConstants.UserSchemaConstants.GROUP_URI, true);
        requiredAttributes.put(SCIMConstants.UserSchemaConstants.EMAILS_URI, true);
        requiredAttributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, true);
        requiredAttributes.put(SCIMConstants.UserSchemaConstants.FAMILY_NAME_URI, true);
        requiredAttributes.put(SCIMConstants.UserSchemaConstants.ROLES_URI + "." + SCIMConstants.DEFAULT, true);
        requiredAttributes.put(SCIMConstants.UserSchemaConstants.LOCALITY_URI, true);
        requiredAttributes.put(SCIMConstants.UserSchemaConstants.REGION_URI, true);
        requiredAttributes.put(SCIMConstants.UserSchemaConstants.ADDRESSES_URI, true);

        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, USERID_LOCAL_CLAIM);
        scimToLocalClaimsMap.put(SCIMConstants.UserSchemaConstants.GROUP_URI, GROUPS_LOCAL_CLAIM);
        scimToLocalClaimsMap.put(SCIMConstants.UserSchemaConstants.EMAILS_URI, EMAIL_ADDRESS_LOCAL_CLAIM);
        scimToLocalClaimsMap.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, USERNAME_LOCAL_CLAIM);
        scimToLocalClaimsMap.put(SCIMConstants.UserSchemaConstants.FAMILY_NAME_URI, LASTNAME_LOCAL_CLAIM);
        scimToLocalClaimsMap.put(SCIMConstants.UserSchemaConstants.ADDRESSES_URI, ADDRESS_LOCAL_CLAIM);
        scimToLocalClaimsMap.put
                (SCIMConstants.UserSchemaConstants.ROLES_URI + "." + SCIMConstants.DEFAULT, ROLES_LOCAL_CLAIM);
        scimToLocalClaimsMap.put(USER_SCHEMA_ADDRESS_HOME, ADDRESS_LOCALITY_LOCAL_CLAIM);
        scimToLocalClaimsMap.put(USER_SCHEMA_ADDRESS_WORK, ADDRESS_REGION_LOCAL_CLAIM);

        HashSet<String> scimRoles = new HashSet<>();
        scimRoles.add("role1");
        scimRoles.add("role2");

        ArrayList<String> groupsList = new ArrayList<>();
        groupsList.add("Internal/admin");
        groupsList.add("Internal/everyone");
        groupsList.add("admin");

        ArrayList<String> rolesList = new ArrayList<>();
        rolesList.add("Internal/admin");
        rolesList.add("Internal/everyone");

        Group group1 = new Group();
        group1.setDisplayName("admin");
        group1.setId("Group 1");

        Group group2 = new Group();
        group2.setDisplayName("PRIMARY/admin");
        group2.setId("Group 2");

        Group group3 = new Group();
        group3.setDisplayName("Internal/admin");
        group3.setId("Role 1");

        Group group4 = new Group();
        group4.setDisplayName("Internal/everyone");
        group4.setId("Role 2");

        Map<String, Group> groupsMap = new HashMap<>();
        groupsMap.put("admin", group1);
        groupsMap.put("PRIMARY/admin", group2);
        groupsMap.put("Internal/admin", group3);
        groupsMap.put("Internal/everyone", group4);

        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        when(SCIMCommonUtils.convertLocalToSCIMDialect(anyMap(), anyMap())).thenCallRealMethod();
        when(SCIMCommonUtils.mandateDomainForUsernamesAndGroupNamesInResponse()).
                thenReturn(mandateDomainForUsernamesAndGroupNamesInResponse);
        when(SCIMCommonUtils.prependDomain(anyString())).thenCallRealMethod();
        when(SCIMCommonUtils.isHybridRole(anyString())).thenCallRealMethod();

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        CommonTestUtils.initPrivilegedCarbonContext();

        org.wso2.carbon.user.core.common.User user = mock(org.wso2.carbon.user.core.common.User.class);
        when(user.getUserStoreDomain()).thenReturn(userStoreDomainName);
        when(user.getUsername()).thenReturn((username));
        when(user.getDomainQualifiedUsername()).thenReturn(domainQualifiedUserName);
        when(user.getUserID()).thenReturn((userId));

        mockedUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockedUserStoreManager.getUserWithID(anyString(), nullable(String[].class), anyString())).thenReturn(user);
        when(mockedUserStoreManager.getTenantId()).thenReturn(1234567);
        when(mockedUserStoreManager.getUserClaimValuesWithID(anyString(), any(), nullable(String.class)))
                .thenReturn(userClaimValues);
        when(mockedUserStoreManager.isRoleAndGroupSeparationEnabled()).thenReturn(isRoleAndGroupSeparationEnabled);
        when(mockedUserStoreManager.getRoleListOfUserWithID(anyString())).thenReturn(groupsList);
        when(mockedUserStoreManager.getHybridRoleListOfUser(anyString(), anyString())).thenReturn(rolesList);
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(secondaryUserStoreManager);

        for (String group : groupsList) {
            when(mockedUserStoreManager.getGroupByGroupName(group, null)).
                    thenReturn(buildUserCoreGroupResponse(group, "123456", "dummyDomain"));
        }
        when(secondaryUserStoreManager.isSCIMEnabled()).thenReturn(true);
        when(secondaryUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfig);
        when(mockedRealmConfig.getUserStoreProperty(anyString())).thenReturn(claimSeparator);
        when(mockedRealmConfig.isPrimary()).thenReturn(true);
        when(mockedRealmConfig.getEveryOneRoleName()).thenReturn("Internal/everyone");

        doNothing().when(mockedGroupDAO).addSCIMGroupAttributesToSCIMDisabledHybridRoles(anyInt(), any());

        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        when(IdentityUtil.isGroupsVsRolesSeparationImprovementsEnabled())
                .thenReturn(isGroupsVsRolesSeparationImprovementsEnabled);
        when(IdentityUtil.getProperty(SCIMCommonConstants.PRIMARY_LOGIN_IDENTIFIER_CLAIM))
                .thenReturn(USERNAME_LOCAL_CLAIM);
        when(IdentityUtil.getProperty(SCIMCommonConstants.ENABLE_LOGIN_IDENTIFIERS)).thenReturn(enableLoginIdentifiers);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn("Internal");

        when(mockedSCIMGroupHandler.listSCIMRoles()).thenReturn(scimRoles);
        when(mockedSCIMGroupHandler.getGroupWithAttributes(any(Group.class), anyString()))
                .thenAnswer(new Answer<Group>() {
            public Group answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                String groupName = (String) args[1];
                return groupsMap.get(groupName);
            }
        });

        try (MockedConstruction<SCIMGroupHandler> mocked = mockConstruction(SCIMGroupHandler.class,
                (mock, context) -> {
                    when(mock.getGroupWithAttributes(any(),any())).thenReturn(group1);
                })) {
            when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
            User scimUser = scimUserManager.getUser(userId, requiredAttributes);
            assertEquals(scimUser.getAttributeList().size(), expectedNoOfAttributes);
            // Check whether the added multi valued attributes for the addresses attribute are contained.
            assertEquals(
                    ((MultiValuedAttribute) scimUser.getAttribute("addresses")).getAttributeValues().size(), 2);
            assertEquals(scimUser.getUserName(), expectedUserName);
            assertEquals(scimUser.getGroups().size(), expectedNoOfGroups);
            assertEquals(scimUser.getRoles().size(), expectedNoOfRoles);
        }
    }

    @DataProvider(name = "exceptionHandlingConfigurations")
    public Object[][] exceptionHandlingConfigurations() {

        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(expectedExceptions = AbstractCharonException.class, dataProvider = "exceptionHandlingConfigurations")
    public void testGetUserWithInvalidUserID(Boolean isNotifyUserstoreStatusEnabled) throws Exception {

        String userId = "12345";
        Map<String, Boolean> requiredAttributes = new HashMap<>();
        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, USERID_LOCAL_CLAIM);

        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        when(SCIMCommonUtils.isNotifyUserstoreStatusEnabled()).thenReturn(isNotifyUserstoreStatusEnabled);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        UserStoreException e = new UserStoreException("30007 - UserNotFound: User 12345 does not exist in: PRIMARY");
        when(mockedUserStoreManager.getUserWithID(anyString(), any(), anyString())).thenThrow(e);
        List<SCIMUserStoreErrorResolver> scimUserStoreErrorResolvers = new ArrayList<>();
        SCIMUserStoreErrorResolver scimUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        scimUserStoreErrorResolvers.add(scimUserStoreErrorResolver);
        when(SCIMCommonComponentHolder.getScimUserStoreErrorResolverList()).thenReturn(scimUserStoreErrorResolvers);
        scimUserManager.getUser(userId, requiredAttributes);
        // This method is for testing of throwing CharonException, hence no assertion.
    }

    @Test(expectedExceptions = CharonException.class)
    public void testGetUserWhenSCIMisDisabled() throws Exception {

        String userId = "12345";
        String userStoreDomainName = "PRIMARY";
        Map<String, Boolean> requiredAttributes = new HashMap<>();
        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, USERID_LOCAL_CLAIM);

        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        mockedUserStoreManager = mock(AbstractUserStoreManager.class);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        org.wso2.carbon.user.core.common.User user = mock(org.wso2.carbon.user.core.common.User.class);
        when(mockedUserStoreManager.getUserWithID(anyString(), any(), anyString())).thenReturn(user);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(secondaryUserStoreManager);
        when(secondaryUserStoreManager.isSCIMEnabled()).thenReturn(false);
        when(user.getUserStoreDomain()).thenReturn(userStoreDomainName);
        scimUserManager.getUser(userId, requiredAttributes);
        // This method is for testing of throwing CharonException, hence no assertion.
    }

    @Test
    public void testListUsersWithPost() throws Exception {

        SearchRequest searchRequest = new SearchRequest();
        UsersGetResponse usersGetResponse = new UsersGetResponse(0, Collections.emptyList());
        Map<String, Boolean> requiredAttributes = new HashMap<>();
        SCIMUserManager scimUserManager = spy(new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME));
        doReturn(usersGetResponse).when(scimUserManager)
                .listUsersWithGET(any(), any(), any(), nullable(String.class), nullable(String.class), nullable(String.class), anyMap());
        when(SCIMCommonComponentHolder.getConfigurationManager()).thenReturn(mockedConfigurationManager);
        Resource resource = getResource();
        when(mockedConfigurationManager.getResourceByTenantId( anyInt(), anyString(),
                anyString() )).thenReturn(resource);
        UsersGetResponse users = scimUserManager.listUsersWithPost(searchRequest, requiredAttributes);
        assertEquals(users, usersGetResponse);
    }

    @Test(expectedExceptions = NotFoundException.class)
    public void testDeleteUserWithInvalidUserId() throws Exception {

        String userId = "12345";
        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, "userIdURI");
        List<org.wso2.carbon.user.core.common.User> coreUsers = new ArrayList<>();

        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        AbstractUserStoreManager mockedUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockedUserStoreManager.getUserListWithID(anyString(), anyString(), anyString())).thenReturn(coreUsers);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(ApplicationManagementService.getInstance()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(null);
        scimUserManager.deleteUser(userId);
        // This method is for testing of throwing NotFoundException, hence no assertion.
    }

    @Test(expectedExceptions = CharonException.class)
    public void testDeleteUserWhenSCIMisDisabled() throws Exception {

        String userId  = "12345";
        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, "userIdURI");
        org.wso2.carbon.user.core.common.User coreUser = new org.wso2.carbon.user.core.common.User();
        coreUser.setUserID(userId);
        coreUser.setUsername("coreUser");
        coreUser.setUserStoreDomain("DomainName");

        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        AbstractUserStoreManager mockedUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockedUserStoreManager.getUserWithID(anyString(), any(), anyString())).thenReturn(coreUser);
        when(mockedUserStoreManager.getSecondaryUserStoreManager("DomainName")).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.isSCIMEnabled()).thenReturn(false);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(ApplicationManagementService.getInstance()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(null);
        scimUserManager.deleteUser(userId);
        // This method is for testing of throwing CharonException, hence no assertion.
    }
    @Test(expectedExceptions = CharonException.class)
    public void testDeleteUserWithUserStoreDomainMismatch() throws Exception {

        String userId = "12345";
        Map<String, String> scimToLocalClaimsMap = new HashMap<>();
        scimToLocalClaimsMap.put(SCIMConstants.CommonSchemaConstants.ID_URI, "userIdURI");
        org.wso2.carbon.user.core.common.User coreUser = new org.wso2.carbon.user.core.common.User();
        coreUser.setUserID(userId);
        coreUser.setUsername("coreUser");
        coreUser.setUserStoreDomain("PRIMARY");

        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimsMap);
        AbstractUserStoreManager mockedUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockedUserStoreManager.getUserWithID(anyString(), any(), anyString())).thenReturn(coreUser);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        InboundProvisioningConfig inboundProvisioningConfig = new InboundProvisioningConfig();
        inboundProvisioningConfig.setProvisioningUserStore("SECONDARY");
        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setInboundProvisioningConfig(inboundProvisioningConfig);
        when(ApplicationManagementService.getInstance()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(serviceProvider);
        scimUserManager.deleteUser(userId);
        // This method is for testing of throwing CharonException, hence no assertion.
    }

    @Test(expectedExceptions = BadRequestException.class)
    public void testCreateUserWithInvalidUserStoreName() throws Exception {

        User user = new User();
        user.setUserName("testUser");

        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString()))
                .thenReturn(null);
        InboundProvisioningConfig inboundProvisioningConfig = new InboundProvisioningConfig();
        inboundProvisioningConfig.setProvisioningUserStore("DomainName");
        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setInboundProvisioningConfig(inboundProvisioningConfig);
        when(ApplicationManagementService.getInstance()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(serviceProvider);
        when(mockedUserStoreManager.isExistingUser(nullable(String.class)))
                .thenThrow(new UserStoreException(new UserStoreClientException("TestException")));
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        scimUserManager.createUser(user, null);
        // This method is for testing of throwing BadRequestException, hence no assertion.
    }

    @Test(expectedExceptions = AbstractCharonException.class)
    public void testCreateUserWhenSCIMisDisabled() throws Exception {

        User user = new User();
        user.setUserName("testUser");

        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString()))
                .thenReturn(secondaryUserStoreManager);
        when(secondaryUserStoreManager.isSCIMEnabled()).thenReturn(false);

        InboundProvisioningConfig inboundProvisioningConfig = new InboundProvisioningConfig();
        inboundProvisioningConfig.setProvisioningUserStore("DomainName");
        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setInboundProvisioningConfig(inboundProvisioningConfig);
        when(ApplicationManagementService.getInstance()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(serviceProvider);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        doThrow(new NotImplementedException()).when(mockedUser).setSchemas(Mockito.any(UserManager.class));
        mockedUser.setSchemas(mock(UserManager.class));
        scimUserManager.createUser(user, null);
        // This method is for testing of throwing CharonException, hence no assertion.
    }

    @DataProvider(name = "createUserConfigurations")
    public Object[][] createUserConfigurations() {

        return new Object[][]{
                {"false"},
                {"true"}
        };
    }

    @Test(expectedExceptions = ConflictException.class, dataProvider = "createUserConfigurations")
    public void testCreateUserWithExistingUserName(String isLoginIdentifiersEnabled) throws Exception {

        User user = new User();
        user.setId("12345");
        user.setUserName("DomainName/testUser1");
        String[] existingUserList = {"user1", "user2"};

        when(IdentityUtil.getProperty(SCIMCommonConstants.PRIMARY_LOGIN_IDENTIFIER_CLAIM))
                .thenReturn("primaryLoginIdentifierClaim");
        when(IdentityUtil.getProperty(SCIMCommonConstants.ENABLE_LOGIN_IDENTIFIERS))
                .thenReturn(isLoginIdentifiersEnabled);
        when(IdentityUtil.extractDomainFromName(anyString())).thenCallRealMethod();

        when(ApplicationManagementService.getInstance()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(null);

        mockedUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockedUserStoreManager.isExistingUserWithID(anyString())).thenReturn(true);
        when(mockedUserStoreManager.isExistingUser(anyString())).thenReturn(true);
        when(mockedUserStoreManager.getUserList(anyString(), anyString(), nullable(String.class))).thenReturn(existingUserList);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString()))
                .thenReturn(secondaryUserStoreManager);
        when(secondaryUserStoreManager.isSCIMEnabled()).thenReturn(true);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        scimUserManager.createUser(user, null);
        // This method is for testing of throwing ConflictException, hence no assertion.
    }

    @Test(expectedExceptions = BadRequestException.class)
    public void testCreateUserWithConflictingLoginIdentifier() throws Exception {

        User user = new User();
        user.setId("12345");
        user.replaceDisplayName("displayName");
        user.setUserName("DomainName/testUser");
        Map<String, String> scimToLocalClaimMappings = new HashMap<>();
        scimToLocalClaimMappings.put(SCIMConstants.UserSchemaConstants.DISPLAY_NAME_URI, DISPLAY_NAME_LOCAL_CLAIM);

        when(IdentityUtil.getProperty(SCIMCommonConstants.PRIMARY_LOGIN_IDENTIFIER_CLAIM))
                .thenReturn(DISPLAY_NAME_LOCAL_CLAIM);
        when(IdentityUtil.getProperty(SCIMCommonConstants.ENABLE_LOGIN_IDENTIFIERS)).thenReturn("true");
        when(IdentityUtil.extractDomainFromName(anyString())).thenCallRealMethod();

        when(ApplicationManagementService.getInstance()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProvider(anyString(), anyString())).thenReturn(null);

        when(SCIMCommonUtils.convertSCIMtoLocalDialect(anyMap())).thenCallRealMethod();
        when(SCIMCommonUtils.getSCIMtoLocalMappings()).thenReturn(scimToLocalClaimMappings);

        mockedUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockedUserStoreManager.getUserList(anyString(), anyString(), anyString())).thenReturn(null);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString()))
                .thenReturn(secondaryUserStoreManager);
        when(secondaryUserStoreManager.isSCIMEnabled()).thenReturn(true);
        SCIMUserManager scimUserManager = new SCIMUserManager(mockedUserStoreManager,
                mockClaimMetadataManagementService, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        scimUserManager.createUser(user, null);
        // This method is for testing of throwing BadRequestException, hence no assertion.
    }

    @Test(dataProvider = "syncedUserAttributesData")
    public void testGetSyncedUserAttributes(Map<String, String> scimToLocalMappings,
                                            Map<String, String> expectedSyncedAttributes,
                                            boolean shouldThrowException) throws CharonException {

        SCIMUserManager userManager = new SCIMUserManager(mockedUserStoreManager, mockClaimMetadataManagementService,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        if (shouldThrowException) {
            scimCommonUtils.when(SCIMCommonUtils::getSCIMtoLocalMappings)
                    .thenThrow(new org.wso2.carbon.user.core.UserStoreException("Database error"));
            Assert.expectThrows(CharonException.class, userManager::getSyncedUserAttributes);
        } else {
            scimCommonUtils.when(SCIMCommonUtils::getSCIMtoLocalMappings).thenReturn(scimToLocalMappings);
            Map<String, String> actualSyncedAttributes = userManager.getSyncedUserAttributes();
            Assert.assertEquals(actualSyncedAttributes, expectedSyncedAttributes);
        }
    }

    @DataProvider(name = "syncedUserAttributesData")
    public Object[][] syncedUserAttributesData() {

        Map<String, String> scimToLocalMappings1 = new HashMap<>();
        scimToLocalMappings1.put("urn:scim:User:emails", "email");
        scimToLocalMappings1.put("urn:scim:User:workEmail", "email");
        scimToLocalMappings1.put("urn:scim:User:phone", "phoneNumber");
        scimToLocalMappings1.put("urn:scim:User:mobile", "phoneNumber");
        scimToLocalMappings1.put("urn:scim:User:username", "username");

        Map<String, String> expectedSyncedAttributes1 = new HashMap<>();
        expectedSyncedAttributes1.put("urn:scim:User:emails", "urn:scim:User:workEmail");
        expectedSyncedAttributes1.put("urn:scim:User:workEmail", "urn:scim:User:emails");
        expectedSyncedAttributes1.put("urn:scim:User:phone", "urn:scim:User:mobile");
        expectedSyncedAttributes1.put("urn:scim:User:mobile", "urn:scim:User:phone");

        Map<String, String> scimToLocalMappings2 = new HashMap<>();
        scimToLocalMappings2.put("urn:scim:User:emails", "email");
        scimToLocalMappings2.put("urn:scim:User:phone", "phoneNumber");
        scimToLocalMappings2.put("urn:scim:User:username", "username");

        Map<String, String> expectedSyncedAttributes2 = Collections.emptyMap();

        return new Object[][]{
                {scimToLocalMappings1, expectedSyncedAttributes1, false},
                {scimToLocalMappings2, expectedSyncedAttributes2, false},
                {null, null, true}
        };
    }

    /**
     * Build a group object with the given params to mock the userstore response.
     *
     * @param groupName  Name of the group.
     * @param groupId    Group id.
     * @param domainName Domain name.
     * @return Group object.
     */
    private org.wso2.carbon.user.core.common.Group buildUserCoreGroupResponse(String groupName, String groupId,
                                                                              String domainName) {

        org.wso2.carbon.user.core.common.Group group = new org.wso2.carbon.user.core.common.Group();
        group.setGroupName(groupName);
        group.setGroupID(groupId);
        group.setUserStoreDomain(domainName);
        return group;
    }

    private List<org.wso2.carbon.identity.configuration.mgt.core.model.Attribute> getResourceAttribute() {

        org.wso2.carbon.identity.configuration.mgt.core.model.Attribute attribute =
                new org.wso2.carbon.identity.configuration.mgt.core.model.Attribute();
        attribute.setKey("userResponseMaxLimit");
        attribute.setValue("100");

        List<org.wso2.carbon.identity.configuration.mgt.core.model.Attribute> attributes = new ArrayList<>();
        attributes.add(attribute);
        return attributes;
    }

    private Resource getResource() {
        Resource resource = new Resource();
        resource.setResourceName(MAX_LIMIT_RESOURCE_NAME);
        resource.setAttributes(getResourceAttribute());
        return resource;
    }
}
