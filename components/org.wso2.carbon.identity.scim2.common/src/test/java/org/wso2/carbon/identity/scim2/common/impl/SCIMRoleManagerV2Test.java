/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.scim2.common.impl;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Permission;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Role;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleProperty;
import org.wso2.carbon.identity.role.v2.mgt.core.util.RoleManagementUtils;
import org.wso2.carbon.identity.scim2.common.internal.component.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.ForbiddenException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.objects.RoleV2;
import org.wso2.charon3.core.objects.plainobjects.MultiValuedComplexType;
import org.wso2.charon3.core.objects.plainobjects.RolesV2GetResponse;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.ROLE_WORKFLOW_CREATED;

/**
 * Contains the unit test cases for SCIMRoleManagerV2.
 */
public class SCIMRoleManagerV2Test {

    private static final String SAMPLE_TENANT_DOMAIN = "carbon.super";
    private static final String SAMPLE_VALID_ROLE_ID = "595f5508-f286-446a-86c4-5071e07b98fc";
    private static final String SAMPLE_GROUP_NAME = "testGroup";
    private static final String SAMPLE_PERMISSION_1_NAME = "permission1";
    private static final String SAMPLE_PERMISSION_2_NAME = "permission2";
    private static final String SAMPLE_VALID_ROLE_NAME = "admin";
    private static final String ROLE_ID = "role_id";
    private static final String ROLE_ID_2 = "role_id_2";
    private static final String ROLE_NAME = "role_name";
    private static final String ROLE_NAME_2 = "role_name_2";
    private static final String ORGANIZATION_AUD = "ORGANIZATION";
    private static final String ORGANIZATION_ID = "organization_id";
    private static final String ORGANIZATION_NAME = "organization_name";
    private static final String ROLE_PROPERTY_NAME = "isSharedRole";
    private static final String SCIM2_ROLES_V2_LOCATION_URI_BASE = "https://localhost:9443/scim2/v2/Roles/";

    private static final int BAD_REQUEST = 400;

    @Mock
    private RoleManagementService roleManagementService;

    @Mock
    private IdpManager idpManager;

    private SCIMRoleManagerV2 scimRoleManagerV2;

    private MockedStatic<IdentityUtil> identityUtil;

    private MockedStatic<OrganizationManagementUtil> organizationManagementUtilMockedStatic;

    private MockedStatic<SCIMCommonComponentHolder> scimCommonComponentHolderMockedStatic;

    private MockedStatic<RoleManagementUtils> roleManagementUtilsMockedStatic;

    @BeforeClass
    public void setUpClass() {

        openMocks(this);
    }

    @BeforeMethod
    public void setUpMethod() {

        identityUtil = mockStatic(IdentityUtil.class);
        scimRoleManagerV2 = new SCIMRoleManagerV2(roleManagementService, SAMPLE_TENANT_DOMAIN);
        organizationManagementUtilMockedStatic = mockStatic(OrganizationManagementUtil.class);
        scimCommonComponentHolderMockedStatic = mockStatic(SCIMCommonComponentHolder.class);
        roleManagementUtilsMockedStatic = mockStatic(RoleManagementUtils.class);
    }

    @AfterMethod
    public void tearDown() {

        identityUtil.close();
        organizationManagementUtilMockedStatic.close();
        scimCommonComponentHolderMockedStatic.close();
        roleManagementUtilsMockedStatic.close();
    }

    @DataProvider(name = "scimOperations")
    public Object[][] provideScimOperations() {

        return new Object[][]{
                {SCIMConstants.OperationalConstants.ADD},
                {SCIMConstants.OperationalConstants.REMOVE},
                {SCIMConstants.OperationalConstants.REPLACE}
        };
    }

    @Test(dataProvider = "scimOperations")
    public void testPatchRoleWithGroupDisplayNameInsteadOfGroupIdThrowingErrors(String operation)
            throws IdentityRoleManagementException, ForbiddenException, ConflictException, NotFoundException,
            CharonException {

        Map<String, List<PatchOperation>> patchOperations = new HashMap<>();
        Map<String, String> valueMap = new HashMap<>();
        valueMap.put(SCIMConstants.CommonSchemaConstants.DISPLAY, SAMPLE_GROUP_NAME);
        valueMap.put(SCIMConstants.CommonSchemaConstants.VALUE, null);

        PatchOperation patchOperation = new PatchOperation();
        patchOperation.setOperation(operation);
        patchOperation.setAttributeName(SCIMConstants.RoleSchemaConstants.GROUPS);
        patchOperation.setValues(valueMap);
        patchOperations.put(SCIMConstants.RoleSchemaConstants.GROUPS, Collections.singletonList(patchOperation));

        when(roleManagementService.getRoleNameByRoleId(SAMPLE_VALID_ROLE_ID, SAMPLE_TENANT_DOMAIN))
                .thenReturn(SAMPLE_VALID_ROLE_NAME);

        try {
            scimRoleManagerV2.patchRole(SAMPLE_VALID_ROLE_ID, patchOperations);
        } catch (BadRequestException e) {
            assertEquals(BAD_REQUEST, e.getStatus());
            assertEquals(ResponseCodeConstants.INVALID_VALUE, e.getScimType());
            assertEquals("Group id is required to update group of the role.", e.getDetail());
        }
    }

    @DataProvider(name = "roleNameUpdateExceptions")
    public Object[][] roleNameUpdateExceptions() {

        return new Object[][] {
                {new IdentityRoleManagementException("RMA-60001", "Role not found"), BadRequestException.class},
                {new IdentityRoleManagementException("RMA-60009", "Role name update is forbidden"), BadRequestException.class}
        };
    }

    @Test(dataProvider = "roleNameUpdateExceptions", expectedExceptions = BadRequestException.class)
    public void testInvalidRequestOnRoleNameUpdate(IdentityRoleManagementException identityException, Class<? extends Throwable> expectedException) throws Exception {

        RoleV2 oldRole = mock(RoleV2.class);
        RoleV2 newRole = mock(RoleV2.class);

        when(oldRole.getDisplayName()).thenReturn(ROLE_NAME);
        when(newRole.getDisplayName()).thenReturn(ROLE_NAME_2);
        when(oldRole.getId()).thenReturn(ROLE_ID);

        when(RoleManagementUtils.isSharedRole(ROLE_ID, SAMPLE_TENANT_DOMAIN)).thenReturn(false);
        when(OrganizationManagementUtil.isOrganization(anyString())).thenReturn(false);

        doThrow(identityException).when(roleManagementService)
                .updateRoleName(ROLE_ID, ROLE_NAME_2, SAMPLE_TENANT_DOMAIN);

        scimRoleManagerV2.updateRole(oldRole, newRole);

    }

    @Test
    public void testPatchRoleWithAddPermissions()
            throws IdentityRoleManagementException, ForbiddenException, ConflictException, NotFoundException,
            CharonException {

        Map<String, List<PatchOperation>> patchOperations = new HashMap<>();
        List<PatchOperation> patchOperationList = new ArrayList<>();
        PatchOperation patchOperation = getPatchOperation(SAMPLE_PERMISSION_1_NAME, SCIMConstants.OperationalConstants.ADD);
        patchOperationList.add(patchOperation);
        patchOperations.put(SCIMConstants.RoleSchemaConstants.PERMISSIONS, patchOperationList);

        Role role = new Role();
        role.setId(SAMPLE_VALID_ROLE_ID);
        role.setName(SAMPLE_VALID_ROLE_NAME);

        try (MockedStatic<SCIMCommonUtils> mockSCIMCommonUtils = mockStatic(SCIMCommonUtils.class)) {

            when(roleManagementService.getPermissionListOfRole(any(), any()))
                    .thenReturn(Arrays.asList(new Permission(SAMPLE_PERMISSION_2_NAME)));
            when(SCIMCommonUtils.getSCIMRoleV2URL(any()))
                    .thenReturn(SCIM2_ROLES_V2_LOCATION_URI_BASE + SAMPLE_VALID_ROLE_ID);
            when(RoleManagementUtils.isSharedRole(any(), any())).thenReturn(Boolean.FALSE);
            scimRoleManagerV2.patchRole(SAMPLE_VALID_ROLE_ID, patchOperations);

            // Capture the arguments passed to updatePermissionListOfRole.
            ArgumentCaptor<List<Permission>> addedPermissionsCaptor = ArgumentCaptor.forClass(List.class);
            ArgumentCaptor<List<Permission>> removedPermissionsCaptor = ArgumentCaptor.forClass(List.class);
            verify(roleManagementService, atLeastOnce()).updatePermissionListOfRole(eq(SAMPLE_VALID_ROLE_ID),
                    addedPermissionsCaptor.capture(), removedPermissionsCaptor.capture(), any());

            List<Permission> addedPermissions = addedPermissionsCaptor.getValue();
            assertEquals(addedPermissions.size(), 1);
            assertTrue(addedPermissions.stream().anyMatch(permission ->
                    SAMPLE_PERMISSION_1_NAME.equals(permission.getName())));

            List<Permission> removedPermissions = removedPermissionsCaptor.getValue();
            assertEquals(removedPermissions.size(), 0);

        } catch (BadRequestException e) {
            assertEquals(BAD_REQUEST, e.getStatus());
            assertEquals(ResponseCodeConstants.INVALID_VALUE, e.getScimType());
            assertEquals("Group id is required to update group of the role.", e.getDetail());
        }
    }

    @Test
    public void testPatchRoleWithAddRemovePermissions()
            throws IdentityRoleManagementException, ForbiddenException, ConflictException, NotFoundException,
            CharonException {

        Map<String, List<PatchOperation>> patchOperations = new HashMap<>();
        List<PatchOperation> patchOperationList = new ArrayList<>();
        PatchOperation patchOperation = getPatchOperation(SAMPLE_PERMISSION_1_NAME, SCIMConstants.OperationalConstants.ADD);
        PatchOperation patchOperation2 = getPatchOperation(SAMPLE_PERMISSION_2_NAME, SCIMConstants.OperationalConstants.REMOVE);
        patchOperationList.add(patchOperation);
        patchOperationList.add(patchOperation2);
        patchOperations.put(SCIMConstants.RoleSchemaConstants.PERMISSIONS, patchOperationList);

        Role role = new Role();
        role.setId(SAMPLE_VALID_ROLE_ID);
        role.setName(SAMPLE_VALID_ROLE_NAME);

        try (MockedStatic<SCIMCommonUtils> mockSCIMCommonUtils = mockStatic(SCIMCommonUtils.class)) {

            when(roleManagementService.getPermissionListOfRole(any(), any()))
                    .thenReturn(Arrays.asList(new Permission(SAMPLE_PERMISSION_2_NAME)));
            when(SCIMCommonUtils.getSCIMRoleV2URL(any()))
                    .thenReturn(SCIM2_ROLES_V2_LOCATION_URI_BASE + SAMPLE_VALID_ROLE_ID);
            when(RoleManagementUtils.isSharedRole(any(), any())).thenReturn(Boolean.FALSE);
            RoleV2 patchedRole = scimRoleManagerV2.patchRole(SAMPLE_VALID_ROLE_ID, patchOperations);

            // Capture the arguments passed to updatePermissionListOfRole.
            ArgumentCaptor<List<Permission>> addedPermissionsCaptor = ArgumentCaptor.forClass(List.class);
            ArgumentCaptor<List<Permission>> removedPermissionsCaptor = ArgumentCaptor.forClass(List.class);
            verify(roleManagementService, atLeastOnce()).updatePermissionListOfRole(eq(SAMPLE_VALID_ROLE_ID),
                    addedPermissionsCaptor.capture(), removedPermissionsCaptor.capture(), any());

            List<Permission> addedPermissions = addedPermissionsCaptor.getValue();
            assertEquals(addedPermissions.size(), 1);
            assertTrue(addedPermissions.stream().anyMatch(permission ->
                    SAMPLE_PERMISSION_1_NAME.equals(permission.getName())));

            List<Permission> removedPermissions = removedPermissionsCaptor.getValue();
            assertEquals(removedPermissions.size(), 1);
            assertTrue(removedPermissions.stream().anyMatch(permission ->
                    SAMPLE_PERMISSION_2_NAME.equals(permission.getName())));

        } catch (BadRequestException e) {
            assertEquals(BAD_REQUEST, e.getStatus());
            assertEquals(ResponseCodeConstants.INVALID_VALUE, e.getScimType());
            assertEquals("Group id is required to update group of the role.", e.getDetail());
        }
    }

    @Test
    public void testPatchRoleWithReplacePermissions()
            throws IdentityRoleManagementException, ForbiddenException, ConflictException, NotFoundException,
            CharonException {

        Map<String, List<PatchOperation>> patchOperations = new HashMap<>();
        List<PatchOperation> patchOperationList = new ArrayList<>();
        PatchOperation patchOperation = getPatchOperation(SAMPLE_PERMISSION_2_NAME, SCIMConstants.OperationalConstants.REPLACE);
        patchOperationList.add(patchOperation);
        patchOperations.put(SCIMConstants.RoleSchemaConstants.PERMISSIONS, patchOperationList);

        Role role = new Role();
        role.setId(SAMPLE_VALID_ROLE_ID);
        role.setName(SAMPLE_VALID_ROLE_NAME);

        try (MockedStatic<SCIMCommonUtils> mockSCIMCommonUtils = mockStatic(SCIMCommonUtils.class)) {

            when(roleManagementService.getPermissionListOfRole(any(), any()))
                    .thenReturn(Arrays.asList(new Permission(SAMPLE_PERMISSION_1_NAME)));
            when(SCIMCommonUtils.getSCIMRoleV2URL(any()))
                    .thenReturn(SCIM2_ROLES_V2_LOCATION_URI_BASE + SAMPLE_VALID_ROLE_ID);
            when(RoleManagementUtils.isSharedRole(any(), any())).thenReturn(Boolean.FALSE);
            RoleV2 patchedRole = scimRoleManagerV2.patchRole(SAMPLE_VALID_ROLE_ID, patchOperations);

            // Capture the arguments passed to updatePermissionListOfRole.
            ArgumentCaptor<List<Permission>> addedPermissionsCaptor = ArgumentCaptor.forClass(List.class);
            ArgumentCaptor<List<Permission>> removedPermissionsCaptor = ArgumentCaptor.forClass(List.class);
            verify(roleManagementService, atLeastOnce()).updatePermissionListOfRole(eq(SAMPLE_VALID_ROLE_ID),
                    addedPermissionsCaptor.capture(), removedPermissionsCaptor.capture(), any());

            List<Permission> addedPermissions = addedPermissionsCaptor.getValue();
            assertEquals(addedPermissions.size(), 1);
            assertTrue(addedPermissions.stream().anyMatch(permission ->
                    SAMPLE_PERMISSION_2_NAME.equals(permission.getName())));

            List<Permission> removedPermissions = removedPermissionsCaptor.getValue();
            assertEquals(removedPermissions.size(), 1);
            assertTrue(removedPermissions.stream().anyMatch(permission ->
                    SAMPLE_PERMISSION_1_NAME.equals(permission.getName())));

        } catch (BadRequestException e) {
            assertEquals(BAD_REQUEST, e.getStatus());
            assertEquals(ResponseCodeConstants.INVALID_VALUE, e.getScimType());
            assertEquals("Group id is required to update group of the role.", e.getDetail());
        }
    }

    private static PatchOperation getPatchOperation(String permissionName, String operation) {

        Map<String, String> valueMap = new HashMap<>();
        valueMap.put(SCIMConstants.CommonSchemaConstants.VALUE, permissionName);
        PatchOperation patchOperation = new PatchOperation();
        patchOperation.setOperation(operation);
        patchOperation.setAttributeName(SCIMConstants.RoleSchemaConstants.PERMISSIONS);
        patchOperation.setValues(valueMap);
        return patchOperation;
    }

    @Test
    public void testGetRoleWithRoleProperties() throws Exception {

        try (MockedStatic<SCIMCommonUtils> mockedSCIMCommonUtils = mockStatic(SCIMCommonUtils.class)) {

            Role mockedRole = new Role();
            mockedRole.setId(ROLE_ID);
            mockedRole.setName(ROLE_NAME);
            mockedRole.setAudience(ORGANIZATION_AUD);
            mockedRole.setAudienceId(ORGANIZATION_ID);
            mockedRole.setAudienceName(ORGANIZATION_NAME);

            RoleProperty roleProperty = new RoleProperty();
            roleProperty.setName(ROLE_PROPERTY_NAME);
            roleProperty.setValue(Boolean.TRUE.toString());
            mockedRole.setRoleProperty(roleProperty);

            mockedSCIMCommonUtils.when(() -> SCIMCommonUtils.getSCIMRoleV2URL(anyString())).
                    thenReturn(SCIM2_ROLES_V2_LOCATION_URI_BASE + ROLE_ID);

            when(roleManagementService.getRoleWithoutUsers(anyString(), anyString())).thenReturn(mockedRole);

            RoleV2 scimRole = scimRoleManagerV2.getRole(ROLE_ID, new HashMap<>());

            assertEquals(scimRole.getId(), ROLE_ID);
            assertEquals(scimRole.getDisplayName(), ROLE_NAME);
            assertEquals(scimRole.getLocation(), SCIM2_ROLES_V2_LOCATION_URI_BASE + ROLE_ID);

            List<MultiValuedComplexType> roleProperties = scimRole.getRoleProperties();
            assertEquals(roleProperties.size(), 1);
            assertEquals(scimRole.getRoleProperties().get(0).getDisplay(), ROLE_PROPERTY_NAME);
        }
    }

    @DataProvider(name = "isPropertiesRequired")
    public Object[][] provideIsPropertiesRequired() {

        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "isPropertiesRequired")
    public void testListRolesWithGETWithRoleProperties(boolean isPropertiesRequired) throws Exception {

        try (MockedStatic<SCIMCommonUtils> mockedSCIMCommonUtils = mockStatic(SCIMCommonUtils.class)) {

            List<String> requiredAttributes = new ArrayList<>();
            requiredAttributes.add("properties");

            Role mockedRole1 = new Role();
            mockedRole1.setId(ROLE_ID);
            mockedRole1.setName(ROLE_NAME);
            mockedRole1.setAudience(ORGANIZATION_AUD);
            mockedRole1.setAudienceId(ORGANIZATION_ID);
            mockedRole1.setAudienceName(ORGANIZATION_NAME);

            Role mockedRole2 = new Role();
            mockedRole2.setId("role_id_2");
            mockedRole2.setName("role_name_2");
            mockedRole2.setAudience(ORGANIZATION_AUD);
            mockedRole2.setAudienceId(ORGANIZATION_ID);
            mockedRole2.setAudienceName(ORGANIZATION_NAME);

            if (isPropertiesRequired) {
                RoleProperty roleProperty1 = new RoleProperty();
                roleProperty1.setName(ROLE_PROPERTY_NAME);
                roleProperty1.setValue(Boolean.TRUE.toString());
                mockedRole1.setRoleProperty(roleProperty1);

                RoleProperty roleProperty2 = new RoleProperty();
                roleProperty2.setName(ROLE_PROPERTY_NAME);
                roleProperty2.setValue(Boolean.FALSE.toString());
                mockedRole2.setRoleProperty(roleProperty2);
            }

            List<Role> mockedRoles = new ArrayList<>();
            mockedRoles.add(mockedRole1);
            mockedRoles.add(mockedRole2);

            mockedSCIMCommonUtils.when(() -> SCIMCommonUtils.getSCIMRoleV2URL(ROLE_ID)).
                    thenReturn(SCIM2_ROLES_V2_LOCATION_URI_BASE + ROLE_ID);
            mockedSCIMCommonUtils.when(() -> SCIMCommonUtils.getSCIMRoleV2URL(ROLE_ID_2)).
                    thenReturn(SCIM2_ROLES_V2_LOCATION_URI_BASE + ROLE_ID_2);

            when(roleManagementService.getRoles(10, 1, null, null, SAMPLE_TENANT_DOMAIN, requiredAttributes)).
                    thenReturn(mockedRoles);

            RolesV2GetResponse rolesV2GetResponse = scimRoleManagerV2.listRolesWithGET(null, 1, 10, null, null,
                    requiredAttributes);
            List<RoleV2> roles = rolesV2GetResponse.getRoles();
            assertEquals(roles.get(0).getDisplayName(), ROLE_NAME);
            assertEquals(roles.get(0).getLocation(), SCIM2_ROLES_V2_LOCATION_URI_BASE + ROLE_ID);

            assertEquals(roles.get(1).getDisplayName(), ROLE_NAME_2);
            assertEquals(roles.get(1).getLocation(), SCIM2_ROLES_V2_LOCATION_URI_BASE + ROLE_ID_2);

            if (isPropertiesRequired) {
                assertEquals(roles.get(0).getRoleProperties().get(0).getDisplay(), ROLE_PROPERTY_NAME);
                assertEquals(roles.get(0).getRoleProperties().get(0).getValue(), Boolean.TRUE.toString());
                assertEquals(roles.get(1).getRoleProperties().get(0).getDisplay(), ROLE_PROPERTY_NAME);
                assertEquals(roles.get(1).getRoleProperties().get(0).getValue(), Boolean.FALSE.toString());
            } else {
                assertTrue(roles.get(0).getRoleProperties().isEmpty());
                assertTrue(roles.get(1).getRoleProperties().isEmpty());
            }
        }
    }

    @Test
    public void testCreateRoleWhenWorkflowEnabled() throws ConflictException, NotImplementedException,
            BadRequestException, CharonException, OrganizationManagementException, IdentityRoleManagementException {

        when(OrganizationManagementUtil.isOrganization(SAMPLE_TENANT_DOMAIN)).thenReturn(true);
        when(SCIMCommonComponentHolder.getIdpManagerService()).thenReturn(idpManager);
        when(roleManagementService.addRole(eq(ROLE_NAME), any(), any(), any(), any(), any(), eq(SAMPLE_TENANT_DOMAIN))).
                thenThrow(new IdentityRoleManagementException(ROLE_WORKFLOW_CREATED.getCode(), "Role " +
                        "creation request is sent to the workflow engine for approval."));
        RoleV2 roleV2 = new RoleV2();
        roleV2.setDisplayName(ROLE_NAME);
        try {
            scimRoleManagerV2.createRole(roleV2);
        } catch (CharonException e) {
            assertEquals(e.getStatus(), ResponseCodeConstants.CODE_ACCEPTED);
            assertEquals(e.getDetail(), "Role creation request is sent to the workflow engine for approval.");
        }
    }

    /**
     * Test the buildSCIMRoleResponse method with valid inputs.
     */
    @Test
    public void testBuildSCIMRoleResponse_ValidInput() throws Exception {

        String roleId = "test-role-id-123";
        String roleName = "TestRole";
        String audienceId = "audience-id-456";
        String audienceName = "Test Audience";
        String audienceType = "application";
        String locationURI = "https://localhost:9443/scim2/v3/Roles/" + roleId;

        RoleBasicInfo roleBasicInfo = mock(RoleBasicInfo.class);
        when(roleBasicInfo.getId()).thenReturn(roleId);
        when(roleBasicInfo.getName()).thenReturn(roleName);
        when(roleBasicInfo.getAudienceId()).thenReturn(audienceId);
        when(roleBasicInfo.getAudienceName()).thenReturn(audienceName);
        when(roleBasicInfo.getAudience()).thenReturn(audienceType);

        java.lang.reflect.Method buildSCIMRoleResponseMethod = SCIMRoleManagerV2.class.getDeclaredMethod(
                "buildSCIMRoleResponse", RoleBasicInfo.class, String.class);
        buildSCIMRoleResponseMethod.setAccessible(true);
        RoleV2 result = (RoleV2) buildSCIMRoleResponseMethod.invoke(
                scimRoleManagerV2, roleBasicInfo, locationURI);

        assertEquals(result.getId(), roleId);
        assertEquals(result.getDisplayName(), roleName);
        assertEquals(result.getLocation(), locationURI);
        assertEquals(result.getAudienceValue(), audienceId);
        assertEquals(result.getAudienceDisplayName(), audienceName);
        assertEquals(result.getAudienceType(), audienceType);
    }

    /**
     * Test the buildSCIMRoleResponse method with organization audience type.
     */
    @Test
    public void testBuildSCIMRoleResponse_OrganizationAudience() throws Exception {

        String roleId = "org-role-id-789";
        String roleName = "OrganizationRole";
        String audienceId = "org-123";
        String audienceName = "Test Organization";
        String audienceType = "organization";
        String locationURI = "https://localhost:9443/scim2/v3/Roles/" + roleId;

        RoleBasicInfo roleBasicInfo = mock(RoleBasicInfo.class);
        when(roleBasicInfo.getId()).thenReturn(roleId);
        when(roleBasicInfo.getName()).thenReturn(roleName);
        when(roleBasicInfo.getAudienceId()).thenReturn(audienceId);
        when(roleBasicInfo.getAudienceName()).thenReturn(audienceName);
        when(roleBasicInfo.getAudience()).thenReturn(audienceType);

        java.lang.reflect.Method buildSCIMRoleResponseMethod = SCIMRoleManagerV2.class.getDeclaredMethod(
                "buildSCIMRoleResponse", RoleBasicInfo.class, String.class);
        buildSCIMRoleResponseMethod.setAccessible(true);
        RoleV2 result = (RoleV2) buildSCIMRoleResponseMethod.invoke(
                scimRoleManagerV2, roleBasicInfo, locationURI);

        assertEquals(result.getId(), roleId);
        assertEquals(result.getDisplayName(), roleName);
        assertEquals(result.getLocation(), locationURI);
        assertEquals(result.getAudienceValue(), audienceId);
        assertEquals(result.getAudienceDisplayName(), audienceName);
        assertEquals(result.getAudienceType(), audienceType);
    }
}
