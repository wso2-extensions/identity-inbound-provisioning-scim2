/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.role.mgt.core.GroupBasicInfo;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementClientException;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementServerException;
import org.wso2.carbon.identity.role.mgt.core.RoleBasicInfo;
import org.wso2.carbon.identity.role.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.mgt.core.UserBasicInfo;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.Role;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.utils.codeutils.ExpressionNode;
import org.wso2.charon3.core.utils.codeutils.Node;
import org.wso2.charon3.core.utils.codeutils.OperationNode;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyListOf;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.INVALID_LIMIT;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.INVALID_REQUEST;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.OPERATION_FORBIDDEN;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.ROLE_ALREADY_EXISTS;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.ROLE_NOT_FOUND;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.UNEXPECTED_SERVER_ERROR;

/**
 * Contains the unit test cases for SCIMRoleManager.
 */
@PrepareForTest({SCIMCommonUtils.class})
public class SCIMRoleManagerTest extends PowerMockTestCase {

    private static final String SAMPLE_TENANT_DOMAIN = "carbon.super";
    private static final String SAMPLE_TENANT_DOMAIN2 = "abc.com";
    private static final String SAMPLE_INVALID_TENANT_DOMAIN = "invalid.org";
    private static final String SAMPLE_VALID_ROLE_ID = "8215b39a-49c6-4f91-9acf-4255fca362e5";
    private static final String SAMPLE_VALID_ROLE_ID2 = "1105d7a2-f91b-4f18-8b60-c53d02453372";
    private static final String SAMPLE_INVALID_ROLE_ID = "1614d770a5ba46afa3cb92d4cc097f3c";
    private static final String SAMPLE_INVALID_ROLE_ID2 = "cad7360942b0-4a2e-8ead-bf0c8@dbea602";
    private static final String SAMPLE_EXISTING_ROLE_ID = "6660279b-14ee-466b-895f-41f9a22ed5f1";
    private static final String SAMPLE_EXISTING_ROLE_ID2 = "73584b7d-45d9-4b0a-9b04-2ac7ff0d5a20";
    private static final String SAMPLE_NON_EXISTING_ROLE_ID = "04b5af38-0bf8-4fff-91c6-2425b273b17a";
    private static final String SAMPLE_NON_EXISTING_ROLE_ID2 = "ad26d674-b163-4cd6-a353-46322d60a491";
    private static final String SAMPLE_VALID_ROLE_NAME = "roleDisplayName1";
    private static final String SAMPLE_VALID_ROLE_NAME2 = "roleDisplayName2";
    private static final String SAMPLE_SYSTEM_ROLE_NAME = "roleDisplayName3";
    private static final String SAMPLE_SYSTEM_ROLE_NAME2 = "roleDisplayName4";
    private static final String SAMPLE_EXISTING_ROLE_NAME = "roleDisplayName5";
    private static final String SAMPLE_EXISTING_ROLE_NAME2 = "roleDisplayName6";
    private static final String SAMPLE_INVALID_ROLE_NAME = "system_roleName1";
    private static final String DUMMY_SCIM_URL =
            "https://localhost:9444/scim2/Roles/3891465e-4ecb-45f6-9822-e411c2deab64";
    private static final List<String> INVALID_ROLE_IDS = Arrays.asList(SAMPLE_INVALID_ROLE_ID, SAMPLE_INVALID_ROLE_ID2);
    private static final List<String> NON_EXISTING_ROLE_IDS = Arrays.asList(SAMPLE_NON_EXISTING_ROLE_ID,
            SAMPLE_NON_EXISTING_ROLE_ID2);
    private static final List<String> EXISTING_ROLE_NAMES = Arrays.asList(SAMPLE_EXISTING_ROLE_NAME,
            SAMPLE_EXISTING_ROLE_NAME2);
    private static final Set<String> SYSTEM_ROLES = new HashSet<>(Arrays.asList(SAMPLE_SYSTEM_ROLE_NAME,
            SAMPLE_SYSTEM_ROLE_NAME2));

    @Mock
    RoleManagementService mockRoleManagementService;

    @BeforeClass
    public void setUpClass() {

        initMocks(this);
    }

    @BeforeMethod
    public void setUpMethod() {

        mockStatic(SCIMCommonUtils.class);
        when(SCIMCommonUtils.getSCIMRoleURL(anyString())).thenReturn(DUMMY_SCIM_URL);
        when(mockRoleManagementService.getSystemRoles()).thenReturn(SYSTEM_ROLES);
    }

    @DataProvider(name = "dataProviderForCreateRoleExistingRole")
    public Object[][] dataProviderForCreateRoleExistingRole() {

        return new Object[][]{
                {SAMPLE_EXISTING_ROLE_ID, SAMPLE_VALID_ROLE_NAME},
                {SAMPLE_EXISTING_ROLE_ID2, ""}
        };
    }

    @Test(dataProvider = "dataProviderForCreateRoleExistingRole")
    public void testCreateRoleExistingRole(String roleId, String roleDisplayName)
            throws IdentityRoleManagementException, BadRequestException, CharonException {

        Role role = getDummyRole(roleId, roleDisplayName);
        when(mockRoleManagementService.isExistingRole(anyString(), anyString())).thenReturn(true);
        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN2);
        assertThrows(ConflictException.class, () -> scimRoleManager.createRole(role));
    }

    @Test
    public void testCreateRoleAddRoleExistingRoleName()
            throws BadRequestException, CharonException, IdentityRoleManagementException {

        Role role = getDummyRole(SAMPLE_VALID_ROLE_ID2, SAMPLE_EXISTING_ROLE_NAME);
        when(mockRoleManagementService.addRole(anyString(), anyListOf(String.class), anyListOf(String.class),
                anyListOf(String.class), anyString())).thenThrow(
                new IdentityRoleManagementException(ROLE_ALREADY_EXISTS.getCode(),
                        "Role already exist for the role name: " + SAMPLE_EXISTING_ROLE_NAME));
        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(ConflictException.class, () -> scimRoleManager.createRole(role));
    }

    @Test
    public void testCreateRoleAddRoleInvalidRoleName()
            throws BadRequestException, CharonException, IdentityRoleManagementException {

        Role role = getDummyRole(SAMPLE_VALID_ROLE_ID, SAMPLE_INVALID_ROLE_NAME);

        when(mockRoleManagementService.addRole(anyString(), anyListOf(String.class), anyListOf(String.class),
                anyListOf(String.class), anyString())).
                thenThrow(new IdentityRoleManagementClientException(INVALID_REQUEST.getCode(),
                        String.format("Invalid role name: %s. Role names with the prefix: %s, is not allowed"
                                        + " to be created from externally in the system.", SAMPLE_INVALID_ROLE_NAME,
                                UserCoreConstants.INTERNAL_SYSTEM_ROLE_PREFIX)));
        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(BadRequestException.class, () -> scimRoleManager.createRole(role));
    }

    @DataProvider(name = "dataProviderForCreateRoleUnexpectedServerError")
    public Object[][] dataProviderForCreateRoleUnexpectedServerError() {

        return new Object[][]{
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN, "sql error"},
                {SAMPLE_VALID_ROLE_ID2, "", SAMPLE_INVALID_TENANT_DOMAIN, null}
        };
    }

    @Test(dataProvider = "dataProviderForCreateRoleUnexpectedServerError")
    public void testCreateRoleUnexpectedServerError(String roleId, String roleDisplayName, String tenantDomain,
                                                    String sError)
            throws BadRequestException, CharonException, IdentityRoleManagementException {

        Role role = getDummyRole(roleId, roleDisplayName);
        when(mockRoleManagementService.addRole(anyString(), anyListOf(String.class), anyListOf(String.class),
                anyListOf(String.class), anyString())).
                thenThrow(unExpectedErrorThrower(tenantDomain, sError,
                        "Error while creating the role: %s in the tenantDomain: %s", roleDisplayName));
        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        assertThrows(CharonException.class, () -> scimRoleManager.createRole(role));
    }

    @DataProvider(name = "dataProviderForCreateRolePositive")
    public Object[][] dataProviderForCreateRolePositive() {

        return new Object[][]{
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_TENANT_DOMAIN},
                {SAMPLE_VALID_ROLE_ID2, "", SAMPLE_TENANT_DOMAIN},
                {SAMPLE_VALID_ROLE_ID, null, SAMPLE_TENANT_DOMAIN},
                {"", null, SAMPLE_TENANT_DOMAIN},
                {null, null, SAMPLE_TENANT_DOMAIN},
                {SAMPLE_VALID_ROLE_ID2, null, ""},
                {"", "", SAMPLE_TENANT_DOMAIN},
        };
    }

    @Test(dataProvider = "dataProviderForCreateRolePositive")
    public void testCreateRolePositive(String roleId, String roleDisplayName, String tenantDomain)
            throws IdentityRoleManagementException, BadRequestException, CharonException, ConflictException {

        Role role = getDummyRole(roleId, roleDisplayName);
        when(mockRoleManagementService.addRole(anyString(), anyListOf(String.class), anyListOf(String.class),
                anyListOf(String.class), anyString())).thenReturn(new RoleBasicInfo(roleId, roleDisplayName));
        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        Role createdRole = scimRoleManager.createRole(role);
        assertEquals(createdRole.getDisplayName(), roleDisplayName);
        assertEquals(createdRole.getId(), roleId);
    }

    @DataProvider(name = "dataProviderForGetRoleNotFound")
    public Object[][] dataProviderForGetRoleNotFound() {

        return new Object[][]{
                {SAMPLE_NON_EXISTING_ROLE_ID, SAMPLE_TENANT_DOMAIN},
                {SAMPLE_NON_EXISTING_ROLE_ID2, SAMPLE_INVALID_TENANT_DOMAIN}
        };
    }

    @Test(dataProvider = "dataProviderForGetRoleNotFound")
    public void testGetRoleNotFound(String roleId, String tenantDomain)
            throws IdentityRoleManagementException {

        when(mockRoleManagementService.getRole(roleId, tenantDomain)).
                thenThrow(new IdentityRoleManagementClientException(ROLE_NOT_FOUND.getCode(),
                        String.format("A role doesn't exist with id: %s in the tenantDomain: %s",
                                roleId, tenantDomain)));

        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        assertThrows(NotFoundException.class, () -> scimRoleManager.getRole(roleId, null));
    }

    @DataProvider(name = "dataProviderForGetRoleUnexpectedServerError")
    public Object[][] dataProviderForGetRoleUnexpectedServerError() {

        return new Object[][]{
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_TENANT_DOMAIN2, "sql error"},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_INVALID_TENANT_DOMAIN, null},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_INVALID_TENANT_DOMAIN, "sql error"},
        };
    }

    @Test(dataProvider = "dataProviderForGetRoleUnexpectedServerError")
    public void testGetRoleUnexpectedServerError(String roleId, String tenantDomain, String sError)
            throws IdentityRoleManagementException {

        when(mockRoleManagementService.getRole(roleId, tenantDomain)).
                thenThrow(unExpectedErrorThrower(tenantDomain, sError,
                        "Error while creating the role: %s in the tenantDomain: %s", roleId));

        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        assertThrows(CharonException.class, () -> scimRoleManager.getRole(roleId, null));
    }

    @DataProvider(name = "dataProviderForGetRolePositive")
    public Object[][] dataProviderForGetRolePositive() {

        return new Object[][]{
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, "roleDomain1", SAMPLE_TENANT_DOMAIN,
                        "urn:ietf:params:scim:schemas:extension:2.0:Role:groups.value", true, false},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME2, null, SAMPLE_TENANT_DOMAIN,
                        "urn:ietf:params:scim:schemas:extension:2.0:Role:groups.value", false, false},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_SYSTEM_ROLE_NAME, null, SAMPLE_TENANT_DOMAIN,
                        "urn:ietf:params:scim:schemas:extension:2.0:Role:groups.value", false, true},
                {SAMPLE_VALID_ROLE_ID, null, "roleDomain1", SAMPLE_TENANT_DOMAIN2, null, false, true},
                {SAMPLE_VALID_ROLE_ID2, "", "roleDomainX", SAMPLE_TENANT_DOMAIN, "", true, false},
                {null, SAMPLE_VALID_ROLE_NAME, "", SAMPLE_TENANT_DOMAIN2, null, true, false},
                {"", "", "", "", "", false, true}
        };
    }

    @Test(dataProvider = "dataProviderForGetRolePositive")
    public void testGetRolePositive(String roleId, String roleName, String domain, String tenantDomain,
                                    String attributeKey, Boolean attributeValue, boolean isEmptyLists)
            throws IdentityRoleManagementException, BadRequestException, NotFoundException, CharonException {

        org.wso2.carbon.identity.role.mgt.core.Role role = getDummyIdentityRole(roleId, roleName, domain, tenantDomain,
                isEmptyLists);
        Map<String, Boolean> attributeMap = null;
        if (attributeKey != null) {
            // If attributeKey is not null, Add dummy data to attributeMap.
            attributeMap = new HashMap<>();
            attributeMap.put(attributeKey, attributeValue);
        }
        when(mockRoleManagementService.getRole(roleId, tenantDomain)).thenReturn(role);

        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        Role scimRole = scimRoleManager.getRole(roleId, attributeMap);
        assertScimRoleFull(scimRole, roleId);
    }

    @Test
    public void testDeleteRoleNonExistingRoleId()
            throws IdentityRoleManagementException {

        doThrow(new IdentityRoleManagementClientException(ROLE_NOT_FOUND.getCode(),
                String.format("A role doesn't exist with id: %s in the tenantDomain: %s",
                        SAMPLE_NON_EXISTING_ROLE_ID2, SAMPLE_TENANT_DOMAIN))).doNothing()
                .when(mockRoleManagementService).deleteRole(SAMPLE_NON_EXISTING_ROLE_ID2, SAMPLE_TENANT_DOMAIN);
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(NotFoundException.class, () -> roleManager.deleteRole(SAMPLE_NON_EXISTING_ROLE_ID2));
    }

    @Test
    public void testDeleteRoleUnDeletableRole()
            throws IdentityRoleManagementException {

        doThrow(new IdentityRoleManagementClientException(OPERATION_FORBIDDEN.getCode(),
                "Invalid operation. Role: adminId Cannot be deleted.")).
                doNothing().when(mockRoleManagementService).deleteRole("adminId", SAMPLE_TENANT_DOMAIN);

        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(BadRequestException.class, () -> roleManager.deleteRole("adminId"));
    }

    @DataProvider(name = "dataProviderForDeleteRoleUnExpectedError")
    public Object[][] dataProviderForDeleteRoleUnExpectedError() {

        return new Object[][]{
                {SAMPLE_VALID_ROLE_ID, SAMPLE_INVALID_TENANT_DOMAIN, "sql error"},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_INVALID_TENANT_DOMAIN, null},
                {"", SAMPLE_TENANT_DOMAIN2, "sql error"},
        };
    }

    @Test(dataProvider = "dataProviderForDeleteRoleUnExpectedError")
    public void testDeleteRoleUnExpectedError(String roleId, String tenantDomain, String sError)
            throws IdentityRoleManagementException {

        doThrow(unExpectedErrorThrower(tenantDomain, sError,
                "Error while creating the role: %s in the tenantDomain: %s", roleId)).
                doNothing().when(mockRoleManagementService).deleteRole(roleId, tenantDomain);

        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        assertThrows(CharonException.class, () -> roleManager.deleteRole(roleId));
    }

    @DataProvider(name = "dataProviderForDeleteRolePositive")
    public Object[][] dataProviderForDeleteRolePositive() {

        return new Object[][]{
                {SAMPLE_VALID_ROLE_ID, SAMPLE_TENANT_DOMAIN},
                {"", SAMPLE_TENANT_DOMAIN2},
                {null, SAMPLE_TENANT_DOMAIN},
                {SAMPLE_VALID_ROLE_ID2, null}
        };
    }

    @Test(dataProvider = "dataProviderForDeleteRolePositive")
    public void testDeleteRolePositive(String roleId, String tenantDomain)
            throws IdentityRoleManagementException, NotFoundException, BadRequestException, CharonException {

        doNothing().when(mockRoleManagementService).deleteRole(roleId, tenantDomain);
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        roleManager.deleteRole(roleId);
        verify(mockRoleManagementService, times(1)).deleteRole(roleId, tenantDomain);
    }

    @DataProvider(name = "dataProviderForListRolesWithGETSortingNotSupport")
    public Object[][] dataProviderForListRolesWithGETSortingNotSupport() {

        return new Object[][]{
                {1, 3, "name", "ascending"},
                {2, 2, null, "ascending"},
                {2, 5, "", "ascending"},
                {0, 0, "name", null},
                {3, 0, "name", ""},
                {3, 0, "", ""}
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithGETSortingNotSupport")
    public void testListRolesWithGETSortingNotSupport(Integer startIndex, Integer count, String sortBy,
                                                      String sortOrder) {

        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(NotImplementedException.class, () -> roleManager.
                listRolesWithGET(null, startIndex, count, sortBy, sortOrder));
    }

    @Test
    public void testListRolesWithGETCountNullZero()
            throws NotImplementedException, BadRequestException, CharonException {

        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        List<Object> roles = roleManager.listRolesWithGET(null, 1, 0, null, null);
        assertEquals(roles.size(), 0);
    }

    @DataProvider(name = "dataProviderForListRolesWithGETInvalidLimit")
    public Object[][] dataProviderForListRolesWithGETInvalidLimit() {

        return new Object[][]{
                {"Expression", -2},
                {null, -5},
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithGETInvalidLimit")
    public void testListRolesWithGETInvalidLimit(String nodeType, Integer count)
            throws IdentityRoleManagementException {

        Node rootNode = generateNodeBasedOnNodeType(nodeType, null);
        when(mockRoleManagementService.getRoles(anyInt(), anyInt(), anyString(), anyString(), anyString())).
                thenAnswer(invocationOnMock -> {
                    Integer countArg = invocationOnMock.getArgument(0);
                    if (countArg != null && countArg < 0) {
                        String errorMessage = String.format("Invalid limit requested. Limit value should be " +
                                "greater than or equal to zero. limit: %s", count);
                        throw new IdentityRoleManagementClientException(INVALID_LIMIT.getCode(), errorMessage);
                    }
                    return null;
                });
        when(mockRoleManagementService.getRoles(anyString(), anyInt(), anyInt(), anyString(), anyString(), anyString()))
                .thenAnswer(invocationOnMock -> {
                    Integer countArg = invocationOnMock.getArgument(1);
                    if (countArg != null && countArg < 0) {
                        String errorMessage = String.format("Invalid limit requested. Limit value should be " +
                                "greater than or equal to zero. limit: %s", count);
                        throw new IdentityRoleManagementClientException(INVALID_LIMIT.getCode(), errorMessage);
                    }
                    return null;
                });
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(CharonException.class, () -> roleManager.
                listRolesWithGET(rootNode, 2, count, null, null));
    }

    @DataProvider(name = "dataProviderForListRolesWithGETInvalidOffset")
    public Object[][] dataProviderForListRolesWithGETInvalidOffset() {

        return new Object[][]{
                {"Expression", -1},
                {null, -2}
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithGETInvalidOffset")
    public void testListRolesWithGETInvalidOffset(String nodeType, Integer startIndex)
            throws IdentityRoleManagementException {

        Node rootNode = generateNodeBasedOnNodeType(nodeType, null);
        when(mockRoleManagementService.getRoles(anyInt(), anyInt(), anyString(), anyString(), anyString())).
                thenAnswer(invocationOnMock -> {
                    Integer startIndexArg = invocationOnMock.getArgument(1);
                    if (startIndexArg != null && startIndexArg < 0) {
                        String errorMessage =
                                "Invalid offset requested. Offset value should be greater " +
                                        "than or equal to zero. offset: " + startIndexArg;
                        throw new IdentityRoleManagementClientException(INVALID_LIMIT.getCode(), errorMessage);
                    }
                    return null;
                });
        when(mockRoleManagementService.getRoles(anyString(), anyInt(), anyInt(), anyString(), anyString(), anyString()))
                .thenAnswer(invocationOnMock -> {
                    Integer startIndexArg = invocationOnMock.getArgument(2);
                    if (startIndexArg != null && startIndexArg < 0) {
                        String errorMessage =
                                "Invalid offset requested. offset value should be greater than or " +
                                        "equal to zero. offset: " + startIndexArg;
                        throw new IdentityRoleManagementClientException(INVALID_LIMIT.getCode(), errorMessage);
                    }
                    return null;
                });

        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(CharonException.class, () -> roleManager.
                listRolesWithGET(rootNode, startIndex, 2, null, null));
    }

    @DataProvider(name = "dataProviderForListRolesWithGETUnExpectedServerError")
    public Object[][] dataProviderForListRolesWithGETUnExpectedServerError() {

        return new Object[][]{
                {"Expression", SAMPLE_INVALID_TENANT_DOMAIN, null},
                {null, SAMPLE_TENANT_DOMAIN2, "sql error"},
                {null, SAMPLE_INVALID_TENANT_DOMAIN, "sql error"},
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithGETUnExpectedServerError")
    public void testListRolesWithGETUnExpectedServerError(String nodeType, String tenantDomain, String sError)
            throws IdentityRoleManagementException {

        Node rootNode = generateNodeBasedOnNodeType(nodeType, "name");
        when(mockRoleManagementService.getRoles(anyInt(), anyInt(), anyString(), anyString(), anyString())).
                thenThrow(unExpectedErrorThrower(tenantDomain, sError,
                        "Error while listing roles in tenantDomain: "));
        when(mockRoleManagementService.getRoles(anyString(), anyInt(), anyInt(), anyString(),
                anyString(), anyString())).
                thenThrow(unExpectedErrorThrower(tenantDomain, sError,
                        "Error while listing roles in tenantDomain: "));
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        assertThrows(CharonException.class, () -> roleManager.
                listRolesWithGET(rootNode, 2, 2, null, null));
    }

    @Test
    public void testListRolesWithGETOperationNode() {

        Node rootNode = generateNodeBasedOnNodeType("Operation", "name");
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN2);
        assertThrows(NotImplementedException.class, () -> roleManager.
                listRolesWithGET(rootNode, 2, 2, null, null));
    }

    @Test
    public void testListRolesWithGETInvalidNode() {

        Node rootNode = new MockNode();
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(CharonException.class, () -> roleManager.
                listRolesWithGET(rootNode, 2, 2, null, null));
    }

    @Test
    public void testListRolesWithBadRequest() {

        Node rootNode = generateNodeBasedOnNodeType("Expression", "name", "bad operation");
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(BadRequestException.class, () -> roleManager.
                listRolesWithGET(rootNode, 2, 2, null, null));
    }

    @DataProvider(name = "dataProviderForListRolesWithGETPositive")
    public Object[][] dataProviderForListRolesWithGETPositive() {

        return new Object[][]{
                {null, 1, SCIMCommonConstants.CO},
                {"Expression", 2, SCIMCommonConstants.EQ},
                {"Expression", 2, SCIMCommonConstants.SW},
                {"Expression", 3, SCIMCommonConstants.EW},
                {"Expression", 4, SCIMCommonConstants.CO},
                {"Expression", null, SCIMCommonConstants.CO},
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithGETPositive")
    public void testListRolesWithGETPositive(String nodeType, Object count, String operation)
            throws CharonException, IdentityRoleManagementException, NotImplementedException, BadRequestException {

        Node rootNode = generateNodeBasedOnNodeType(nodeType, "name", operation);
        List<RoleBasicInfo> roleList = getDummyRoleBasicInfoList();

        when(mockRoleManagementService.getRoles(anyInt(), anyInt(), anyString(), anyString(), anyString())).
                thenAnswer(invocationOnMock -> roleList);
        when(mockRoleManagementService.getRoles(anyString(), anyInt(), anyInt(), anyString(),
                anyString(), anyString())).
                thenAnswer(invocationOnMock -> roleList);
        when(mockRoleManagementService.getRolesCount(anyString())).thenAnswer(invocationOnMock -> 5);

        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        List<Object> listRolesWithGET = roleManager.listRolesWithGET(rootNode, 2, (Integer) count, null, null);
        int totalRolesCount = (Integer)listRolesWithGET.get(0);
        if (rootNode == null) {
            assertEquals(totalRolesCount, 5);
        } else {
            assertEquals(totalRolesCount, roleList.size());
        }
        assertTrue(true, "list roles works as expected");
    }

    @DataProvider(name = "dataProviderForUpdateRoleUpdateRoleName")
    public Object[][] dataProviderForUpdateRoleUpdateRoleName() {

        return new Object[][]{
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN2, ""},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME, SAMPLE_TENANT_DOMAIN2, ""},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        "EMPTY_DELETED"},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        "EMPTY_NEW"},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        "EMPTY_BOTH"},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_INVALID_TENANT_DOMAIN,
                        "NULL_NEW_PERMISSION"},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        "NULL_OLD_PERMISSION"},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        "EMPTY_NEW_PERMISSION"},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        "EMPTY_OLD_PERMISSION"},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        "ALL_EMPTY_PERMISSION"},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        "ALL_EQUAL_PERMISSION"},
        };
    }

    @Test(dataProvider = "dataProviderForUpdateRoleUpdateRoleName")
    public void testUpdateRoleUpdateRoleName(String roleId, String oldRoleName, String newRoleName, String tenantDomain,
                                             String type)
            throws IdentityRoleManagementException, BadRequestException, CharonException, ConflictException,
            NotFoundException {

        RoleBasicInfo roleBasicInfo = new RoleBasicInfo(roleId, newRoleName);
        Role[] oldAndNewRoles = getOldAndNewRoleDummies(roleId, oldRoleName, newRoleName, type);
        when(mockRoleManagementService.updateRoleName(anyString(), anyString(), anyString())).thenReturn(roleBasicInfo);
        when(mockRoleManagementService.updateUserListOfRole(
                eq(roleId), anyListOf(String.class), anyListOf(String.class), anyString())).thenReturn(roleBasicInfo);
        when(mockRoleManagementService.updateGroupListOfRole(eq(roleId), anyListOf(String.class),
                anyListOf(String.class), anyString())).thenReturn(roleBasicInfo);
        when(mockRoleManagementService.setPermissionsForRole(eq(roleId), anyListOf(String.class), anyString())).
                thenReturn(roleBasicInfo);

        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        scimRoleManager.updateRole(oldAndNewRoles[0], oldAndNewRoles[1]);

        assertTrue(true, "updateRole execute successfully");
    }

    @DataProvider(name = "dataProviderForUpdateRoleUpdateRoleNameThrowingErrors")
    public Object[][] dataProviderForUpdateRoleUpdateRoleNameThrowingErrors() {

        return new Object[][]{
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_EXISTING_ROLE_NAME, SAMPLE_TENANT_DOMAIN, null,},
                {SAMPLE_NON_EXISTING_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        null},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_SYSTEM_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN, null},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_INVALID_TENANT_DOMAIN,
                        null},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN2,
                        "sql error"}
        };
    }

    @Test(dataProvider = "dataProviderForUpdateRoleUpdateRoleNameThrowingErrors", expectedExceptions = {
            ConflictException.class, NotFoundException.class, BadRequestException.class, CharonException.class})
    public void testUpdateRoleUpdateRoleNameThrowingErrors(String roleId, String oldRoleName, String newRoleName,
                                                           String tenantDomain, String sError)
            throws IdentityRoleManagementException, BadRequestException, CharonException, ConflictException,
            NotFoundException {

        Role[] oldAndNewRoles = getOldAndNewRoleDummies(roleId, oldRoleName, newRoleName);

        when(mockRoleManagementService.updateRoleName(anyString(), anyString(), anyString())).
                thenAnswer(invocationOnMock -> {
                    String newRoleNameArg = invocationOnMock.getArgument(1);
                    String roleIdArg = invocationOnMock.getArgument(0);
                    String tenantDomainArg = invocationOnMock.getArgument(2);
                    if (EXISTING_ROLE_NAMES.contains(newRoleNameArg)) {
                        throw new IdentityRoleManagementClientException(ROLE_ALREADY_EXISTS.getCode(),
                                "Role name: " + newRoleNameArg +
                                        " is already there in the system. Please pick another role name.");
                    }
                    if (NON_EXISTING_ROLE_IDS.contains(roleIdArg)) {
                        throw new IdentityRoleManagementClientException(ROLE_NOT_FOUND.getCode(),
                                "Role id: " + roleIdArg + " does not exist in the system.");
                    }
                    if (SYSTEM_ROLES.contains(oldRoleName)) {
                        throw new IdentityRoleManagementClientException(RoleConstants.Error.OPERATION_FORBIDDEN.
                                getCode(),
                                "Invalid operation. Role: " + oldRoleName +
                                        " Cannot be renamed since it's a read only system role.");
                    }
                    Throwable unExpectedErrors = unExpectedErrorThrower(tenantDomainArg, sError,
                            "Error while updating users to the role: %s in the tenantDomain: %s",
                            roleIdArg);
                    if (unExpectedErrors != null) throw unExpectedErrors;
                    return null;
                });

        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        scimRoleManager.updateRole(oldAndNewRoles[0], oldAndNewRoles[1]);
    }

    @DataProvider(name = "dataProviderForUpdateRoleUpdateUserListOfRoleThrowingErrors")
    public Object[][] dataProviderForUpdateRoleUpdateUserListOfRoleThrowingErrors() {

        return new Object[][]{
                {SAMPLE_INVALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN, "",
                        null},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_INVALID_TENANT_DOMAIN,
                        "", null},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN,
                        "", "sql error"},
        };
    }

    @Test(dataProvider = "dataProviderForUpdateRoleUpdateUserListOfRoleThrowingErrors", expectedExceptions =
            {BadRequestException.class, CharonException.class})
    public void testUpdateRoleUpdateUserListOfRoleThrowingErrors(String roleId, String oldRoleName, String newRoleName,
                                                                 String tenantDomain, String type, String sError)
            throws IdentityRoleManagementException, BadRequestException, CharonException, ConflictException,
            NotFoundException {

        RoleBasicInfo roleBasicInfo = new RoleBasicInfo(roleId, newRoleName);
        Role[] oldAndNewRoles = getOldAndNewRoleDummies(roleId, oldRoleName, newRoleName, type);

        when(mockRoleManagementService.updateRoleName(anyString(), anyString(), anyString())).thenReturn(roleBasicInfo);
        when(mockRoleManagementService.updateUserListOfRole(
                anyString(), anyListOf(String.class), anyListOf(String.class), anyString())).
                thenAnswer(invocationOnMock -> {
                    String roleIdArg = invocationOnMock.getArgument(0);
                    String tenantDomainArg = invocationOnMock.getArgument(3);
                    if (INVALID_ROLE_IDS.contains(roleIdArg)) {
                        String errorMessage =
                                "Invalid scenario. Multiple roles found for the given role name: " + roleIdArg
                                        + " and tenantDomain: " + tenantDomain;
                        throw new IdentityRoleManagementClientException(INVALID_REQUEST.getCode(), errorMessage);
                    }
                    Throwable unExpectedErrors = unExpectedErrorThrower(tenantDomainArg, sError,
                            "Error while updating users to the role: %s in the tenantDomain: %s",
                            roleIdArg);
                    if (unExpectedErrors != null) throw unExpectedErrors;
                    return roleBasicInfo;
                });

        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        scimRoleManager.updateRole(oldAndNewRoles[0], oldAndNewRoles[1]);
    }

    @DataProvider(name = "dataProviderForUpdateRoleUpdateGroupListOfRoleThrowingErrors")
    public Object[][] dataProviderForUpdateRoleUpdateGroupListOfRoleThrowingErrors() {

        return new Object[][]{
                {SAMPLE_INVALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN, "",
                        null},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_INVALID_TENANT_DOMAIN,
                        "", null},
                {SAMPLE_VALID_ROLE_ID2, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN2, "",
                        "sql error"},
        };
    }

    @Test(dataProvider = "dataProviderForUpdateRoleUpdateGroupListOfRoleThrowingErrors", expectedExceptions = {
            BadRequestException.class, CharonException.class})
    public void testUpdateRoleUpdateGroupListOfRoleThrowingErrors(String roleId, String oldRoleName, String newRoleName,
                                                                  String tenantDomain, String type, String sError)
            throws IdentityRoleManagementException, BadRequestException, CharonException, ConflictException,
            NotFoundException {

        RoleBasicInfo roleBasicInfo = new RoleBasicInfo(roleId, newRoleName);
        Role[] oldAndNewRoles = getOldAndNewRoleDummies(roleId, oldRoleName, newRoleName, type);
        when(mockRoleManagementService.updateRoleName(anyString(), anyString(), anyString())).thenReturn(roleBasicInfo);
        when(mockRoleManagementService.updateGroupListOfRole(
                anyString(), anyListOf(String.class), anyListOf(String.class), anyString())).
                thenAnswer(invocationOnMock -> {
                    String roleIdArg = invocationOnMock.getArgument(0);
                    String tenantDomainArg = invocationOnMock.getArgument(3);
                    if (INVALID_ROLE_IDS.contains(roleIdArg)) {
                        String errorMessage =
                                "Invalid scenario. Multiple roles found for the given role name: " + roleIdArg
                                        + " and tenantDomain: " + tenantDomain;
                        throw new IdentityRoleManagementClientException(INVALID_REQUEST.getCode(), errorMessage);
                    }
                    Throwable unExpectedErrors = unExpectedErrorThrower(tenantDomainArg, sError,
                            "Error while updating users to the role: %s in the tenantDomain: %s", roleIdArg);
                    if (unExpectedErrors != null) throw unExpectedErrors;
                    return roleBasicInfo;
                });
        when(mockRoleManagementService.updateUserListOfRole(eq(roleId), anyListOf(String.class),
                anyListOf(String.class), anyString())).thenReturn(roleBasicInfo);

        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        scimRoleManager.updateRole(oldAndNewRoles[0], oldAndNewRoles[1]);
    }

    @DataProvider(name = "dataProviderForRoleUpdatePermissionListOfRoleThrowingErrors")
    public Object[][] dataProviderForRoleUpdatePermissionListOfRoleThrowingErrors() {

        return new Object[][]{
                {SAMPLE_INVALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN, "",
                        null},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_SYSTEM_ROLE_NAME2, SAMPLE_VALID_ROLE_NAME2, SAMPLE_TENANT_DOMAIN, "",
                        null},
                {SAMPLE_VALID_ROLE_ID, SAMPLE_VALID_ROLE_NAME, SAMPLE_VALID_ROLE_NAME2, SAMPLE_INVALID_TENANT_DOMAIN,
                        "", null},
        };
    }

    @Test(dataProvider = "dataProviderForRoleUpdatePermissionListOfRoleThrowingErrors", expectedExceptions =
            {BadRequestException.class, CharonException.class})
    public void testRoleUpdatePermissionListOfRoleThrowingErrors(String roleId, String oldRoleName, String newRoleName,
                                                                 String tenantDomain, String permissionType,
                                                                 String sError)
            throws IdentityRoleManagementException, BadRequestException, CharonException,
            ConflictException, NotFoundException {

        RoleBasicInfo roleBasicInfo = new RoleBasicInfo(roleId, newRoleName);
        Role[] oldAndNewRoles = getOldAndNewRoleDummies(roleId, oldRoleName, newRoleName, permissionType);
        when(mockRoleManagementService.updateRoleName(anyString(), anyString(), anyString())).thenReturn(roleBasicInfo);
        when(mockRoleManagementService.setPermissionsForRole(
                anyString(), anyListOf(String.class), anyString())).
                thenAnswer(invocationOnMock -> {
                    String roleIdArg = invocationOnMock.getArgument(0);
                    String tenantDomainArg = invocationOnMock.getArgument(2);
                    if (INVALID_ROLE_IDS.contains(roleIdArg)) {
                        String errorMessage =
                                "Invalid scenario. Multiple roles found for the given role name: " + roleIdArg
                                        + " and tenantDomain: " + tenantDomain;
                        throw new IdentityRoleManagementClientException(INVALID_REQUEST.getCode(), errorMessage);
                    }
                    if (SYSTEM_ROLES.contains(oldRoleName)) {
                        throw new IdentityRoleManagementClientException(RoleConstants.Error.OPERATION_FORBIDDEN.
                                getCode(), "Invalid operation. Permissions cannot be modified in the role: "
                                + oldRoleName + " since it's a read only system role.");
                    }
                    Throwable unExpectedErrors = unExpectedErrorThrower(tenantDomainArg, sError,
                            "Error while updating users to the role: %s in the tenantDomain: %s",
                            roleIdArg);
                    if (unExpectedErrors != null) throw unExpectedErrors;
                    return roleBasicInfo;
                });
        when(mockRoleManagementService.updateUserListOfRole(eq(roleId), anyListOf(String.class),
                anyListOf(String.class), anyString())).thenReturn(roleBasicInfo);
        when(mockRoleManagementService.updateGroupListOfRole(eq(roleId), anyListOf(String.class),
                anyListOf(String.class), anyString())).thenReturn(roleBasicInfo);

        SCIMRoleManager scimRoleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        scimRoleManager.updateRole(oldAndNewRoles[0], oldAndNewRoles[1]);
    }

    @DataProvider(name = "dataProviderForListRolesWithPOSTSortingNotSupport")
    public Object[][] dataProviderForListRolesWithPOSTSortingNotSupport() {

        return new Object[][]{
                {"name", "ascending"},
                {null, "ascending"},
                {"", "ascending"},
                {"name", null},
                {"", ""},
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithPOSTSortingNotSupport")
    public void testListRolesWithPOSTSortingNotSupport(String sortBy, String sortOrder) {

        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(NotImplementedException.class, () -> roleManager.
                listRolesWithPost(getDummySearchRequest(null, 2, 2, sortBy, sortOrder)));
    }

    @Test
    public void testListRolesWithPOSTCountNullZero() throws NotImplementedException, BadRequestException,
            CharonException {

        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN2);
        List<Object> roles = roleManager.listRolesWithPost(getDummySearchRequest(null, 2, 0,
                null, null));
        assertEquals(roles.size(), 0);
    }

    @DataProvider(name = "dataProviderForListRolesWithPOSTInvalidLimit")
    public Object[][] dataProviderForListRolesWithPOSTInvalidLimit() {

        return new Object[][]{
                {"Expression", -2},
                {null, -5}
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithPOSTInvalidLimit")
    public void testListRolesWithPOSTInvalidLimit(String nodeType, Integer count)
            throws IdentityRoleManagementException {

        Node rootNode = generateNodeBasedOnNodeType(nodeType, "name");
        when(mockRoleManagementService.getRoles(anyInt(), anyInt(), anyString(), anyString(), anyString())).
                thenAnswer(invocationOnMock -> {
                    Integer countArg = invocationOnMock.getArgument(0);
                    if (countArg != null && countArg < 0) {
                        String errorMessage =
                                "Invalid limit requested. Limit value should be greater than or equal to zero. limit: "
                                        + count;
                        throw new IdentityRoleManagementClientException(INVALID_LIMIT.getCode(), errorMessage);
                    }
                    return null;
                });
        when(mockRoleManagementService.getRoles(anyString(), anyInt(), anyInt(), anyString(), anyString(), anyString()))
                .thenAnswer(invocationOnMock -> {
                    Integer countArg = invocationOnMock.getArgument(1);

                    if (countArg != null && countArg < 0) {
                        String errorMessage =
                                "Invalid limit requested. Limit value should be greater than or equal to zero. limit: "
                                        + count;
                        throw new IdentityRoleManagementClientException(INVALID_LIMIT.getCode(), errorMessage);
                    }
                    return null;
                });
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(CharonException.class, () -> roleManager.
                listRolesWithPost(getDummySearchRequest(rootNode, 2, count, null, null)));
    }

    @DataProvider(name = "dataProviderForListRolesWithPOSTInvalidOffset")
    public Object[][] dataProviderForListRolesWithPOSTInvalidOffset() {

        return new Object[][]{
                {"Expression", -1},
                {null, -2}
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithPOSTInvalidOffset")
    public void testListRolesWithPOSTInvalidOffset(String nodeType, Integer startIndex)
            throws IdentityRoleManagementException {

        Node rootNode = generateNodeBasedOnNodeType(nodeType, "name");
        when(mockRoleManagementService.getRoles(anyInt(), anyInt(), anyString(), anyString(), anyString())).
                thenAnswer(invocationOnMock -> {
                    Integer startIndexArg = invocationOnMock.getArgument(1);

                    if (startIndexArg != null && startIndexArg < 0) {
                        String errorMessage =
                                "Invalid limit requested. Limit value should be greater than or equal to zero. limit: "
                                        + startIndexArg;
                        throw new IdentityRoleManagementClientException(INVALID_LIMIT.getCode(), errorMessage);
                    }
                    return null;
                });
        when(mockRoleManagementService.getRoles(anyString(), anyInt(), anyInt(), anyString(), anyString(), anyString()))
                .thenAnswer(invocationOnMock -> {
                    Integer startIndexArg = invocationOnMock.getArgument(2);

                    if (startIndexArg != null && startIndexArg < 0) {
                        String errorMessage =
                                "Invalid limit requested. Limit value should be greater than or equal to zero. limit: "
                                        + startIndexArg;
                        throw new IdentityRoleManagementClientException(INVALID_LIMIT.getCode(), errorMessage);
                    }
                    return null;
                });
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(CharonException.class, () -> roleManager.
                listRolesWithPost(getDummySearchRequest(rootNode, startIndex, 2, null, null)));
    }

    @DataProvider(name = "dataProviderForListRolesWithPOSTUnExpectedServerError")
    public Object[][] dataProviderForListRolesWithPOSTUnExpectedServerError() {

        return new Object[][]{
                {"Expression", SAMPLE_INVALID_TENANT_DOMAIN, null},
                {null, SAMPLE_TENANT_DOMAIN2, "sql error"},
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithPOSTUnExpectedServerError")
    public void testListRolesWithPOSTUnExpectedServerError(String nodeType, String tenantDomain, String sError)
            throws IdentityRoleManagementException {

        Node rootNode = generateNodeBasedOnNodeType(nodeType, "name");
        System.out.println(nodeType);
        System.out.println(rootNode);

        when(mockRoleManagementService.getRoles(anyInt(), anyInt(), nullable(String.class), nullable(String.class), anyString())).
                thenThrow(unExpectedErrorThrower(tenantDomain, sError,
                        "Error while listing roles in tenantDomain: "));
        when(mockRoleManagementService.getRoles(anyString(), anyInt(), anyInt(), nullable(String.class),
                nullable(String.class), anyString())).thenThrow(unExpectedErrorThrower(tenantDomain, sError,
                "Error while listing roles in tenantDomain: "));
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, tenantDomain);
        assertThrows(CharonException.class, () -> roleManager.
                listRolesWithPost(getDummySearchRequest(rootNode, 2, 2, null, null)));
    }

    @Test
    public void testListRolesWithPOSTOperationNode() {

        Node rootNode = generateNodeBasedOnNodeType("Operation", "name");
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);

        assertThrows(NotImplementedException.class, () -> roleManager.
                listRolesWithPost(getDummySearchRequest(rootNode, 2, 2, null, null)));
    }

    @Test
    public void testListRolesWithPOSTInvalidNode() {

        Node rootNode = new MockNode();
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN2);

        assertThrows(CharonException.class, () -> roleManager.
                listRolesWithPost(getDummySearchRequest(rootNode, 2, 2, null, null)));
    }

    @Test
    public void testListRolesWithPOSTWIthBadRequest() {

        Node rootNode = generateNodeBasedOnNodeType("Expression", "name", "bad operation");
        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        assertThrows(BadRequestException.class, () -> roleManager.
                listRolesWithPost(getDummySearchRequest(rootNode, 2, 3, null, null)));
    }

    @DataProvider(name = "dataProviderForListRolesWithPOSTPositive")
    public Object[][] dataProviderForListRolesWithPOSTPositive() {

        return new Object[][]{
                {null, SCIMCommonConstants.CO},
                {"Expression", SCIMCommonConstants.EQ},
                {"Expression", SCIMCommonConstants.SW},
                {"Expression", SCIMCommonConstants.EW},
                {"Expression", SCIMCommonConstants.CO},
        };
    }

    @Test(dataProvider = "dataProviderForListRolesWithPOSTPositive")
    public void testListRolesWithPOSTPositive(String nodeType, String operation)
            throws CharonException, IdentityRoleManagementException, NotImplementedException, BadRequestException {

        Node rootNode = generateNodeBasedOnNodeType(nodeType, "name", operation);

        List<RoleBasicInfo> roleList = getDummyRoleBasicInfoList();

        when(mockRoleManagementService.getRoles(anyInt(), anyInt(), anyString(), anyString(), anyString())).
                thenAnswer(invocationOnMock -> roleList);
        when(mockRoleManagementService.getRoles(anyString(), anyInt(), anyInt(), anyString(),
                anyString(), anyString())).thenAnswer(invocationOnMock -> roleList);

        SCIMRoleManager roleManager = new SCIMRoleManager(mockRoleManagementService, SAMPLE_TENANT_DOMAIN);
        roleManager.listRolesWithPost(getDummySearchRequest(rootNode, 2, 3, null, null));
        assertTrue(true, "listRolesWIthPost run successfully");
    }

    private Role[] getOldAndNewRoleDummies(String roleId, String oldRoleName, String newRoleName)
            throws BadRequestException, CharonException {

        return getOldAndNewRoleDummies(roleId, oldRoleName, newRoleName, "");
    }

    private Role[] getOldAndNewRoleDummies(String roleId, String oldRoleName, String newRoleName,
                                           String roleSelectionType)
            throws BadRequestException, CharonException {

        User u1 = new User();
        u1.setUserName("username1");
        u1.setId("7646b885-4207-4ca0-bc65-5df82272b6d1");
        User u2 = new User();
        u2.setUserName("username2");
        u2.setId("7646b885-4207-4ca0-bc65-5df82272b6d2");
        User u3 = new User();
        u3.setUserName("username3");
        u3.setId("7646b885-4207-4ca0-bc65-5df82272b6d3");
        User u4 = new User();
        u4.setUserName("username4");
        u4.setId("7646b885-4207-4ca0-bc65-5df82272b6d4");
        User u5 = new User();
        u5.setUserName("username5");
        u5.setId("7646b885-4207-4ca0-bc65-5df82272b6d5");
        // Create groups.
        Group group1 = new Group();
        group1.setDisplayName("groupName1");
        group1.setId("26d3a726-9c00-4f4c-8a4e-f5e310138081");
        group1.setMember(u1);
        Group group2 = new Group();
        group2.setDisplayName("groupName2");
        group2.setId("26d3a726-9c00-4f4c-8a4e-f5e310138082");
        group2.setMember(u2);
        Group group3 = new Group();
        group3.setDisplayName("groupName3");
        group3.setId("26d3a726-9c00-4f4c-8a4e-f5e310138083");
        group3.setMember(u3);
        Group group4 = new Group();
        group4.setDisplayName("groupName4");
        group4.setId("26d3a726-9c00-4f4c-8a4e-f5e310138084");
        group4.setMember(u4);
        Group group5 = new Group();
        group5.setDisplayName("groupName5");
        group5.setId("26d3a726-9c00-4f4c-8a4e-f5e310138085");
        group5.setMember(u5);
        // Old role.
        Role oldRole = new Role();
        oldRole.setId(roleId);
        oldRole.setDisplayName(oldRoleName);

        // New role.
        Role newRole = new Role();
        newRole.setId(roleId);
        newRole.setDisplayName(newRoleName);

        switch (roleSelectionType) {
            case "NULL_NEW_PERMISSION":
                newRole.setPermissions(null);
                break;
            case "NULL_OLD_PERMISSION":
                oldRole.setPermissions(null);
                break;
            case "EMPTY_NEW_PERMISSION":
                oldRole.setPermissions(Arrays.asList("permission", "usermgt", "security", "configure"));
                newRole.setPermissions(Collections.emptyList());
                break;
            case "EMPTY_OLD_PERMISSION":
                oldRole.setPermissions(Collections.emptyList());
                newRole.setPermissions(Arrays.asList("permission", "usermgt", "security", "configure"));
                break;
            case "ALL_EMPTY_PERMISSION":
                oldRole.setPermissions(Collections.emptyList());
                newRole.setPermissions(Collections.emptyList());
                break;
            case "ALL_EQUAL_PERMISSION":
                oldRole.setPermissions(Arrays.asList("permission", "usermgt", "configure", "admin"));
                newRole.setPermissions(Arrays.asList("permission", "usermgt", "configure", "admin"));
                break;
            case "EMPTY_DELETED":
                oldRole.setUser(u1);
                oldRole.setUser(u2);
                oldRole.setUser(u4);
                newRole.setUser(u1);
                newRole.setUser(u2);
                newRole.setUser(u4);
                newRole.setUser(u5);
                oldRole.setGroup(group1);
                oldRole.setGroup(group2);
                oldRole.setGroup(group4);
                newRole.setGroup(group1);
                newRole.setGroup(group2);
                newRole.setGroup(group4);
                newRole.setGroup(group5);
                break;
            case "EMPTY_NEW":
                oldRole.setUser(u1);
                oldRole.setUser(u2);
                oldRole.setUser(u4);
                newRole.setUser(u1);
                newRole.setUser(u2);
                oldRole.setGroup(group1);
                oldRole.setGroup(group2);
                oldRole.setGroup(group4);
                newRole.setGroup(group1);
                newRole.setGroup(group2);
                break;
            case "EMPTY_BOTH":
                oldRole.setUser(u1);
                oldRole.setUser(u2);
                oldRole.setUser(u4);
                newRole.setUser(u1);
                newRole.setUser(u2);
                newRole.setUser(u4);
                oldRole.setGroup(group1);
                oldRole.setGroup(group2);
                oldRole.setGroup(group4);
                newRole.setGroup(group1);
                newRole.setGroup(group2);
                newRole.setGroup(group4);
                break;
            default:
                oldRole.setPermissions(Arrays.asList("permission", "usermgt", "security", "configure"));
                newRole.setPermissions(Arrays.asList("permission", "usermgt", "configure", "admin"));
                oldRole.setUser(u1);
                oldRole.setUser(u2);
                oldRole.setUser(u2);
                oldRole.setUser(u4);
                newRole.setUser(u1);
                newRole.setUser(u2);
                newRole.setUser(u4);
                newRole.setUser(u5);
                oldRole.setGroup(group1);
                oldRole.setGroup(group2);
                oldRole.setGroup(group3);
                oldRole.setGroup(group4);
                newRole.setGroup(group1);
                newRole.setGroup(group2);
                newRole.setGroup(group4);
                newRole.setGroup(group5);
                break;
        }
        return new Role[]{oldRole, newRole};
    }

    private Role getDummyRole(String roleId, String roleDisplayName) throws BadRequestException, CharonException {

        Role role = new Role();
        User user = new User();
        user.setUserName("username");
        role.setUser(user);
        role.setDisplayName(roleDisplayName);
        role.setId(roleId);
        role.setPermissions(Arrays.asList("permission", "usermgt"));
        return role;
    }

    private org.wso2.carbon.identity.role.mgt.core.Role getDummyIdentityRole(String roleId, String roleName,
                                                                             String domain, String tenantDomain) {

        org.wso2.carbon.identity.role.mgt.core.Role role = new org.wso2.carbon.identity.role.mgt.core.Role();
        role.setId(roleId);
        role.setPermissions(Arrays.asList("permission", "usermgt"));
        role.setName(roleName);
        role.setDomain(domain);
        role.setTenantDomain(tenantDomain);
        role.setUsers(Arrays.asList(new UserBasicInfo("7646b885-4207-4ca0-bc65-5df82272b6d1", "username1"),
                new UserBasicInfo("7646b885-4207-4ca0-bc65-5df82272b6d2", "username2")));
        GroupBasicInfo groupBasicInfo1 = new GroupBasicInfo();
        groupBasicInfo1.setName("groupName1");
        groupBasicInfo1.setId("26d3a726-9c00-4f4c-8a4e-f5e310138081");
        GroupBasicInfo groupBasicInfo2 = new GroupBasicInfo();
        groupBasicInfo2.setName("groupName2");
        groupBasicInfo2.setId("26d3a726-9c00-4f4c-8a4e-f5e310138082");
        role.setGroups(Arrays.asList(groupBasicInfo1, groupBasicInfo2));
        return role;
    }

    private org.wso2.carbon.identity.role.mgt.core.Role getDummyIdentityRole(String roleId, String roleName,
                                                                             String domain, String tenantDomain,
                                                                             boolean isEmptyLists) {

        if (isEmptyLists) {
            org.wso2.carbon.identity.role.mgt.core.Role role = new org.wso2.carbon.identity.role.mgt.core.Role();
            role.setId(roleId);
            role.setPermissions(Arrays.asList("permission", "usermgt"));
            role.setName(roleName);
            role.setDomain(domain);
            role.setTenantDomain(tenantDomain);
            return role;
        } else {
            return getDummyIdentityRole(roleId, roleName, domain, tenantDomain);
        }
    }

    private void assertScimRoleFull(Role scimRole, String roleId) {

        assertEquals(scimRole.getId(), roleId);
        if (!scimRole.getUsers().isEmpty()) {
            assertEquals(scimRole.getUsers().get(0), "7646b885-4207-4ca0-bc65-5df82272b6d1");
        }
        assertEquals(scimRole.getPermissions().get(0), "permission");
        if (!scimRole.getGroups().isEmpty()) {
            assertEquals(scimRole.getGroups().get(0), "26d3a726-9c00-4f4c-8a4e-f5e310138081");
        }
        assertEquals(scimRole.getLocation(), DUMMY_SCIM_URL);
    }

    private List<RoleBasicInfo> getDummyRoleBasicInfoList() {

        return Arrays.asList(new RoleBasicInfo("role1", SAMPLE_VALID_ROLE_NAME),
                new RoleBasicInfo("role2", SAMPLE_VALID_ROLE_NAME2),
                new RoleBasicInfo("role3", SAMPLE_SYSTEM_ROLE_NAME));
    }

    private Node generateNodeBasedOnNodeType(String nodeType, String attributes) {

        return generateNodeBasedOnNodeType(nodeType, attributes, SCIMCommonConstants.EQ);
    }

    private Node generateNodeBasedOnNodeType(String nodeType, String attributes, String operation) {

        Node rootNode = null;
        if (nodeType != null && nodeType.equals("Expression")) {
            rootNode = new ExpressionNode();
            ((ExpressionNode) rootNode).setOperation(operation);
            ((ExpressionNode) rootNode).setAttributeValue("attributeValue");
            ((ExpressionNode) rootNode).setValue(attributes);
        } else if (nodeType != null && nodeType.equals("Operation")) {
            rootNode = new OperationNode("operation");
        }
        return rootNode;
    }

    private Throwable unExpectedErrorThrower(String tenantDomainArg, String sError, String errorMessage) {

        if (sError != null) {
            return new IdentityRoleManagementServerException(UNEXPECTED_SERVER_ERROR.getCode(),
                    errorMessage + tenantDomainArg, new Error(sError));
        }
        if (tenantDomainArg.equals(SAMPLE_INVALID_TENANT_DOMAIN)) {
            return new IdentityRoleManagementServerException(UNEXPECTED_SERVER_ERROR.getCode(),
                    errorMessage + tenantDomainArg, new Error("invalid tenant domain"));
        }
        return null;
    }

    private Throwable unExpectedErrorThrower(String tenantDomainArg, String sError,
                                             String errorMessage, String roleIdArg) {

        if (tenantDomainArg.equals(SAMPLE_INVALID_TENANT_DOMAIN)) {
            return new IdentityRoleManagementServerException(UNEXPECTED_SERVER_ERROR.getCode(),
                    String.format(errorMessage, roleIdArg, tenantDomainArg), new Error("invalid tenantDomain"));
        }
        if (sError != null) {
            return new IdentityRoleManagementServerException(UNEXPECTED_SERVER_ERROR.getCode(),
                    String.format(errorMessage, roleIdArg, tenantDomainArg), new Error(sError));
        }
        return null;
    }

    private SearchRequest getDummySearchRequest(Node node, int startIndex, int count,
                                                String sortBy, String sortOrder) {

        SearchRequest searchRequest = new SearchRequest();
        searchRequest.setFilter(node);
        searchRequest.setStartIndex(startIndex);
        searchRequest.setCount(count);
        searchRequest.setSortBy(sortBy);
        searchRequest.setSortOder(sortOrder);
        return searchRequest;
    }

    private static class MockNode extends Node {

    }
}
