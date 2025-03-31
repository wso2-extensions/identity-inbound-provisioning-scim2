/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.ForbiddenException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.objects.RoleV2;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;

/**
 * Contains the unit test cases for SCIMRoleManagerV2.
 */
public class SCIMRoleManagerV2Test {

    private static final String SAMPLE_TENANT_DOMAIN = "carbon.super";
    private static final String SAMPLE_VALID_ROLE_ID = "595f5508-f286-446a-86c4-5071e07b98fc";
    private static final String SAMPLE_GROUP_NAME = "testGroup";
    private static final String SAMPLE_VALID_ROLE_NAME = "admin";
    private static final int BAD_REQUEST = 400;

    @Mock
    private RoleManagementService roleManagementService;

    private SCIMRoleManagerV2 scimRoleManagerV2;

    private MockedStatic<IdentityUtil> identityUtil;

    @BeforeClass
    public void setUpClass() {

        initMocks(this);
    }

    @BeforeMethod
    public void setUpMethod() {

        identityUtil = mockStatic(IdentityUtil.class);
        scimRoleManagerV2 = new SCIMRoleManagerV2(roleManagementService, SAMPLE_TENANT_DOMAIN);
    }

    @AfterMethod
    public void tearDown() {
        identityUtil.close();
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

    @Test(expectedExceptions = BadRequestException.class)
    public void testDoUpdateRoleNameException() throws Exception {

        RoleV2 oldRole = org.mockito.Mockito.mock(RoleV2.class);
        RoleV2 newRole = org.mockito.Mockito.mock(RoleV2.class);

        when(oldRole.getDisplayName()).thenReturn("OldName");
        when(newRole.getDisplayName()).thenReturn("NewName");
        when(oldRole.getId()).thenReturn("roleId");

        Mockito.mockStatic(OrganizationManagementUtil.class);
        when(OrganizationManagementUtil.isOrganization(anyString())).thenReturn(false);

        IdentityRoleManagementException identityException =
                new IdentityRoleManagementException("RMA-60001", "Role not found");
        doThrow(identityException)
                .when(roleManagementService)
                .updateRoleName("roleId", "NewName", "carbon.super");

        scimRoleManagerV2.updateRole(oldRole, newRole);
    }
}
