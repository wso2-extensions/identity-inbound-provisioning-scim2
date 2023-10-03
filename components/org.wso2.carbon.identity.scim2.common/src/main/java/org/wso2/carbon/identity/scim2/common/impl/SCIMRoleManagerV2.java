/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.role.v2.mgt.core.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.Permission;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleBasicInfo;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.ForbiddenException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.RoleV2Manager;
import org.wso2.charon3.core.objects.RoleV2;
import org.wso2.charon3.core.objects.plainobjects.RolesV2GetResponse;
import org.wso2.charon3.core.utils.codeutils.Node;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.INVALID_REQUEST;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.ROLE_ALREADY_EXISTS;

/**
 * Implementation of the {@link RoleV2Manager} interface to manage RoleResourceV2.
 */
public class SCIMRoleManagerV2 implements RoleV2Manager {

    private static final Log LOG = LogFactory.getLog(SCIMRoleManagerV2.class);
    // TODO change to new Role manager Service.
    private RoleManagementService roleManagementService;
    private String tenantDomain;
    // TODO check whether can we change this in V2.
    private Set<String> systemRoles;


    // TODO change to new Role manager Service.
    public SCIMRoleManagerV2(RoleManagementService roleManagementService, String tenantDomain) {

        this.roleManagementService = roleManagementService;
        this.tenantDomain = tenantDomain;
        // Get the read only system roles set.
        this.systemRoles = roleManagementService.getSystemRoles();
    }

    public RoleV2 createRole(RoleV2 role)
            throws CharonException, ConflictException, NotImplementedException, BadRequestException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating role: " + role.getDisplayName());
        }
        try {
            // Check if the role already exists.
            if (roleManagementService.isExistingRole(role.getId(), tenantDomain)) {
                String error = "Role with name: " + role.getDisplayName() + " already exists in the tenantDomain: "
                        + tenantDomain;
                throw new ConflictException(error);
            }
            List<String> permissionValues = role.getPermissionValues();
            List<Permission> permissionList = new ArrayList<>();
            if (permissionValues != null) {
                for (String permissionValue : permissionValues) {
                    Permission permission = new Permission(permissionValue);
                    permissionList.add(permission);
                }
            }
            RoleBasicInfo roleBasicInfo =
                    roleManagementService.addRole(role.getDisplayName(), role.getUsers(), role.getGroups(),
                            permissionList, role.getAudienceType(), role.getAudienceValue(), tenantDomain);

            RoleV2 createdRole = new RoleV2();
            createdRole.setId(roleBasicInfo.getId());
            String locationURI = SCIMCommonUtils.getSCIMRoleV2URL(roleBasicInfo.getId());
            createdRole.setLocation(locationURI);
            createdRole.setDisplayName(roleBasicInfo.getName());
            createdRole.setSchemas();
            createdRole.setAudience(roleBasicInfo.getAudienceId(), roleBasicInfo.getAudienceName(),
                    roleBasicInfo.getAudience());

            return createdRole;
        } catch (IdentityRoleManagementException e) {
            if (StringUtils.equals(ROLE_ALREADY_EXISTS.getCode(), e.getErrorCode())) {
                throw new ConflictException(e.getMessage());
            } else if (StringUtils.equals(INVALID_REQUEST.getCode(), e.getErrorCode())) {
                throw new BadRequestException(e.getMessage());
            }
            throw new CharonException(
                    String.format("Error occurred while adding a new role: %s", role.getDisplayName()), e);
        }
    }

    public RoleV2 getRole(String roleID, Map<String, Boolean> requiredAttributes)
            throws BadRequestException, CharonException, NotFoundException {

        return null;
    }

    public void deleteRole(String roleID) throws CharonException, NotFoundException, BadRequestException {

    }

    public RolesV2GetResponse listRolesWithGET(Node rootNode, Integer startIndex, Integer count, String sortBy,
                                               String sortOrder)
            throws CharonException, NotImplementedException, BadRequestException {

        return null;
    }

    @Override
    public RolesV2GetResponse listRolesWithPost(SearchRequest searchRequest)
            throws NotImplementedException, BadRequestException, CharonException {

        return null;
    }

    public RoleV2 updateRole(RoleV2 oldRole, RoleV2 newRole)
            throws BadRequestException, CharonException, ConflictException, NotFoundException {

        return null;
    }

    public RoleV2 patchRole(String roleId, Map<String, List<PatchOperation>> patchOperations)
            throws BadRequestException, CharonException, ConflictException, NotFoundException, ForbiddenException {

        return null;
    }
}
