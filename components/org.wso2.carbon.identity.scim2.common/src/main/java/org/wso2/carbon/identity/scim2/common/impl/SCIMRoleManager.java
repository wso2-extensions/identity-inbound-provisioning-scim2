/*
 * Copyright (c) 2020-2024, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.role.mgt.core.GroupBasicInfo;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.mgt.core.RoleBasicInfo;
import org.wso2.carbon.identity.role.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.mgt.core.UserBasicInfo;
import org.wso2.carbon.identity.role.mgt.core.util.UserIDResolver;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.ForbiddenException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.RoleManager;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.Role;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.objects.plainobjects.RolesGetResponse;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.ExpressionNode;
import org.wso2.charon3.core.utils.codeutils.Node;
import org.wso2.charon3.core.utils.codeutils.OperationNode;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.OPERATION_FORBIDDEN;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.INVALID_REQUEST;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.ROLE_ALREADY_EXISTS;
import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.ROLE_NOT_FOUND;

/**
 * Implementation of the {@link RoleManager} interface.
 */
public class SCIMRoleManager implements RoleManager {

    private static final Log log = LogFactory.getLog(SCIMRoleManager.class);
    private RoleManagementService roleManagementService;
    private String tenantDomain;
    private Set<String> systemRoles;
    private static final String FILTERING_DELIMITER = "*";
    private UserIDResolver userIDResolver = new UserIDResolver();

    public SCIMRoleManager(RoleManagementService roleManagementService, String tenantDomain) {

        this.roleManagementService = roleManagementService;
        this.tenantDomain = tenantDomain;
        // Get the read only system roles set.
        this.systemRoles = roleManagementService.getSystemRoles();
    }

    @Override
    public Role createRole(Role role) throws CharonException, ConflictException,
            BadRequestException, ForbiddenException {

        List<String> authorizedScopes = (List<String>) IdentityUtil.threadLocalProperties.get().get(
                SCIMCommonConstants.AUTHORIZED_SCOPES);

        if (authorizedScopes == null ||
                !(authorizedScopes.contains("internal_role_mgt_create") ||
                        authorizedScopes.contains("internal_bulk_resource_create") ||
                        authorizedScopes.contains("internal_bulk_role_create"))) {
            throw new ForbiddenException("Operation is not permitted. You do not have permissions to" +
                    " make this request..");
        }

        if (log.isDebugEnabled()) {
            log.debug("Creating role: " + role.getDisplayName());
        }
        try {
            if (!isRoleModificationAllowedForTenant(tenantDomain)) {
                throw new BadRequestException("Role creation is not allowed for organizations.",
                        ResponseCodeConstants.INVALID_VALUE);
            }

            // Check if the role already exists.
            if (roleManagementService.isExistingRole(role.getId(), tenantDomain)) {
                String error = "Role with name: " + role.getDisplayName() + " already exists in the tenantDomain: "
                        + tenantDomain;
                throw new ConflictException(error);
            }
            RoleBasicInfo roleBasicInfo = roleManagementService
                    .addRole(role.getDisplayName(), role.getUsers(), role.getGroups(), role.getPermissions(),
                            tenantDomain);

            Role createdRole = new Role();
            createdRole.setId(roleBasicInfo.getId());
            String locationURI = SCIMCommonUtils.getSCIMRoleURL(roleBasicInfo.getId());
            createdRole.setLocation(locationURI);
            createdRole.setDisplayName(roleBasicInfo.getName());
            createdRole.setSchemas();

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

    @Override
    public Role getRole(String roleID, Map<String, Boolean> requiredAttributes)
            throws BadRequestException, CharonException, NotFoundException {

        try {
            org.wso2.carbon.identity.role.mgt.core.Role role;
            if (isUsersAttributeRequired(requiredAttributes)) {
                role = roleManagementService.getRole(roleID, tenantDomain);
            } else  {
                role = roleManagementService.getRoleWithoutUsers(roleID, tenantDomain);
            }
            Role scimRole = new Role();
            scimRole.setId(role.getId());
            scimRole.setDisplayName(role.getName());
            String locationURI = SCIMCommonUtils.getSCIMRoleURL(role.getId());
            scimRole.setLocation(locationURI);
            scimRole.setPermissions(role.getPermissions());
            scimRole.setSchemas();
            if (systemRoles.contains(role.getName())) {
                scimRole.setSystemRole(true);
            }

            if (CollectionUtils.isNotEmpty(role.getUsers())) {
                for (UserBasicInfo userInfo : role.getUsers()) {
                    String userLocationURI = SCIMCommonUtils.getSCIMUserURL(userInfo.getId());
                    User user = new User();
                    user.setUserName(userInfo.getName());
                    user.setId(userInfo.getId());
                    user.setLocation(userLocationURI);
                    scimRole.setUser(user);
                }
            }
            if (CollectionUtils.isNotEmpty(role.getGroups())) {
                for (GroupBasicInfo groupInfo : role.getGroups()) {
                    String groupLocationURI = SCIMCommonUtils.getSCIMGroupURL(groupInfo.getId());
                    Group group = new Group();
                    group.setDisplayName(groupInfo.getName());
                    group.setId(groupInfo.getId());
                    group.setLocation(groupLocationURI);
                    scimRole.setGroup(group);
                }
            }
            return scimRole;

        } catch (IdentityRoleManagementException e) {
            if (StringUtils.equals(ROLE_NOT_FOUND.getCode(), e.getErrorCode())) {
                throw new NotFoundException(e.getMessage());
            }
            throw new CharonException(String.format("Error occurred while getting the role: %s", roleID), e);
        }
    }

    @Override
    public void deleteRole(String roleID) throws CharonException, NotFoundException,
            BadRequestException, ForbiddenException{

        List<String> authorizedScopes = (List<String>) IdentityUtil.threadLocalProperties.get().get(
                SCIMCommonConstants.AUTHORIZED_SCOPES);

        if (authorizedScopes == null ||
                !(authorizedScopes.contains("internal_role_mgt_delete") ||
                        authorizedScopes.contains("internal_bulk_resource_create") ||
                        authorizedScopes.contains("internal_bulk_role_delete"))) {
            throw new ForbiddenException("Operation is not permitted. You do not have permissions to" +
                    " make this request..");
        }

        try {
            roleManagementService.deleteRole(roleID, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            if (StringUtils.equals(ROLE_NOT_FOUND.getCode(), e.getErrorCode())) {
                throw new NotFoundException(e.getMessage());
            } else if (StringUtils.equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                throw new BadRequestException(e.getMessage());
            }
            throw new CharonException(String.format("Error occurred while deleting the role: %s", roleID), e);
        }

    }

    @Override
    public RolesGetResponse listRolesWithGET(Node rootNode, Integer startIndex, Integer count, String sortBy,
                            String sortOrder) throws CharonException, NotImplementedException, BadRequestException {

        if (sortBy != null || sortOrder != null) {
            throw new NotImplementedException("Sorting is not supported.");
        } else if (count != null && count == 0) {
            return new RolesGetResponse(0, Collections.emptyList());
        } else if (rootNode != null) {
            return filterRoles(rootNode, count, startIndex, sortBy, sortOrder);
        } else {
            return listRoles(count, startIndex, sortBy, sortOrder);
        }
    }

    /**
     * Filter users using multi-attribute filters or single attribute filters with pagination.
     *
     * @param node       Filter condition tree.
     * @param startIndex Starting index of the count.
     * @param count      Number of required results (count).
     * @param sortBy     SortBy.
     * @param sortOrder  Sort order.
     * @return Detailed user list.
     * @throws CharonException Error filtering the roles.
     */
    private RolesGetResponse filterRoles(Node node, Integer count, Integer startIndex, String sortBy, String sortOrder)
            throws CharonException, NotImplementedException, BadRequestException {

        // Handle single attribute search.
        if (node instanceof ExpressionNode) {
            return filterRolesBySingleAttribute((ExpressionNode) node, count, startIndex, sortBy, sortOrder);
        } else if (node instanceof OperationNode) {
            String error = "Complex filters are not supported yet";
            throw new NotImplementedException(error);
        } else {
            throw new CharonException("Unknown operation. Not either an expression node or an operation node.");
        }
    }

    /**
     * Get the list of roles based on the filter.
     *
     * @param node       Expression node.
     * @param startIndex Starting index.
     * @param count      Number of results required.
     * @param sortBy     SortBy.
     * @param sortOrder  Sorting order.
     * @return Filtered roles.
     * @throws CharonException Error filtering the roles.
     */
    private RolesGetResponse filterRolesBySingleAttribute(ExpressionNode node, Integer count, Integer startIndex,
            String sortBy, String sortOrder) throws CharonException, BadRequestException {

        String attributeName = node.getAttributeValue();
        String filterOperation = node.getOperation();
        String attributeValue = node.getValue();
        if (log.isDebugEnabled()) {
            log.debug(
                    "Filtering roles with filter: " + attributeName + " + " + filterOperation + " + " + attributeValue);
        }
        // Check whether the filter operation is supported for filtering in roles.
        if (isFilteringNotSupported(filterOperation)) {
            String errorMessage = "Filter operation: " + filterOperation + " is not supported for role filtering.";
            throw new BadRequestException(errorMessage);
        }

        String searchFilter = getSearchFilter(filterOperation, attributeValue);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Filtering roleNames from search filter: %s", searchFilter));
        }
        List<RoleBasicInfo> roles;
        try {
            roles = roleManagementService.getRoles(searchFilter, count, startIndex, sortBy, sortOrder, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while listing roles based on the search filter: %s", searchFilter),
                    e);
        }
        List<Role> scimRoles = getScimRolesList(roles);
        return new RolesGetResponse(scimRoles.size(), scimRoles);
    }

    /**
     * Check whether the filtering is supported.
     *
     * @param filterOperation Operator to be used for filtering.
     * @return boolean to check whether operator is supported.
     */
    private boolean isFilteringNotSupported(String filterOperation) {

        return !filterOperation.equalsIgnoreCase(SCIMCommonConstants.EQ) && !filterOperation
                .equalsIgnoreCase(SCIMCommonConstants.CO) && !filterOperation.equalsIgnoreCase(SCIMCommonConstants.SW)
                && !filterOperation.equalsIgnoreCase(SCIMCommonConstants.EW);
    }

    /**
     * Get the search filter.
     *
     * @param filterOperation Operator value.
     * @param attributeValue  Search value.
     * @return Search filter.
     */
    private String getSearchFilter(String filterOperation, String attributeValue) {

        String searchAttribute = null;
        if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.CO)) {
            searchAttribute =
                    SCIMRoleManager.FILTERING_DELIMITER + attributeValue + SCIMRoleManager.FILTERING_DELIMITER;
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.SW)) {
            searchAttribute = attributeValue + SCIMRoleManager.FILTERING_DELIMITER;
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EW)) {
            searchAttribute = SCIMRoleManager.FILTERING_DELIMITER + attributeValue;
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EQ)) {
            searchAttribute = attributeValue;
        }
        return searchAttribute;
    }

    /**
     * Method to list roles.
     *
     * @param startIndex Starting index of the results.
     * @param count      Results count value.
     * @param sortBy     SortBy.
     * @param sortOrder  Sorting order.
     * @return List of roles.
     * @throws CharonException Error while listing users
     */
    private RolesGetResponse listRoles(Integer count, Integer startIndex, String sortBy, String sortOrder)
            throws CharonException, BadRequestException {

        List<Role> rolesList = new ArrayList<>();
        int rolesCount;
        try {
            List<RoleBasicInfo> roles = roleManagementService
                    .getRoles(count, startIndex, sortBy, sortOrder, tenantDomain);
            List<Role> scimRoles = getScimRolesList(roles);

            rolesCount = roleManagementService.getRolesCount(tenantDomain);
            // Set total number of results to 0th index.
            if (rolesCount == 0) {
                rolesCount = scimRoles.size();
            }
            // Add the results list.
            rolesList.addAll(scimRoles);
        } catch (IdentityRoleManagementException e) {
            throw new CharonException("Error occurred while listing roles.", e);
        }
        return new RolesGetResponse(rolesCount, rolesList);
    }

    private List<Role> getScimRolesList(List<RoleBasicInfo> roles) throws BadRequestException, CharonException {

        List<Role> scimRoles = new ArrayList<>();
        for (RoleBasicInfo roleBasicInfo : roles) {
            Role scimRole = new Role();
            scimRole.setDisplayName(roleBasicInfo.getName());
            scimRole.setId(roleBasicInfo.getId());
            scimRole.setLocation(SCIMCommonUtils.getSCIMRoleURL(roleBasicInfo.getId()));
            if (systemRoles.contains(roleBasicInfo.getName())) {
                scimRole.setSystemRole(true);
            }
            scimRoles.add(scimRole);
        }
        return scimRoles;
    }

    @Override
    public Role updateRole(Role oldRole, Role newRole)
            throws BadRequestException, CharonException, ConflictException, NotFoundException, ForbiddenException {

        List<String> authorizedScopes = (List<String>) IdentityUtil.threadLocalProperties.get().get(
                SCIMCommonConstants.AUTHORIZED_SCOPES);

        if (authorizedScopes == null ||
                !(authorizedScopes.contains("internal_role_mgt_update") ||
                        authorizedScopes.contains("internal_bulk_resource_create") ||
                        authorizedScopes.contains("internal_bulk_role_update"))) {
            throw new ForbiddenException("Operation is not permitted. You do not have permissions to" +
                    " make this request..");
        }

        doUpdateRoleName(oldRole, newRole);
        doUpdateUsers(oldRole, newRole);
        doUpdateGroups(oldRole, newRole);
        doUpdatePermissions(oldRole, newRole);

        Role role = new Role();
        role.setDisplayName(newRole.getDisplayName());
        role.setId(oldRole.getId());
        role.setSchemas();
        role.setLocation(oldRole.getLocation());
        return role;
    }

    private void doUpdateRoleName(Role oldRole, Role newRole)
            throws CharonException, ConflictException, NotFoundException, BadRequestException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Updating name of role %s to %s.", oldRole.getDisplayName(),
                    newRole.getDisplayName()));
        }

        // Update name if it is changed.
        String oldRoleDisplayName = oldRole.getDisplayName();
        String newRoleDisplayName = newRole.getDisplayName();

        if (!StringUtils.equals(oldRoleDisplayName, newRoleDisplayName)) {
            // Update role name.
            try {
                roleManagementService.updateRoleName(oldRole.getId(), newRoleDisplayName, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (StringUtils.equals(ROLE_NOT_FOUND.getCode(), e.getErrorCode())) {
                    throw new NotFoundException(e.getMessage());
                } else if (StringUtils.equals(ROLE_ALREADY_EXISTS.getCode(), e.getErrorCode())) {
                    throw new ConflictException(e.getMessage());
                } else if (StringUtils.equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating role name from: %s to %s", oldRoleDisplayName,
                                newRoleDisplayName), e);
            }
        }
    }

    private void doUpdateUsers(Role oldRole, Role newRole) throws CharonException, BadRequestException {

        if (log.isDebugEnabled()) {
            log.debug("Updating users of role: " + oldRole.getDisplayName());
        }

        Set<String> userIDsInOldRole = new HashSet<>(oldRole.getUsers());
        Set<String> userIDsInNewRole = new HashSet<>(newRole.getUsers());

        // Check for deleted users.
        Set<String> deletedUserIDList = getRemovedIDList(userIDsInOldRole, userIDsInNewRole);

        // Check for added users.
        Set<String> newUserIDList = getAddedIDList(userIDsInOldRole, userIDsInNewRole);

        // Update the role with added users and deleted users.
        if (isNotEmpty(newUserIDList) || isNotEmpty(deletedUserIDList)) {
            try {
                roleManagementService.updateUserListOfRole(oldRole.getId(), new ArrayList<>(newUserIDList),
                        new ArrayList<>(deletedUserIDList), tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (StringUtils.equals(INVALID_REQUEST.getCode(), e.getErrorCode()) || StringUtils
                        .equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating users in the role: %s", newRole.getDisplayName()),
                        e);
            }
        }
    }

    private void doUpdateGroups(Role oldRole, Role newRole) throws CharonException, BadRequestException {

        if (log.isDebugEnabled()) {
            log.debug("Updating groups of role: " + oldRole.getDisplayName());
        }

        Set<String> groupIDsInOldRole = new HashSet<>(oldRole.getGroups());
        Set<String> groupIDsInNewRole = new HashSet<>(newRole.getGroups());

        // Check for deleted groups.
        Set<String> deleteGroupIDList = getRemovedIDList(groupIDsInOldRole, groupIDsInNewRole);

        // Check for added groups.
        Set<String> newGroupIDList = getAddedIDList(groupIDsInOldRole, groupIDsInNewRole);

        // Update the role with added users and deleted users.
        if (isNotEmpty(newGroupIDList) || isNotEmpty(deleteGroupIDList)) {
            try {
                roleManagementService.updateGroupListOfRole(oldRole.getId(), new ArrayList<>(newGroupIDList),
                        new ArrayList<>(deleteGroupIDList), tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (StringUtils.equals(INVALID_REQUEST.getCode(), e.getErrorCode()) || StringUtils
                        .equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating groups in the role: %s", newRole.getDisplayName()),
                        e);
            }
        }
    }

    private void doUpdatePermissions(Role oldRole, Role newRole) throws BadRequestException, CharonException {

        if (log.isDebugEnabled()) {
            log.debug("Updating permissions of role: " + oldRole.getDisplayName());
        }

        List<String> oldRolePermissions = oldRole.getPermissions();
        List<String> newRolePermissions = newRole.getPermissions();

        // Update the role with specified permissions.
        if (hasPermissionsChanged(oldRolePermissions, newRolePermissions)) {
            if (log.isDebugEnabled()) {
                log.debug("Permissions have changed. Updating permissions of role: " + oldRole.getDisplayName());
            }
            try {
                roleManagementService.setPermissionsForRole(oldRole.getId(), newRolePermissions, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (StringUtils.equals(INVALID_REQUEST.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                } else if (StringUtils.equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating permissions for role: %s",
                                newRole.getDisplayName()), e);
            }
        }
    }

    private Set<String> getAddedIDList(Set<String> oldIDs, Set<String> newIDs) {

        Set<String> addedIDs = new HashSet<>(newIDs);
        addedIDs.removeAll(oldIDs);
        return addedIDs;
    }

    private Set<String> getRemovedIDList(Set<String> oldIDs, Set<String> newIDs) {

        Set<String> removedIDs = new HashSet<>(oldIDs);
        removedIDs.removeAll(newIDs);
        return removedIDs;
    }

    private boolean hasPermissionsChanged(List<String> oldRolePermissions, List<String> newRolePermissions) {

        if (newRolePermissions == null) {
            return false;
        }

        if (oldRolePermissions == null) {
            return true;
        }

        if (CollectionUtils.isEmpty(oldRolePermissions) && CollectionUtils.isEmpty(newRolePermissions)) {
            return false;
        }

        return !CollectionUtils.isEqualCollection(oldRolePermissions, newRolePermissions);
    }

    @Override
    public RolesGetResponse listRolesWithPost(SearchRequest searchRequest)
            throws NotImplementedException, BadRequestException, CharonException {

        return listRolesWithGET(searchRequest.getFilter(), searchRequest.getStartIndex(), searchRequest.getCount(),
                searchRequest.getSortBy(), searchRequest.getSortOder());
    }

    @Override
    public Role patchRole(String roleId, Map<String, List<PatchOperation>> patchOperations)
            throws BadRequestException, CharonException, ConflictException, NotFoundException, ForbiddenException {

        List<String> authorizedScopes = (List<String>) IdentityUtil.threadLocalProperties.get().get(
                SCIMCommonConstants.AUTHORIZED_SCOPES);

        if (authorizedScopes == null ||
                !(authorizedScopes.contains("internal_role_mgt_update") ||
                        authorizedScopes.contains("internal_bulk_resource_create") ||
                        authorizedScopes.contains("internal_bulk_role_update"))) {
            throw new ForbiddenException("Operation is not permitted. You do not have permissions to" +
                    " make this request..");
        }

        String currentRoleName = getCurrentRoleName(roleId, tenantDomain);

        if (log.isDebugEnabled()) {
            log.debug("Updating Role: " + currentRoleName);
        }

        List<PatchOperation> displayNameOperations = new ArrayList<>();
        List<PatchOperation> memberOperations = new ArrayList<>();
        List<PatchOperation> groupOperations = new ArrayList<>();
        List<PatchOperation> permissionOperations = new ArrayList<>();

        if (MapUtils.isEmpty(patchOperations)) {
            throw new CharonException("Patch operation can't be null or empty");
        }
        for (List<PatchOperation> patchOperationList : patchOperations.values()) {
            for (PatchOperation patchOperation : patchOperationList) {
                switch (patchOperation.getAttributeName()) {
                    case (SCIMConstants.RoleSchemaConstants.DISPLAY_NAME):
                        displayNameOperations.add(patchOperation);
                        break;
                    case (SCIMConstants.RoleSchemaConstants.USERS):
                        memberOperations.add(patchOperation);
                        break;
                    case (SCIMConstants.RoleSchemaConstants.GROUPS):
                        groupOperations.add(patchOperation);
                        break;
                    case (SCIMConstants.RoleSchemaConstants.PERMISSIONS):
                        permissionOperations.add(patchOperation);
                        break;
                }
            }
        }


        if (CollectionUtils.isNotEmpty(displayNameOperations)) {
            String newRoleName = (String) displayNameOperations.get(displayNameOperations.size() - 1).getValues();
            updateRoleName(roleId, currentRoleName, newRoleName);
        }

        if (CollectionUtils.isNotEmpty(permissionOperations)) {
            updatePermissions(roleId, permissionOperations);
        }

        if (CollectionUtils.isNotEmpty(groupOperations)) {
            updateGroups(roleId, groupOperations);
        }

        if (CollectionUtils.isNotEmpty(memberOperations)) {
            updateUsers(roleId, currentRoleName, memberOperations);
        }

        HashMap<String, Boolean> requiredAttributes = new HashMap<>();
        requiredAttributes.put(SCIMConstants.RoleSchemaConstants.DISPLAY_NAME_URI, true);
        return getRole(roleId, requiredAttributes);
    }

    private void updateUsers(String roleId, String currentRoleName, List<PatchOperation> memberOperations)
            throws BadRequestException, CharonException, ForbiddenException {

        Collections.sort(memberOperations);
        Set<String> addedUsers = new HashSet<>();
        Set<String> deletedUsers = new HashSet<>();
        Set<Object> newlyAddedUsersIds = new HashSet<>();

        for (PatchOperation memberOperation : memberOperations) {
            if (memberOperation.getValues() instanceof Map) {
                Map<String, String> memberObject = (Map<String, String>) memberOperation.getValues();
                prepareAddedRemovedUserLists(addedUsers, deletedUsers, newlyAddedUsersIds,
                        memberOperation, memberObject, currentRoleName);
            } else if (memberOperation.getValues() instanceof List) {
                List<Map<String, String>> memberOperationValues =
                        (List<Map<String, String>>) memberOperation.getValues();
                for (Map<String, String> memberObject : memberOperationValues) {
                    prepareAddedRemovedUserLists(addedUsers, deletedUsers, newlyAddedUsersIds,
                            memberOperation, memberObject, currentRoleName);
                }
            }
        }

        if (isNotEmpty(addedUsers) || isNotEmpty(deletedUsers)) {
            doUpdateUsers(addedUsers, deletedUsers, newlyAddedUsersIds, roleId);
        }
    }

    private void updateGroups(String roleId, List<PatchOperation> groupOperations)
            throws CharonException, BadRequestException {

        try {
            Collections.sort(groupOperations);
            Set<String> addedGroupIds = new HashSet<>();
            Set<String> deletedGroupIds = new HashSet<>();
            Set<String> replaceGroupsIds = new HashSet<>();

            List<GroupBasicInfo> groupListOfRole = roleManagementService.getGroupListOfRole(roleId, tenantDomain);

            for (PatchOperation groupOperation : groupOperations) {
                if (groupOperation.getValues() instanceof Map) {
                    Map<String, String> groupObject = (Map<String, String>) groupOperation.getValues();
                    prepareAddedRemovedGroupLists(addedGroupIds, deletedGroupIds, replaceGroupsIds,
                            groupOperation, groupObject, groupListOfRole);
                } else if (groupOperation.getValues() instanceof List) {
                    List<Map<String, String>> memberOperationValues =
                            (List<Map<String, String>>) groupOperation.getValues();
                    for (Map<String, String> groupObject : memberOperationValues) {
                        prepareAddedRemovedGroupLists(addedGroupIds, deletedGroupIds, replaceGroupsIds,
                                groupOperation, groupObject, groupListOfRole);
                    }
                }
                prepareReplacedGroupLists(groupListOfRole, addedGroupIds, deletedGroupIds, replaceGroupsIds);
            }

            if (isNotEmpty(addedGroupIds) || isNotEmpty(deletedGroupIds)) {
                doUpdateGroups(roleId, addedGroupIds, deletedGroupIds);
            }
        } catch (IdentityRoleManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while retrieving the group list for role: %s", roleId), e);
        }
    }

    private String getCurrentRoleName(String roleId, String tenantDomain) throws CharonException, BadRequestException {

        String currentRoleName;
        try {
            currentRoleName = roleManagementService.getRoleNameByRoleId(roleId, tenantDomain);
            if (isInternalRole(currentRoleName)) {
                currentRoleName = addInternalDomain(currentRoleName);
            }
        } catch (IdentityRoleManagementException e) {
            if ((ROLE_NOT_FOUND.getCode()).equals(e.getErrorCode())) {
                throw new BadRequestException(e.getMessage());
            }
            throw new CharonException(String.format("Error occurred while getting the role name by " +
                    "the role id: %s", roleId), e);
        }
        return currentRoleName;
    }

    private void doUpdateUsers(Set<String> newUserList, Set<String> deletedUserList, Set<Object> newlyAddedMemberIds,
                               String roleId) throws CharonException, BadRequestException, ForbiddenException {

        // Update the role with added users and deleted users.
        List<String> newUserIDList = getUserIDList(new ArrayList<>(newUserList), tenantDomain);
        List<String> deletedUserIDList = getUserIDList(new ArrayList<>(deletedUserList), tenantDomain);

        if (isNotEmpty(newUserList) && !(newlyAddedMemberIds.size() == 1 && newlyAddedMemberIds.contains(null))) {
            validateUserIds(newUserIDList, newlyAddedMemberIds);
        }

        if (isNotEmpty(newUserIDList) || isNotEmpty(deletedUserIDList)) {
            try {
                roleManagementService.updateUserListOfRole(roleId, new ArrayList<>(newUserIDList),
                        new ArrayList<>(deletedUserIDList), tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (INVALID_REQUEST.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                if (OPERATION_FORBIDDEN.getCode().equals(e.getErrorCode())) {
                    throw new ForbiddenException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating users in the role: %s", roleId), e);
            }
        }
    }

    private void updateRoleName(String roleId, String oldRoleDisplayName, String newRoleDisplayName)
            throws CharonException, ConflictException, NotFoundException {

        if (!StringUtils.equals(oldRoleDisplayName, newRoleDisplayName)) {
            try {
                roleManagementService.updateRoleName(roleId, newRoleDisplayName, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if ((ROLE_NOT_FOUND.getCode()).equals(e.getErrorCode())) {
                    throw new NotFoundException(e.getMessage());
                } else if ((ROLE_ALREADY_EXISTS.getCode()).equals(e.getErrorCode())) {
                    throw new ConflictException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating role name from: %s to %s", oldRoleDisplayName,
                                newRoleDisplayName), e);
            }
        }
    }

    private void updatePermissions(String roleId, List<PatchOperation> permissionOperations)
            throws BadRequestException, CharonException {

        List<String> oldRolePermissions;
        List<String> newRolePermissions = getNewRolePermissions(permissionOperations);
        try {
            oldRolePermissions =
                    roleManagementService.getPermissionListOfRole(roleId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while retrieving the permissions for role: %s", roleId), e);
        }

        // Update the role with specified permissions.
        if (hasPermissionsChanged(oldRolePermissions, newRolePermissions)) {
            if (log.isDebugEnabled()) {
                log.debug("Permissions have changed. Updating permissions of role: " + roleId);
            }
            try {
                roleManagementService.setPermissionsForRole(roleId, newRolePermissions, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (INVALID_REQUEST.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating permissions for role: %s", roleId), e);
            }
        }
    }

    private void prepareAddedRemovedGroupLists(Set<String> addedGroupsIds, Set<String> removedGroupsIds,
                                               Set<String> replacedGroupsIds, PatchOperation groupOperation,
                                               Map<String, String> groupObject, List<GroupBasicInfo> groupListOfRole)
            throws BadRequestException {

        String value = groupObject.get(SCIMConstants.CommonSchemaConstants.VALUE);

        if (StringUtils.isBlank(value)) {
            throw new BadRequestException("Group id is required to update group of the role.",
                    ResponseCodeConstants.INVALID_VALUE);
        }

        switch (groupOperation.getOperation()) {
            case (SCIMConstants.OperationalConstants.ADD):
                removedGroupsIds.remove(value);
                if (!isGroupExist(value, groupListOfRole)) {
                    addedGroupsIds.add(value);
                }
                break;
            case (SCIMConstants.OperationalConstants.REMOVE):
                addedGroupsIds.remove(value);
                removedGroupsIds.add(value);
                break;
            case (SCIMConstants.OperationalConstants.REPLACE):
                replacedGroupsIds.add(value);
                break;
        }
    }

    private void prepareAddedRemovedUserLists(Set<String> addedMembers, Set<String> removedMembers,
                                              Set<Object> newlyAddedMemberIds, PatchOperation memberOperation,
                                              Map<String, String> memberObject, String currentRoleName)
            throws BadRequestException, CharonException {

        try {
            AbstractUserStoreManager userStoreManager =
                    (AbstractUserStoreManager) PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserRealm()
                            .getUserStoreManager();
            if (StringUtils.isEmpty(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY))) {
                List<org.wso2.carbon.user.core.common.User> userListWithID =
                        userStoreManager.getUserListWithID(SCIMConstants.CommonSchemaConstants.ID_URI,
                                memberObject.get(SCIMConstants.CommonSchemaConstants.VALUE), null);
                if (isNotEmpty(userListWithID)) {
                    memberObject.put(SCIMConstants.RoleSchemaConstants.DISPLAY,
                            UserCoreUtil.addDomainToName(userListWithID.get(0).getUsername(),
                                    userListWithID.get(0).getUserStoreDomain()));
                    memberOperation.setValues(memberObject);
                }
            }

            if (memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY) == null) {
                throw new BadRequestException("User can't be resolved from the given user Id.");
            }

            List<String> roleList = Arrays.asList(userStoreManager.
                    getRoleListOfUser(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY)));

            if (StringUtils.equals(memberOperation.getOperation(), SCIMConstants.OperationalConstants.ADD) &&
                    !roleList.contains(currentRoleName)) {
                removedMembers.remove(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY));
                addedMembers.add(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY));
                newlyAddedMemberIds.add(memberObject.get(SCIMConstants.CommonSchemaConstants.VALUE));
            } else if (StringUtils.equals(memberOperation.getOperation(),
                    SCIMConstants.OperationalConstants.REMOVE)) {
                addedMembers.remove(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY));
                removedMembers.add(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY));
            }
        } catch (UserStoreException e) {
            if("Invalid Domain Name".equals(e.getMessage())) {
                throw new BadRequestException("Invalid userstore name", ResponseCodeConstants.INVALID_VALUE);
            }
            throw new CharonException("Error occurred while retrieving the user list for role.");
        }
    }

    private void prepareReplacedGroupLists(List<GroupBasicInfo> groupListOfRole, Set<String> addedGroupIds,
                                           Set<String> removedGroupsIds, Set<String> replacedGroupsIds) {

        if (replacedGroupsIds.isEmpty()) {
            return;
        }

        if (!groupListOfRole.isEmpty()) {
            for (GroupBasicInfo groupBasicInfo : groupListOfRole) {
                if (!replacedGroupsIds.contains(groupBasicInfo.getId())) {
                    removedGroupsIds.add(groupBasicInfo.getId());
                } else {
                    replacedGroupsIds.remove(groupBasicInfo.getId());
                }
            }
        }
        addedGroupIds.addAll(replacedGroupsIds);
    }

    private void doUpdateGroups(String roleId, Set<String> newGroupIDList, Set<String> deleteGroupIDList)
            throws CharonException, BadRequestException {

        // Update the role with added users and deleted users.
        if (isNotEmpty(newGroupIDList) || isNotEmpty(deleteGroupIDList)) {
            try {
                roleManagementService.updateGroupListOfRole(roleId, new ArrayList<>(newGroupIDList),
                        new ArrayList<>(deleteGroupIDList), tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (INVALID_REQUEST.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating groups in the role: %s", roleId), e);
            }
        }
    }

    private List<String> getUserIDList(List<String> userList, String tenantDomain) throws CharonException,
            BadRequestException {

        List<String> userIDList = new ArrayList<>();
        for (String user : userList) {
            try {
                userIDList.add(getUserIDByName(user, tenantDomain));
            } catch (IdentityRoleManagementException e) {
                if (RoleConstants.Error.INVALID_REQUEST.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage(), ResponseCodeConstants.INVALID_VALUE);
                }
                throw new CharonException(String.format("Error occurred while getting the user id " +
                        "of the user: %s", user), e);
            }
        }
        return userIDList;
    }

    private void validateUserIds(List<String> newUserIDList, Set<Object> newlyAddedMemberIds) throws
            BadRequestException {

        for (Object addedUserId : newlyAddedMemberIds) {
            if (!newUserIDList.contains(addedUserId.toString())) {
                throw new BadRequestException(String.format("Provided SCIM user Id: %s doesn't match with the "
                        + "userID obtained from user-store for the provided username.", addedUserId.toString()),
                        ResponseCodeConstants.INVALID_VALUE);
            }
        }
    }

    private boolean isGroupExist(String groupId, List<GroupBasicInfo> groupListOfRole) {

        for (GroupBasicInfo group : groupListOfRole) {
            if (StringUtils.equals(groupId, group.getId())) {
                return true;
            }
        }
        return false;
    }

    private String getUserIDByName(String name, String tenantDomain) throws IdentityRoleManagementException {

        return userIDResolver.getIDByName(name, tenantDomain);
    }

    private boolean isInternalRole(String roleName) {

        return StringUtils.isNotBlank(IdentityUtil.extractDomainFromName(roleName));
    }

    private String addInternalDomain(String roleName) {

        if (StringUtils.isNotBlank(IdentityUtil.extractDomainFromName(roleName))) {
            return UserCoreConstants.INTERNAL_DOMAIN + UserCoreConstants.DOMAIN_SEPARATOR + roleName;
        }
        return roleName;
    }

    private List<String> getNewRolePermissions(List<PatchOperation> permissionOperations) {

        for (PatchOperation permissionOperation : permissionOperations) {
            if ((SCIMConstants.OperationalConstants.REPLACE).equals(permissionOperation.getOperation())) {
                if (permissionOperation.getValues() instanceof List) {
                    return (List<String>) permissionOperation.getValues();
                }
            }
        }
        return Collections.emptyList();
    }

    private boolean isUsersAttributeRequired(Map<String, Boolean> requiredAttributes) {

        if (requiredAttributes == null || MapUtils.isEmpty(requiredAttributes)) {
            return true;
        }
        for (String attribute : requiredAttributes.keySet()) {
            if (attribute.startsWith(SCIMConstants.RoleSchemaConstants.USERS_URI)) {
                return true;
            }
        }
        return false;
    }

    private boolean isRoleModificationAllowedForTenant(String tenantDomain) throws CharonException {

        try {
            return !OrganizationManagementUtil.isOrganization(tenantDomain);
        } catch (OrganizationManagementException e) {
            throw new CharonException("Error while checking whether the tenant is an organization.", e);
        }
    }
}
