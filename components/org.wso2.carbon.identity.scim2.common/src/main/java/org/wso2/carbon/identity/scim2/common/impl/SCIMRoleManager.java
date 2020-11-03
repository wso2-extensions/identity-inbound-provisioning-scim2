/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.impl;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.role.mgt.core.GroupBasicInfo;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.mgt.core.RoleBasicInfo;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.mgt.core.UserBasicInfo;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.RoleManager;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.Role;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.utils.codeutils.ExpressionNode;
import org.wso2.charon3.core.utils.codeutils.Node;
import org.wso2.charon3.core.utils.codeutils.OperationNode;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
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
    private static final String FILTERING_DELIMITER = "*";

    public SCIMRoleManager(RoleManagementService roleManagementService, String tenantDomain) {

        this.roleManagementService = roleManagementService;
        this.tenantDomain = tenantDomain;
    }

    @Override
    public Role createRole(Role role) throws CharonException, ConflictException, BadRequestException {

        if (log.isDebugEnabled()) {
            log.debug("Creating role: " + role.getDisplayName());
        }
        try {
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
            org.wso2.carbon.identity.role.mgt.core.Role role = roleManagementService.getRole(roleID, tenantDomain);
            Role scimRole = new Role();
            scimRole.setId(role.getId());
            scimRole.setDisplayName(role.getName());
            String locationURI = SCIMCommonUtils.getSCIMRoleURL(role.getId());
            scimRole.setLocation(locationURI);
            scimRole.setPermissions(role.getPermissions());
            scimRole.setSchemas();

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
    public void deleteRole(String roleID) throws CharonException, NotFoundException {

        try {
            roleManagementService.deleteRole(roleID, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            if (StringUtils.equals(ROLE_NOT_FOUND.getCode(), e.getErrorCode())) {
                throw new NotFoundException(e.getMessage());
            }
            throw new CharonException(String.format("Error occurred while deleting the role: %s", roleID), e);
        }

    }

    @Override
    public List<Object> listRolesWithGET(Node rootNode, Integer startIndex, Integer count, String sortBy,
            String sortOrder) throws CharonException, NotImplementedException, BadRequestException {

        if (sortBy != null || sortOrder != null) {
            throw new NotImplementedException("Sorting is not supported.");
        } else if (count != null && count == 0) {
            return Collections.emptyList();
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
    private List<Object> filterRoles(Node node, Integer count, Integer startIndex, String sortBy, String sortOrder)
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
    private List<Object> filterRolesBySingleAttribute(ExpressionNode node, Integer count, Integer startIndex,
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

        List<Object> filteredRoles = new ArrayList<>();
        // 0th index is to store total number of results.
        filteredRoles.add(0);
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
        List<Object> scimRoles = getScimRolesList(roles);

        // Set total number of results to 0th index.
        filteredRoles.set(0, scimRoles.size());
        // Add the results list.
        filteredRoles.addAll(scimRoles);

        return filteredRoles;
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
    private List<Object> listRoles(Integer count, Integer startIndex, String sortBy, String sortOrder)
            throws CharonException, BadRequestException {

        List<Object> rolesList = new ArrayList<>();
        try {
            // 0th index is to store total number of results.
            rolesList.add(0);
            List<RoleBasicInfo> roles = roleManagementService
                    .getRoles(count, startIndex, sortBy, sortOrder, tenantDomain);
            List<Object> scimRoles = getScimRolesList(roles);

            // Set total number of results to 0th index.
            rolesList.set(0, scimRoles.size());
            // Add the results list.
            rolesList.addAll(scimRoles);
        } catch (IdentityRoleManagementException e) {
            throw new CharonException("Error occurred while listing roles.", e);
        }
        return rolesList;
    }

    private List<Object> getScimRolesList(List<RoleBasicInfo> roles) throws BadRequestException, CharonException {

        List<Object> scimRoles = new ArrayList<>();
        for (RoleBasicInfo roleBasicInfo : roles) {
            Role scimRole = new Role();
            scimRole.setDisplayName(roleBasicInfo.getName());
            scimRole.setId(roleBasicInfo.getId());
            scimRole.setLocation(SCIMCommonUtils.getSCIMRoleURL(roleBasicInfo.getId()));
            scimRoles.add(scimRole);
        }
        return scimRoles;
    }

    @Override
    public Role updateRole(Role oldRole, Role newRole)
            throws BadRequestException, CharonException, ConflictException, NotFoundException {

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
            throws CharonException, ConflictException, NotFoundException {

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
                if (StringUtils.equals(INVALID_REQUEST.getCode(), e.getErrorCode())) {
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
                if (StringUtils.equals(INVALID_REQUEST.getCode(), e.getErrorCode())) {
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

        List<String> newRolePermissions = newRole.getPermissions();

        // Update the role with specified permissions.
        if (isNotEmpty(newRolePermissions)) {
            try {
                roleManagementService.setPermissionsForRole(oldRole.getId(), newRolePermissions, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (StringUtils.equals(INVALID_REQUEST.getCode(), e.getErrorCode())) {
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

    @Override
    public List<Object> listRolesWithPost(SearchRequest searchRequest)
            throws NotImplementedException, BadRequestException, CharonException {

        return listRolesWithGET(searchRequest.getFilter(), searchRequest.getStartIndex(), searchRequest.getCount(),
                searchRequest.getSortBy(), searchRequest.getSortOder());
    }
}
