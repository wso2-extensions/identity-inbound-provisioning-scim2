/*
 * Copyright (c) 2023-2024, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.IdPGroup;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.AssociatedApplication;
import org.wso2.carbon.identity.role.v2.mgt.core.model.GroupBasicInfo;
import org.wso2.carbon.identity.role.v2.mgt.core.model.IdpGroup;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Permission;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Role;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleProperty;
import org.wso2.carbon.identity.role.v2.mgt.core.model.UserBasicInfo;
import org.wso2.carbon.identity.role.v2.mgt.core.util.RoleManagementUtils;
import org.wso2.carbon.identity.role.v2.mgt.core.util.UserIDResolver;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.ForbiddenException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.RoleV2Manager;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.RoleV2;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.objects.plainobjects.MultiValuedComplexType;
import org.wso2.charon3.core.objects.plainobjects.RolesV2GetResponse;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.ExpressionNode;
import org.wso2.charon3.core.utils.codeutils.Node;
import org.wso2.charon3.core.utils.codeutils.OperationNode;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.APPLICATION;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.INVALID_AUDIENCE;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.INVALID_PERMISSION;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.INVALID_REQUEST;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.OPERATION_FORBIDDEN;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.ROLE_ALREADY_EXISTS;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.ROLE_NOT_FOUND;

/**
 * Implementation of the {@link RoleV2Manager} interface to manage RoleResourceV2.
 */
public class SCIMRoleManagerV2 implements RoleV2Manager {

    private static final Log LOG = LogFactory.getLog(SCIMRoleManagerV2.class);
    private static final String ROLE_NAME_FILTER_ATTRIBUTE = "name";
    private static final String ROLE_AUDIENCE_TYPE_FILTER_ATTRIBUTE = "audience";
    private static final String ROLE_AUDIENCE_ID_FILTER_ATTRIBUTE = "audienceId";
    private final String USERS = "users";
    private final String GROUPS = "groups";
    private final String PERMISSIONS = "permissions";
    private final String ASSOCIATED_APPLICATIONS = "associatedApplications";
    private final String PROPERTIES = "properties";
    private RoleManagementService roleManagementService;
    private String tenantDomain;
    private Set<String> systemRoles;
    private UserIDResolver userIDResolver = new UserIDResolver();

    public SCIMRoleManagerV2(RoleManagementService roleManagementService, String tenantDomain) {

        this.roleManagementService = roleManagementService;
        this.tenantDomain = tenantDomain;
        // Get the read only system roles set.
        this.systemRoles = roleManagementService.getSystemRoles();
    }

    public RoleV2 createRole(RoleV2 role)
            throws CharonException, ConflictException, NotImplementedException, BadRequestException {

        try {
            // Check if the role already exists.
            if (roleManagementService.isExistingRole(role.getId(), tenantDomain)) {
                String error = "Role with id: " + role.getId() + " already exists in the tenantDomain: "
                        + tenantDomain;
                throw new ConflictException(error);
            }

            if (OrganizationManagementUtil.isOrganization(tenantDomain) && APPLICATION.equals(role.
                    getAudienceType())) {
                ServiceProvider app = ApplicationManagementService.getInstance().getApplicationByResourceId(
                        role.getAudienceValue(), tenantDomain);
                if (app == null) {
                    throw new BadRequestException("Invalid audience value. Audience value should be valid " +
                            "application ID");
                }

                if (app.getSpProperties() != null && Arrays.stream(app.getSpProperties())
                        .anyMatch(property -> ApplicationConstants.IS_FRAGMENT_APP.equals(property.getName())
                                && Boolean.parseBoolean(property.getValue()))) {
                    throw new BadRequestException("Role creation for shared applications is not allowed at " +
                            "organization level.");
                }
            }
            List<String> permissionValues = role.getPermissionValues();
            List<Permission> permissionList = new ArrayList<>();
            if (permissionValues != null) {
                for (String permissionValue : permissionValues) {
                    Permission permission = new Permission(permissionValue);
                    permissionList.add(permission);
                }
            }
            String audienceType = role.getAudienceType();
            String audienceValue = role.getAudienceValue();
            if (LOG.isDebugEnabled()) {
                if (StringUtils.isNotBlank(audienceType) && StringUtils.isNotBlank(audienceValue)) {
                    LOG.debug("Creating role: " + role.getDisplayName() + " for " + audienceType + " with id: " +
                            audienceValue + " audience.");
                } else {
                    LOG.debug("Creating role: " + role.getDisplayName() + " for organization.");
                }
            }

            List<String> groupIds = role.getGroups();
            // Get valid IdP groups from the given group IDs.
            List<IdPGroup> idpGroups = SCIMCommonComponentHolder.getIdpManagerService().getValidIdPGroupsByIdPGroupIds(
                    groupIds, tenantDomain);
            List<IdpGroup> idpGroupList = idpGroups.stream()
                    .map(this::convertToIdpGroup)
                    .collect(Collectors.toList());
            List<String> validIdpGroupIds = idpGroupList.stream()
                    .map(IdpGroup::getGroupId)
                    .collect(Collectors.toList());
            // Exclude the valid Idp groups from the given group IDs for role creation.
            List<String> localGroupIds = groupIds.stream()
                    .filter(groupId -> !validIdpGroupIds.contains(groupId))
                    .collect(Collectors.toList());
            RoleBasicInfo roleBasicInfo =
                    roleManagementService.addRole(role.getDisplayName(), role.getUsers(), localGroupIds,
                            permissionList, audienceType, role.getAudienceValue(), tenantDomain);
            if (isNotEmpty(idpGroupList)) {
                roleManagementService.updateIdpGroupListOfRole(roleBasicInfo.getId(), idpGroupList, new ArrayList<>(),
                        tenantDomain);
            }
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
            } else if (INVALID_AUDIENCE.getCode().equals(e.getErrorCode()) ||
                    INVALID_PERMISSION.getCode().equals(e.getErrorCode())) {
                throw new BadRequestException(e.getMessage(), ResponseCodeConstants.INVALID_VALUE);
            }
            throw new CharonException(
                    String.format("Error occurred while adding a new role: %s", role.getDisplayName()), e);
        } catch (IdentityProviderManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while retrieving IdP groups for role: %s", role.getDisplayName()),
                    e);
        } catch (IdentityApplicationManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while retrieving application relevant for role: %s audience.",
                            role.getDisplayName()), e);
        } catch (OrganizationManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while checking the organization status of the tenant: %s",
                            tenantDomain), e);
        }
    }

    public RoleV2 getRole(String roleID, Map<String, Boolean> requiredAttributes)
            throws BadRequestException, CharonException, NotFoundException {

        try {
            Role role;
            if (isUsersAttributeRequired(requiredAttributes)) {
                role = roleManagementService.getRole(roleID, tenantDomain);
            } else {
                role = roleManagementService.getRoleWithoutUsers(roleID, tenantDomain);
            }
            RoleV2 scimRole = new RoleV2();
            scimRole.setId(role.getId());
            scimRole.setDisplayName(role.getName());
            String locationURI = SCIMCommonUtils.getSCIMRoleV2URL(role.getId());
            scimRole.setLocation(locationURI);
            scimRole.setSchemas();
            scimRole.setAudience(role.getAudienceId(), role.getAudienceName(), role.getAudience());
            if (systemRoles.contains(role.getName())) {
                scimRole.setSystemRole(true);
            }
            List<MultiValuedComplexType> roleProperties =
                    convertRolePropertiesToMultiValuedComplexType(role.getRoleProperties());
            scimRole.setRoleProperties(roleProperties);
            // Set permissions.
            List<MultiValuedComplexType> permissions =
                    convertPermissionsToMultiValuedComplexType(role.getPermissions());
            scimRole.setPermissions(permissions);

            // Set role's assigned users.
            List<UserBasicInfo> assignedUsers = role.getUsers();
            if (assignedUsers != null) {
                for (UserBasicInfo userInfo : assignedUsers) {
                    userInfo.getId();
                    String userLocationURI = SCIMCommonUtils.getSCIMUserURL(userInfo.getId());
                    User user = new User();
                    user.setUserName(userInfo.getName());
                    user.setId(userInfo.getId());
                    user.setLocation(userLocationURI);
                    scimRole.setUser(user);
                }
            }

            // Set role's assigned userstore groups.
            List<GroupBasicInfo> assignedUserstoreGroups = role.getGroups();
            if (assignedUserstoreGroups != null) {
                for (GroupBasicInfo groupInfo : assignedUserstoreGroups) {
                    String groupId = groupInfo.getId();
                    String groupLocationURI = SCIMCommonUtils.getSCIMGroupURL(groupId);
                    Group group = new Group();
                    group.setDisplayName(groupInfo.getName());
                    group.setId(groupId);
                    group.setLocation(groupLocationURI);
                    scimRole.setGroup(group);
                }
            }

            // Set role's assigned idp groups.
            List<IdpGroup> assignedIdpGroups = role.getIdpGroups();
            if (assignedIdpGroups != null) {
                for (IdpGroup idpGroup : assignedIdpGroups) {
                    String idpGroupId = idpGroup.getGroupId();
                    String idpGroupLocationURI = SCIMCommonUtils.getIdpGroupURL(idpGroup.getIdpId(), idpGroupId);
                    Group group = new Group();
                    group.setDisplayName(idpGroup.getGroupName());
                    group.setId(idpGroupId);
                    group.setLocation(idpGroupLocationURI);
                    scimRole.setGroup(group);
                }
            }

            // Set associated applications.
            List<MultiValuedComplexType> associatedApps =
                    convertAssociatedAppsToMultivaluedComplexType(role.getAssociatedApplications());
            if (CollectionUtils.isNotEmpty(associatedApps)) {
                scimRole.setAssociatedApplications(associatedApps);
            }
            return scimRole;
        } catch (IdentityRoleManagementException e) {
            if (StringUtils.equals(ROLE_NOT_FOUND.getCode(), e.getErrorCode())) {
                throw new NotFoundException(e.getMessage());
            }
            throw new CharonException(String.format("Error occurred while getting the role: %s", roleID), e);
        }
    }

    private List<MultiValuedComplexType> convertAssociatedAppsToMultivaluedComplexType(
            List<AssociatedApplication> associatedApplications) {

        List<MultiValuedComplexType> associatedApplicationsList = new ArrayList<>();
        if (associatedApplications != null) {
            for (AssociatedApplication associatedApplication : associatedApplications) {
                String appId = associatedApplication.getId();
                String appName = associatedApplication.getName();
                MultiValuedComplexType applicationComplexObject = new MultiValuedComplexType();
                applicationComplexObject.setValue(appId);
                applicationComplexObject.setDisplay(appName);
                applicationComplexObject.setReference(SCIMCommonUtils.getApplicationRefURL(appId));
                associatedApplicationsList.add(applicationComplexObject);
            }
        }
        return associatedApplicationsList;
    }

    private List<MultiValuedComplexType> convertPermissionsToMultiValuedComplexType(List<Permission> permissions) {

        List<MultiValuedComplexType> permissionValues = new ArrayList<>();
        if (permissions != null) {
            for (Permission permission : permissions) {
                MultiValuedComplexType permissionComplexObject = new MultiValuedComplexType();
                permissionComplexObject.setValue(permission.getName());
                permissionComplexObject.setDisplay(permission.getDisplayName());
                permissionComplexObject.setReference(
                        SCIMCommonUtils.getPermissionRefURL(permission.getApiId().get(), permission.getName()));
                permissionValues.add(permissionComplexObject);
            }
        }
        return permissionValues;
    }

    private List<MultiValuedComplexType> convertRolePropertiesToMultiValuedComplexType(List<RoleProperty> roleProperties) {

        List<MultiValuedComplexType> rolePropertyValues = new ArrayList<>();
        if (roleProperties != null) {
            for (RoleProperty roleProperty : roleProperties) {
                MultiValuedComplexType rolePropertyComplexObject = new MultiValuedComplexType();
                rolePropertyComplexObject.setValue(roleProperty.getValue());
                rolePropertyComplexObject.setDisplay(roleProperty.getName());
                rolePropertyValues.add(rolePropertyComplexObject);
            }
        }
        return rolePropertyValues;
    }

    public void deleteRole(String roleID) throws CharonException, NotFoundException, BadRequestException {

        try {
            if (isSharedRole(roleID)) {
                throw new BadRequestException("Shared role deletion is not allowed.",
                        ResponseCodeConstants.INVALID_VALUE);
            }
            roleManagementService.deleteRole(roleID, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            if (StringUtils.equals(ROLE_NOT_FOUND.getCode(), e.getErrorCode())) {
                throw new NotFoundException(e.getMessage());
            } else if (StringUtils.equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                throw new BadRequestException(e.getMessage());
            } else if (INVALID_REQUEST.getCode().equals(e.getErrorCode())) {
                throw new BadRequestException(e.getMessage(), ResponseCodeConstants.INVALID_VALUE);
            }
            throw new CharonException(String.format("Error occurred while deleting the role: %s", roleID), e);
        }
    }

    public RolesV2GetResponse listRolesWithGET(Node rootNode, Integer startIndex, Integer count, String sortBy,
                                               String sortOrder, List<String> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {

        if (sortBy != null || sortOrder != null) {
            throw new NotImplementedException("Sorting is not supported.");
        } else if (count != null && count == 0) {
            return new RolesV2GetResponse(0, Collections.emptyList());
        } else if (rootNode != null) {
            return filterRoles(rootNode, count, startIndex, null, null, requiredAttributes);
        } else {
            return listRoles(count, startIndex, null, null, requiredAttributes);
        }
    }

    @Override
    public RolesV2GetResponse listRolesWithPost(SearchRequest searchRequest, List<String> requiredAttributes)
            throws NotImplementedException, BadRequestException, CharonException {

        return listRolesWithGET(searchRequest.getFilter(), searchRequest.getStartIndex(), searchRequest.getCount(),
                searchRequest.getSortBy(), searchRequest.getSortOder(), requiredAttributes);
    }

    @Override
    public RoleV2 updateRole(RoleV2 oldRole, RoleV2 newRole)
            throws BadRequestException, CharonException, ConflictException, NotFoundException {

        doUpdateRoleName(oldRole, newRole);
        doUpdateUsers(oldRole, newRole);
        doUpdateGroups(oldRole, newRole);
        doUpdatePermissions(oldRole, newRole);

        RoleV2 role = new RoleV2();
        role.setDisplayName(newRole.getDisplayName());
        role.setId(oldRole.getId());
        role.setSchemas();
        role.setLocation(oldRole.getLocation());
        role.setAudience(oldRole.getAudienceValue(), oldRole.getAudienceDisplayName(), oldRole.getAudienceType());
        return role;
    }

    @Override
    public RoleV2 patchRole(String roleId, Map<String, List<PatchOperation>> patchOperations)
            throws BadRequestException, CharonException, ConflictException, NotFoundException, ForbiddenException {

        String currentRoleName = getCurrentRoleName(roleId, tenantDomain);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Updating Role: " + roleId);
        }

        List<PatchOperation> displayNameOperations = new ArrayList<>();
        List<PatchOperation> memberOperations = new ArrayList<>();
        List<PatchOperation> groupOperations = new ArrayList<>();
        List<PatchOperation> permissionOperations = new ArrayList<>();

        if (MapUtils.isEmpty(patchOperations)) {
            throw new CharonException("Patch operation can't be null or empty.");
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
            if (isSharedRole(roleId)) {
                throw new BadRequestException("Role name modification is not allowed for shared roles.",
                        ResponseCodeConstants.INVALID_VALUE);
            }
            String newRoleName = (String) displayNameOperations.get(displayNameOperations.size() - 1).getValues();
            updateRoleName(roleId, currentRoleName, newRoleName);
        }
        if (CollectionUtils.isNotEmpty(permissionOperations)) {
            if (isSharedRole(roleId)) {
                throw new BadRequestException("Role permission modification is not allowed for shared roles.",
                        ResponseCodeConstants.INVALID_VALUE);
            }
            updatePermissions(roleId, permissionOperations);
        }
        if (CollectionUtils.isNotEmpty(groupOperations)) {
            updateGroups(roleId, groupOperations);
        }
        if (CollectionUtils.isNotEmpty(memberOperations)) {
            updateUsers(roleId, memberOperations);
        }

        HashMap<String, Boolean> requiredAttributes = new HashMap<>();
        requiredAttributes.put(SCIMConstants.RoleSchemaConstants.DISPLAY_NAME_URI, true);
        return getRole(roleId, requiredAttributes);
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
    private RolesV2GetResponse filterRoles(Node node, Integer count, Integer startIndex, String sortBy,
                                           String sortOrder, List<String> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {

        if (node instanceof ExpressionNode || node instanceof OperationNode) {
            return filterRolesByAttributes(node, count, startIndex, sortBy, sortOrder, requiredAttributes);
        }
        throw new CharonException("Unknown operation. Not either an expression node or an operation node.");
    }

    /**
     * Get the list of roles based on the filter.
     *
     * @param node       Filter node.
     * @param startIndex Starting index.
     * @param count      Number of results required.
     * @param sortBy     SortBy.
     * @param sortOrder  Sorting order.
     * @return Filtered roles.
     * @throws CharonException Error filtering the roles.
     */
    private RolesV2GetResponse filterRolesByAttributes(Node node, Integer count, Integer startIndex, String sortBy,
                                                       String sortOrder, List<String> requiredAttributes)
            throws CharonException, BadRequestException {

        String searchFilter = buildSearchFilter(node);
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Filtering roles from search filter: %s", searchFilter));
        }
        List<Role> roles;
        int roleCount;
        List<RoleV2> scimRoles;
        try {
            roles = roleManagementService.getRoles(searchFilter, count, startIndex, sortBy, sortOrder, tenantDomain,
                    requiredAttributes);
            scimRoles = getScimRolesList(roles, requiredAttributes);
            roleCount = roleManagementService.getRolesCount(searchFilter, tenantDomain);
            if (roleCount == 0) {
                roleCount = scimRoles.size();
            }
        } catch (IdentityRoleManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while listing roles based on the search filter: %s", searchFilter),
                    e);
        }
        return new RolesV2GetResponse(roleCount, scimRoles);
    }

    private String buildSearchFilter(Node node) throws BadRequestException {

        if (node instanceof ExpressionNode) {
            ExpressionNode expressionNode = (ExpressionNode) node;
            return createFilter(expressionNode);
        } else if (node instanceof OperationNode) {
            OperationNode operationNode = (OperationNode) node;
            String leftFilter = buildSearchFilter(operationNode.getLeftNode());
            String rightFilter = buildSearchFilter(operationNode.getRightNode());
            return combineFilters(operationNode, leftFilter, rightFilter);
        }
        throw new BadRequestException("Unknown operation.");
    }

    private String createFilter(ExpressionNode expressionNode) throws BadRequestException {

        String attributeName = expressionNode.getAttributeValue();
        String filterOperation = expressionNode.getOperation();
        String attributeValue = expressionNode.getValue();

        // Check whether the filter operation is supported for filtering in roles.
        if (isFilteringNotSupported(filterOperation)) {
            String errorMessage = "Filter operation: " + filterOperation + " is not supported for role filtering.";
            throw new BadRequestException(errorMessage);
        }
        return getSearchFilter(attributeName, filterOperation, attributeValue);
    }

    private String combineFilters(OperationNode operationNode, String leftFilter, String rightFilter) throws BadRequestException {

        String operator = operationNode.getOperation();
        if (SCIMConstants.OperationalConstants.OR.equalsIgnoreCase(operator)) {
            String errorMessage = "Filter operator: " + operator + " is not supported for role filtering.";
            throw new BadRequestException(errorMessage);
        }
        return String.format("%s %s %s", leftFilter, operator, rightFilter);
    }

    /**
     * Method to list roles.
     *
     * @param count      Results count value.
     * @param startIndex Starting index of the results.
     * @param sortBy     SortBy.
     * @param sortOrder  Sorting order.
     * @return List of roles matching to the criteria.
     * @throws CharonException Error while listing users.
     */
    private RolesV2GetResponse listRoles(Integer count, Integer startIndex, String sortBy, String sortOrder,
                                         List<String> requiredAttributes)
            throws CharonException, BadRequestException {

        List<RoleV2> rolesList = new ArrayList<>();
        int rolesCount;
        try {
            List<Role> roles = roleManagementService.getRoles(count, startIndex, sortBy, sortOrder, tenantDomain,
                    requiredAttributes);
            List<RoleV2> scimRoles = getScimRolesList(roles, requiredAttributes);
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
        return new RolesV2GetResponse(rolesCount, rolesList);
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
                && !filterOperation.equalsIgnoreCase(SCIMCommonConstants.EW)
                && !filterOperation.equalsIgnoreCase(SCIMCommonConstants.NE);
    }

    /**
     * Get the search filter.
     *
     * @param attributeName   Attribute name.
     * @param filterOperation Operator value.
     * @param attributeValue  Search value.
     * @return Search filter.
     * @throws BadRequestException Error in building the search filter.
     */
    private String getSearchFilter(String attributeName, String filterOperation, String attributeValue)
            throws BadRequestException {

        String searchFilter;
        switch (attributeName) {
            case SCIMConstants.RoleSchemaConstants.DISPLAY_NAME_URI:
                searchFilter = ROLE_NAME_FILTER_ATTRIBUTE + " " + filterOperation + " " + attributeValue;
                break;
            case SCIMConstants.RoleSchemaConstants.AUDIENCE_VALUE_URI:
                searchFilter = ROLE_AUDIENCE_ID_FILTER_ATTRIBUTE + " " + filterOperation + " " + attributeValue;
                break;
            case SCIMConstants.RoleSchemaConstants.AUDIENCE_TYPE_URI:
                searchFilter = ROLE_AUDIENCE_TYPE_FILTER_ATTRIBUTE + " " + filterOperation + " " + attributeValue;
                break;
            default:
                String errorMessage = "Filtering based on attribute: " + attributeName + " is not supported.";
                throw new BadRequestException(errorMessage);
        }
        return searchFilter;
    }

    private List<RoleV2> getScimRolesList(List<Role> roles, List<String> requiredAttributes)
            throws BadRequestException, CharonException {

        List<RoleV2> scimRoles = new ArrayList<>();
        for (Role role : roles) {
            RoleV2 scimRole = new RoleV2();
            scimRole.setDisplayName(role.getName());
            scimRole.setId(role.getId());
            scimRole.setSchemas();
            scimRole.setLocation(SCIMCommonUtils.getSCIMRoleV2URL(role.getId()));
            scimRole.setAudience(role.getAudienceId(), role.getAudienceName(),
                    role.getAudience());
            if (systemRoles.contains(role.getName())) {
                scimRole.setSystemRole(true);
            }
            if (requiredAttributes != null) {
                if (requiredAttributes.contains(USERS)) {
                    // Set role's assigned users.
                    List<UserBasicInfo> assignedUsers = role.getUsers();
                    if (assignedUsers != null) {
                        for (UserBasicInfo userInfo : assignedUsers) {
                            userInfo.getId();
                            String userLocationURI = SCIMCommonUtils.getSCIMUserURL(userInfo.getId());
                            User user = new User();
                            user.setUserName(userInfo.getName());
                            user.setId(userInfo.getId());
                            user.setLocation(userLocationURI);
                            scimRole.setUser(user);
                        }
                    }
                }
                if (requiredAttributes.contains(GROUPS)) {
                    // Set role's assigned userstore groups.
                    List<GroupBasicInfo> assignedUserstoreGroups = role.getGroups();
                    if (assignedUserstoreGroups != null) {
                        for (GroupBasicInfo groupInfo : assignedUserstoreGroups) {
                            String groupId = groupInfo.getId();
                            String groupLocationURI = SCIMCommonUtils.getSCIMGroupURL(groupId);
                            Group group = new Group();
                            group.setDisplayName(groupInfo.getName());
                            group.setId(groupId);
                            group.setLocation(groupLocationURI);
                            scimRole.setGroup(group);
                        }
                    }

                    // Set role's assigned idp groups.
                    List<IdpGroup> assignedIdpGroups = role.getIdpGroups();
                    if (assignedIdpGroups != null) {
                        for (IdpGroup idpGroup : assignedIdpGroups) {
                            String idpGroupId = idpGroup.getGroupId();
                            String idpGroupLocationURI =
                                    SCIMCommonUtils.getIdpGroupURL(idpGroup.getIdpId(), idpGroupId);
                            Group group = new Group();
                            group.setDisplayName(idpGroup.getGroupName());
                            group.setId(idpGroupId);
                            group.setLocation(idpGroupLocationURI);
                            scimRole.setGroup(group);
                        }
                    }
                }
                if (requiredAttributes.contains(PERMISSIONS)) {
                    List<MultiValuedComplexType> permissions =
                            convertPermissionsToMultiValuedComplexType(role.getPermissions());
                    scimRole.setPermissions(permissions);
                }
                if (requiredAttributes.contains(ASSOCIATED_APPLICATIONS)) {
                    // Set associated applications.
                    List<MultiValuedComplexType> associatedApps =
                            convertAssociatedAppsToMultivaluedComplexType(role.getAssociatedApplications());
                    if (CollectionUtils.isNotEmpty(associatedApps)) {
                        scimRole.setAssociatedApplications(associatedApps);
                    }
                }
                if (requiredAttributes.contains(PROPERTIES)) {
                    // Set role properties.
                    List<MultiValuedComplexType> roleProperties =
                            convertRolePropertiesToMultiValuedComplexType(role.getRoleProperties());
                    if (CollectionUtils.isNotEmpty(roleProperties)) {
                        scimRole.setRoleProperties(roleProperties);
                    }
                }
            }
            scimRoles.add(scimRole);
        }
        return scimRoles;
    }

    private void doUpdateRoleName(RoleV2 oldRole, RoleV2 newRole)
            throws CharonException, ConflictException, NotFoundException, BadRequestException {

        String oldRoleDisplayName = oldRole.getDisplayName();
        String newRoleDisplayName = newRole.getDisplayName();
        String roleId = oldRole.getId();
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Updating role name from %s to %s of role with id: %s.", oldRoleDisplayName,
                    newRoleDisplayName, roleId));
        }

        // Update name if it is changed.
        if (!StringUtils.equals(oldRoleDisplayName, newRoleDisplayName)) {
            // Update role name.
            try {
                if (isSharedRole(roleId)) {
                    throw new BadRequestException("Role name update is not allowed for shared roles.",
                            ResponseCodeConstants.INVALID_VALUE);
                }
                roleManagementService.updateRoleName(oldRole.getId(), newRoleDisplayName, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (StringUtils.equals(ROLE_NOT_FOUND.getCode(), e.getErrorCode())) {
                    throw new NotFoundException(e.getMessage());
                } else if (StringUtils.equals(RoleConstants.Error.ROLE_ALREADY_EXISTS.getCode(), e.getErrorCode())) {
                    throw new ConflictException(e.getMessage());
                } else if (StringUtils.equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating role %s's name from: %s to %s", roleId,
                                oldRoleDisplayName, newRoleDisplayName), e);
            }
        }
    }

    private String getCurrentRoleName(String roleId, String tenantDomain) throws CharonException, NotFoundException {

        String currentRoleName;
        try {
            currentRoleName = roleManagementService.getRoleNameByRoleId(roleId, tenantDomain);
            if (isInternalRole(currentRoleName)) {
                currentRoleName = addInternalDomain(currentRoleName);
            }
        } catch (IdentityRoleManagementException e) {
            if ((ROLE_NOT_FOUND.getCode()).equals(e.getErrorCode())) {
                throw new NotFoundException(e.getMessage());
            }
            throw new CharonException(String.format("Error occurred while getting the role name by " +
                    "the role id: %s", roleId), e);
        }
        return currentRoleName;
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

    private void doUpdateUsers(RoleV2 oldRole, RoleV2 newRole) throws CharonException, BadRequestException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Updating users of role with ID: " + oldRole.getId());
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
                if (StringUtils.equals(RoleConstants.Error.INVALID_REQUEST.getCode(), e.getErrorCode()) || StringUtils
                        .equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating users in the role with ID: %s", oldRole.getId()),
                        e);
            }
        }
    }

    private void doUpdateGroups(RoleV2 oldRole, RoleV2 newRole) throws CharonException, BadRequestException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Updating groups of role with ID: " + oldRole.getId());
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
                if (StringUtils.equals(RoleConstants.Error.INVALID_REQUEST.getCode(), e.getErrorCode()) || StringUtils
                        .equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating groups in the role with ID: %s", oldRole.getId()),
                        e);
            }
        }
    }

    private void doUpdatePermissions(RoleV2 oldRole, RoleV2 newRole) throws BadRequestException, CharonException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Updating permissions of role: " + oldRole.getDisplayName());
        }

        Set<String> oldRolePermissions = new HashSet<>(oldRole.getPermissionValues());
        Set<String> newRolePermissions = new HashSet<>(newRole.getPermissionValues());
        // Check for deleted permissions.
        Set<String> deletePermissionValuesList = getRemovedIDList(oldRolePermissions, newRolePermissions);
        // Check for added permissions.
        Set<String> addedPermissionValuesList = getAddedIDList(oldRolePermissions, newRolePermissions);

        // Update the role with added permissions and deleted permissions.
        if (isNotEmpty(deletePermissionValuesList) || isNotEmpty(addedPermissionValuesList)) {
            if (isSharedRole(oldRole.getId())) {
                throw new BadRequestException("Role's permission modification is not allowed for shared roles.",
                        ResponseCodeConstants.INVALID_VALUE);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Permissions have changed. Updating permissions of role with ID: " + oldRole.getId());
            }
            try {
                List<Permission> addedPermissions = addedPermissionValuesList.stream()
                        .map(Permission::new)
                        .collect(Collectors.toList());
                List<Permission> removedPermissions = deletePermissionValuesList.stream()
                        .map(Permission::new)
                        .collect(Collectors.toList());
                roleManagementService.updatePermissionListOfRole(oldRole.getId(), addedPermissions, removedPermissions,
                        tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (StringUtils.equals(RoleConstants.Error.INVALID_REQUEST.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                } else if (RoleConstants.Error.INVALID_PERMISSION.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage(), ResponseCodeConstants.INVALID_VALUE);
                } else if (StringUtils.equals(OPERATION_FORBIDDEN.getCode(), e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating permissions for role with ID: %s",
                                oldRole.getId()), e);
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

    private void updateRoleName(String roleId, String oldRoleDisplayName, String newRoleDisplayName)
            throws CharonException, ConflictException, NotFoundException {

        if (!StringUtils.equals(oldRoleDisplayName, newRoleDisplayName)) {
            try {
                roleManagementService.updateRoleName(roleId, newRoleDisplayName, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if ((ROLE_NOT_FOUND.getCode()).equals(e.getErrorCode())) {
                    throw new NotFoundException(e.getMessage());
                } else if ((RoleConstants.Error.ROLE_ALREADY_EXISTS.getCode()).equals(e.getErrorCode())) {
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

        try {
            Collections.sort(permissionOperations);
            Set<String> addedPermissions = new HashSet<>();
            Set<String> deletedPermissions = new HashSet<>();
            Set<String> replacedPermissions = new HashSet<>();

            List<Permission> permissionListOfRole = roleManagementService.getPermissionListOfRole(roleId, tenantDomain);

            for (PatchOperation permissionOperation : permissionOperations) {
                if (permissionOperation.getValues() instanceof Map) {
                    Map<String, String> permissionObject = (Map<String, String>) permissionOperation.getValues();
                    prepareAddedRemovedPermissionLists(addedPermissions, deletedPermissions, replacedPermissions,
                            permissionOperation, permissionObject, permissionListOfRole);
                } else if (permissionOperation.getValues() instanceof List) {
                    List<Map<String, String>> permissionOperationValues =
                            (List<Map<String, String>>) permissionOperation.getValues();
                    for (Map<String, String> permissionObject : permissionOperationValues) {
                        prepareAddedRemovedPermissionLists(addedPermissions, deletedPermissions, replacedPermissions,
                                permissionOperation, permissionObject, permissionListOfRole);
                    }
                }
                if (SCIMConstants.OperationalConstants.REPLACE.equals(
                        permissionOperation.getOperation().toLowerCase(Locale.ENGLISH))) {
                    prepareReplacedPermissionLists(permissionListOfRole, addedPermissions, deletedPermissions,
                            replacedPermissions);
                }
            }
            if (isNotEmpty(addedPermissions) || isNotEmpty(deletedPermissions)) {
                doUpdatePermissions(roleId, addedPermissions, deletedPermissions);
            }
        } catch (IdentityRoleManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while updating permissions for role with ID: %s", roleId), e);
        }
    }

    private void prepareAddedRemovedPermissionLists(Set<String> addedPermissions, Set<String> deletedPermissions,
                                                    Set<String> replacedPermissions, PatchOperation permissionOperation,
                                                    Map<String, String> permissionObject,
                                                    List<Permission> permissionListOfRole) {

        switch (permissionOperation.getOperation()) {
            case (SCIMConstants.OperationalConstants.ADD):
                deletedPermissions.remove(permissionObject.get(SCIMConstants.CommonSchemaConstants.VALUE));
                if (!isPermissionExist(permissionObject.get(SCIMConstants.CommonSchemaConstants.VALUE),
                        permissionListOfRole)) {
                    addedPermissions.add(permissionObject.get(SCIMConstants.CommonSchemaConstants.VALUE));
                }
                break;
            case (SCIMConstants.OperationalConstants.REMOVE):
                addedPermissions.remove(permissionObject.get(SCIMConstants.CommonSchemaConstants.VALUE));
                deletedPermissions.add(permissionObject.get(SCIMConstants.CommonSchemaConstants.VALUE));
                break;
            case (SCIMConstants.OperationalConstants.REPLACE):
                replacedPermissions.add(permissionObject.get(SCIMConstants.CommonSchemaConstants.VALUE));
                break;
        }
    }

    private void prepareReplacedPermissionLists(List<Permission> permissionsOfRole, Set<String> addedPermissions,
                                                Set<String> removedPermissions, Set<String> replacedPermissions) {

        if (!permissionsOfRole.isEmpty()) {
            for (Permission permission : permissionsOfRole) {
                if (!replacedPermissions.contains(permission.getName())) {
                    removedPermissions.add(permission.getName());
                } else {
                    replacedPermissions.remove(permission.getName());
                }
            }
        }
        addedPermissions.addAll(replacedPermissions);
    }

    private void updateGroups(String roleId, List<PatchOperation> groupOperations)
            throws CharonException, BadRequestException {

        try {
            Collections.sort(groupOperations);

            Set<String> givenAddedGroupIds = new HashSet<>();
            Set<String> givenDeletedGroupIds = new HashSet<>();
            Set<String> givenReplaceGroupsIds = new HashSet<>();

            Set<String> addedGroupIds = new HashSet<>();
            Set<String> deletedGroupIds = new HashSet<>();
            Set<String> replaceGroupIds = new HashSet<>();

            Set<String> addedIdpGroupIds = new HashSet<>();
            Set<String> deletedIdpGroupIds = new HashSet<>();
            Set<String> replaceIdpGroupIds = new HashSet<>();

            List<GroupBasicInfo> groupListOfRole = roleManagementService.getGroupListOfRole(roleId, tenantDomain);
            for (PatchOperation groupOperation : groupOperations) {
                if (groupOperation.getValues() instanceof Map) {
                    Map<String, String> groupObject = (Map<String, String>) groupOperation.getValues();
                    prepareInitialGroupLists(givenAddedGroupIds, givenDeletedGroupIds, givenReplaceGroupsIds,
                            groupOperation, groupObject);
                } else if (groupOperation.getValues() instanceof List) {
                    List<Map<String, String>> groupOperationValues =
                            (List<Map<String, String>>) groupOperation.getValues();
                    if (groupOperationValues.isEmpty()
                            && SCIMConstants.OperationalConstants.REPLACE.equals(groupOperation.getOperation())) {
                        deletedGroupIds.addAll(groupListOfRole.stream().map(GroupBasicInfo::getId).
                                collect(Collectors.toList()));
                    }
                    for (Map<String, String> groupObject : groupOperationValues) {
                        prepareInitialGroupLists(givenAddedGroupIds, givenDeletedGroupIds, givenReplaceGroupsIds,
                                groupOperation, groupObject);
                    }
                }
            }

            Set<String> givenUniqueGroupIds = new HashSet<>();
            givenUniqueGroupIds.addAll(givenAddedGroupIds);
            givenUniqueGroupIds.addAll(givenDeletedGroupIds);
            givenUniqueGroupIds.addAll(givenReplaceGroupsIds);

            List<IdPGroup> idpGroups = SCIMCommonComponentHolder.getIdpManagerService().getValidIdPGroupsByIdPGroupIds(
                    new ArrayList<>(givenUniqueGroupIds), tenantDomain);
            Set<String> idpGroupIds = idpGroups.stream().map(IdPGroup::getIdpGroupId).collect(Collectors.toSet());
            
            Set<String> groupIdListOfRole =
                    groupListOfRole.stream().map(GroupBasicInfo::getId).collect(Collectors.toSet());
            List<IdpGroup> idpGroupListOfRole = roleManagementService.getIdpGroupListOfRole(roleId, tenantDomain);
            Set<String> idpGroupIdListOfRole =
                    idpGroupListOfRole.stream().map(IdpGroup::getGroupId).collect(Collectors.toSet());

            seperatedAddedGroupLists(givenAddedGroupIds, idpGroupIds, idpGroupIdListOfRole, groupIdListOfRole,
                    addedIdpGroupIds, addedGroupIds);
            seperateRemovedGroupLists(givenDeletedGroupIds, idpGroupIds, deletedIdpGroupIds, deletedGroupIds);

            seperateReplacedGroupLists(givenReplaceGroupsIds, idpGroupIds, replaceIdpGroupIds, replaceGroupIds);
            prepareReplacedGroupLists(groupListOfRole, addedGroupIds, deletedGroupIds, replaceGroupIds);
            prepareReplacedIdPGroupLists(idpGroupListOfRole, addedIdpGroupIds, deletedIdpGroupIds, replaceIdpGroupIds);

            if (isNotEmpty(addedGroupIds) || isNotEmpty(deletedGroupIds)) {
                doUpdateGroups(roleId, addedGroupIds, deletedGroupIds);
            }
            if (isNotEmpty(addedIdpGroupIds) || isNotEmpty(deletedIdpGroupIds)) {
                Map<String, IdPGroup> idpGroupMap = idpGroups.stream()
                        .collect(Collectors.toMap(IdPGroup::getIdpGroupId, Function.identity()));
                List<IdpGroup> addedIdpGroups = addedIdpGroupIds.stream()
                        .map(idpGroupMap::get)
                        .map(this::convertToIdpGroup)
                        .collect(Collectors.toList());
                List<IdpGroup> deletedIdpGroups = deletedIdpGroupIds.stream()
                        .map(idpGroupMap::get)
                        .map(this::convertToIdpGroup)
                        .collect(Collectors.toList());
                doUpdateIdPGroups(roleId, addedIdpGroups, deletedIdpGroups);
            }
        } catch (IdentityRoleManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while retrieving the group list for role with ID: %s", roleId), e);
        } catch (IdentityProviderManagementException e) {
            throw new CharonException(
                    String.format("Error occurred while retrieving the IDP group list for role with ID: %s", roleId),
                    e);
        }
    }

    private void updateUsers(String roleId, List<PatchOperation> memberOperations)
            throws BadRequestException, CharonException, ForbiddenException {

        Collections.sort(memberOperations);
        Set<String> addedUsers = new HashSet<>();
        Set<String> deletedUsers = new HashSet<>();
        Set<Object> newlyAddedUsersIds = new HashSet<>();

        for (PatchOperation memberOperation : memberOperations) {
            if (memberOperation.getValues() instanceof Map) {
                Map<String, String> memberObject = (Map<String, String>) memberOperation.getValues();
                prepareAddedRemovedUserLists(addedUsers, deletedUsers, newlyAddedUsersIds,
                        memberOperation, memberObject, roleId);
            } else if (memberOperation.getValues() instanceof List) {
                List<Map<String, String>> memberOperationValues =
                        (List<Map<String, String>>) memberOperation.getValues();
                for (Map<String, String> memberObject : memberOperationValues) {
                    prepareAddedRemovedUserLists(addedUsers, deletedUsers, newlyAddedUsersIds,
                            memberOperation, memberObject, roleId);
                }
            }
        }

        if (isNotEmpty(addedUsers) || isNotEmpty(deletedUsers)) {
            doUpdateUsers(addedUsers, deletedUsers, newlyAddedUsersIds, roleId);
        }
    }

    private void doUpdatePermissions(String roleId, Set<String> addedPermissions, Set<String> removedPermissions)
            throws CharonException, BadRequestException {

        // Update the role with added permissions and deleted permissions.
        if (isNotEmpty(addedPermissions) || isNotEmpty(removedPermissions)) {
            List<Permission> addedPermissionsList = addedPermissions.stream()
                    .map(Permission::new)
                    .collect(Collectors.toList());
            List<Permission> removedPermissionsList = removedPermissions.stream()
                    .map(Permission::new)
                    .collect(Collectors.toList());
            try {
                roleManagementService.updatePermissionListOfRole(roleId, addedPermissionsList, removedPermissionsList,
                        tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (RoleConstants.Error.INVALID_REQUEST.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                } else if (RoleConstants.Error.INVALID_PERMISSION.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage(), ResponseCodeConstants.INVALID_VALUE);
                }
                throw new CharonException(
                        String.format("Error occurred while updating permissions of the role with ID: %s", roleId), e);
            }
        }
    }

    private void doUpdateGroups(String roleId, Set<String> newGroupIDList, Set<String> deleteGroupIDList)
            throws CharonException, BadRequestException {

        // Update the role with added groups and deleted groups.
        if (isNotEmpty(newGroupIDList) || isNotEmpty(deleteGroupIDList)) {
            try {
                roleManagementService.updateGroupListOfRole(roleId, new ArrayList<>(newGroupIDList),
                        new ArrayList<>(deleteGroupIDList), tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (RoleConstants.Error.INVALID_REQUEST.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating groups in the role with ID: %s", roleId), e);
            }
        }
    }

    private void doUpdateIdPGroups(String roleId, List<IdpGroup> newGroupIDList, List<IdpGroup> deleteGroupIDList)
            throws CharonException, BadRequestException {

        // Update the role with added groups and deleted groups.
        if (isNotEmpty(newGroupIDList) || isNotEmpty(deleteGroupIDList)) {
            try {
                roleManagementService.updateIdpGroupListOfRole(roleId, newGroupIDList, deleteGroupIDList, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                if (RoleConstants.Error.INVALID_REQUEST.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating groups in the role with ID: %s", roleId), e);
            }
        }
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
                if (RoleConstants.Error.INVALID_REQUEST.getCode().equals(e.getErrorCode())) {
                    throw new BadRequestException(e.getMessage());
                } else if (OPERATION_FORBIDDEN.getCode().equals(e.getErrorCode())) {
                    throw new ForbiddenException(e.getMessage());
                }
                throw new CharonException(
                        String.format("Error occurred while updating users in the role with ID: %s", roleId), e);
            }
        }
    }

    private void validateUserIds(List<String> newUserIDList, Set<Object> newlyAddedMemberIds) throws
            BadRequestException {

        for (Object addedUserId : newlyAddedMemberIds) {
            if (!newUserIDList.contains(addedUserId.toString())) {
                throw new BadRequestException(String.format("Provided SCIM user Id: %s doesn't match with the "
                        + "userID obtained from user-store for the provided username.", addedUserId),
                        ResponseCodeConstants.INVALID_VALUE);
            }
        }
    }

    private String getUserIDByName(String name, String tenantDomain) throws IdentityRoleManagementException {

        return userIDResolver.getIDByName(name, tenantDomain);
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

    private void prepareInitialGroupLists(Set<String> givenAddedGroupsIds, Set<String> givenRemovedGroupsIds,
                                          Set<String> givenReplacedGroupsIds, PatchOperation groupOperation,
                                          Map<String, String> groupObject) throws BadRequestException {

        String value = groupObject.get(SCIMConstants.CommonSchemaConstants.VALUE);

        if (StringUtils.isBlank(value)) {
            throw new BadRequestException("Group id is required to update group of the role.",
                    ResponseCodeConstants.INVALID_VALUE);
        }

        switch (groupOperation.getOperation()) {
            case (SCIMConstants.OperationalConstants.ADD):
                givenRemovedGroupsIds.remove(value);
                givenAddedGroupsIds.add(value);
                break;
            case (SCIMConstants.OperationalConstants.REMOVE):
                givenAddedGroupsIds.remove(value);
                givenRemovedGroupsIds.add(value);
                break;
            case (SCIMConstants.OperationalConstants.REPLACE):
                givenReplacedGroupsIds.add(value);
                break;
            default:
                break;
        }
    }

    private void seperatedAddedGroupLists(Set<String> givenAddedGroupIds, Set<String> idpGroupIds,
                                          Set<String> idpGroupIdListOfRole,Set<String> groupIdListOfRole,
                                          Set<String> addedIdpGroupIds, Set<String> addedGroupIds) {

        for (String groupId : givenAddedGroupIds) {
            if (idpGroupIds.contains(groupId) && !idpGroupIdListOfRole.contains(groupId)) {
                addedIdpGroupIds.add(groupId);
            } else if (!groupIdListOfRole.contains(groupId)) {
                addedGroupIds.add(groupId);
            }
        }
    }

    private void seperateRemovedGroupLists(Set<String> givenDeletedGroupIds, Set<String> idpGroupIds,
                                           Set<String> deletedIdpGroupIds, Set<String> deletedGroupIds) {

        for (String groupId : givenDeletedGroupIds) {
            if (idpGroupIds.contains(groupId)) {
                deletedIdpGroupIds.add(groupId);
            } else {
                deletedGroupIds.add(groupId);
            }
        }
    }

    private void seperateReplacedGroupLists(Set<String> givenReplaceGroupsIds, Set<String> idpGroupIds,
                                            Set<String> replaceIdpGroupIds, Set<String> replaceGroupIds) {

        for (String groupId : givenReplaceGroupsIds) {
            if (idpGroupIds.contains(groupId)) {
                replaceIdpGroupIds.add(groupId);
            } else {
                replaceGroupIds.add(groupId);
            }
        }
    }

    private void prepareAddedRemovedUserLists(Set<String> addedMembers, Set<String> removedMembers,
                                              Set<Object> newlyAddedMemberIds, PatchOperation memberOperation,
                                              Map<String, String> memberObject, String roleId)
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
                    String tempDisplay = userListWithID.get(0).getUsername();
                    if (StringUtils.isNotBlank(userListWithID.get(0).getUserStoreDomain())) {
                        tempDisplay = userListWithID.get(0).getUserStoreDomain() + CarbonConstants.DOMAIN_SEPARATOR +
                                tempDisplay;
                    }
                    memberObject.put(SCIMConstants.RoleSchemaConstants.DISPLAY, tempDisplay);
                    memberOperation.setValues(memberObject);
                }
            }

            if (memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY) == null) {
                throw new BadRequestException("User can't be resolved from the given user Id.",
                        ResponseCodeConstants.INVALID_VALUE);
            }

            String userID = memberObject.get(SCIMConstants.RoleSchemaConstants.VALUE);
            if (StringUtils.isEmpty(userID)) {
                userID = userStoreManager.getUserIDFromUserName(
                        memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY));
                if (StringUtils.isEmpty(userID)) {
                    throw new BadRequestException("User can't be resolved from the given username.",
                            ResponseCodeConstants.NO_TARGET);
                }
            }

            List<String> roleList;
            try {
                roleList = roleManagementService.getRoleIdListOfUser(userID, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                throw new CharonException("Error occurred while retrieving the role list of user.");
            }

            if (SCIMConstants.OperationalConstants.ADD.equals(memberOperation.getOperation()) &&
                    !roleList.contains(roleId)) {
                removedMembers.remove(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY));
                addedMembers.add(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY));
                newlyAddedMemberIds.add(memberObject.get(SCIMConstants.CommonSchemaConstants.VALUE));
            } else if (SCIMConstants.OperationalConstants.REMOVE.equals(memberOperation.getOperation())) {
                addedMembers.remove(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY));
                removedMembers.add(memberObject.get(SCIMConstants.RoleSchemaConstants.DISPLAY));
            }
        } catch (UserStoreException e) {
            if ("Invalid Domain Name".equals(e.getMessage())) {
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

    private void prepareReplacedIdPGroupLists(List<IdpGroup> idpGroupListOfRole, Set<String> addedGroupIds,
                                           Set<String> removedGroupsIds, Set<String> replacedGroupsIds) {

        if (replacedGroupsIds.isEmpty()) {
            return;
        }

        if (!idpGroupListOfRole.isEmpty()) {
            for (IdpGroup idpGroupInfo : idpGroupListOfRole) {
                if (!replacedGroupsIds.contains(idpGroupInfo.getGroupId())) {
                    removedGroupsIds.add(idpGroupInfo.getGroupId());
                } else {
                    replacedGroupsIds.remove(idpGroupInfo.getGroupId());
                }
            }
        }
        addedGroupIds.addAll(replacedGroupsIds);
    }

    private boolean isGroupExist(String groupId, List<GroupBasicInfo> groupListOfRole) {

        return groupListOfRole != null &&
                groupListOfRole.stream()
                        .anyMatch(groupBasicInfo -> groupBasicInfo.getId().equals(groupId));
    }

    private boolean isPermissionExist(String permissionValue, List<Permission> permissionsOfRole) {

        return permissionsOfRole != null &&
                permissionsOfRole.stream()
                        .anyMatch(permission -> permission.getName().equals(permissionValue));
    }

    private boolean isUsersAttributeRequired(Map<String, Boolean> requiredAttributes) {

        if (requiredAttributes == null) {
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

    private IdpGroup convertToIdpGroup(IdPGroup idpGroup) {

        IdpGroup convertedGroup = new IdpGroup(idpGroup.getIdpGroupId(), idpGroup.getIdpId());
        convertedGroup.setGroupName(idpGroup.getIdpGroupName());
        return convertedGroup;
    }

    private boolean isSharedRole(String roleId) throws CharonException {

        try {
            return RoleManagementUtils.isSharedRole(roleId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new CharonException("Error while checking whether the role is a shared role.", e);
        }
    }
}
