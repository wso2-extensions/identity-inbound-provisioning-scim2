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

package org.wso2.carbon.identity.scim2.common.group;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.util.RoleManagementUtils;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.AttributeUtil;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;


/**
 * This is for managing SCIM specific attributes related to Group resource in Identity_SCIM_GROUP
 * Table. This should be managed per tenant.
 * But need to use the same approach as for User, by going through AttributMapper to do it in a generic way.
 */
public class SCIMGroupHandler {
    private static final Log logger = LogFactory.getLog(SCIMGroupHandler.class);
    private int tenantId;

    /**
     * Always use this constructor and pass tenant Id.
     *
     * @param tenantId
     */
    public SCIMGroupHandler(int tenantId) {
        this.tenantId = tenantId;
    }

    /**
     * When adding a group through management console, we need to make it SCIM compatible, if SCIM
     * enabled in the UserStoreManager config, by adding the READONLY attributes added by Charon.
     *
     * @param groupName
     */
    public void addMandatoryAttributes(String groupName)
            throws IdentitySCIMException {
        Map<String, String> attributes = new HashMap<>();
        String id = UUID.randomUUID().toString();
        attributes.put(SCIMConstants.CommonSchemaConstants.ID_URI, id);

        String createdDate = AttributeUtil.formatDateTime(Instant.now());
        attributes.put(SCIMConstants.CommonSchemaConstants.CREATED_URI, createdDate);

        attributes.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, createdDate);
        attributes.put(SCIMConstants.CommonSchemaConstants.LOCATION_URI, SCIMCommonUtils.getSCIMGroupURL(id));
        GroupDAO groupDAO = new GroupDAO();
        groupDAO.addSCIMGroupAttributes(tenantId, groupName, attributes);
    }

    /**
     * Add roleV2 SCIM metadata.
     *
     * @param roleName Role name.
     * @throws IdentitySCIMException if any error occurs while adding admin role attributes.
     */
    public void addRoleV2MandatoryAttributes(String roleName) throws IdentitySCIMException {

        Map<String, String> attributes = new HashMap<>();
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        String id;
        int roleAudienceRefId;
        try {
            String orgId  = getOrganizationId(tenantDomain);
            id = SCIMCommonComponentHolder.getRoleManagementServiceV2()
                    .getRoleIdByName(UserCoreUtil.removeDomainFromName(roleName), RoleConstants.ORGANIZATION, orgId,
                            tenantDomain);
            roleAudienceRefId = RoleManagementUtils.resolveAudienceRefId(RoleConstants.ORGANIZATION, orgId);
        } catch (IdentityRoleManagementException e) {
            throw new IdentitySCIMException("Error while resolving " + roleName + " role id.", e);
        }
        if (StringUtils.isBlank(id)) {
            throw new IdentitySCIMException("Role : " + roleName + " id not found.");
        }
        if (roleAudienceRefId == -1) {
            throw new IdentitySCIMException("Role : " + roleName + " audience id not found.");
        }
        attributes.put(SCIMConstants.CommonSchemaConstants.ID_URI, id);

        String createdDate = AttributeUtil.formatDateTime(Instant.now());
        attributes.put(SCIMConstants.CommonSchemaConstants.CREATED_URI, createdDate);

        attributes.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, createdDate);
        attributes.put(SCIMConstants.CommonSchemaConstants.LOCATION_URI, SCIMCommonUtils.getSCIMRoleV2URL(id));
        GroupDAO groupDAO = new GroupDAO();
        groupDAO.addSCIMRoleV2Attributes(tenantId, roleName, roleAudienceRefId, attributes);
    }

    /**
     * Get the organization id of the tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return Organization id.
     * @throws IdentitySCIMException if any error occurs while resolving organization id.
     */
    private String getOrganizationId(String tenantDomain) throws IdentitySCIMException {

        String orgId;
        try {
            orgId = SCIMCommonComponentHolder.getOrganizationManager().resolveOrganizationId(tenantDomain);
        } catch (OrganizationManagementException e) {
            throw new IdentitySCIMException("Error while resolving org id of tenant : " + tenantDomain, e);
        }
        if (StringUtils.isBlank(orgId)) {
            throw new IdentitySCIMException("Organization id not found for tenant : " + tenantDomain);
        }
        return orgId;
    }

    /**
     * Retrieve the group attributes by group name
     *
     * @param groupName
     * @return
     */
    public Map<String, String> getGroupAttributesByName(String groupName) {
        return null;
    }

    /**
     * Retrieve the group attributes by group id
     *
     * @param id
     * @return
     */
    public Map<String, String> getGroupAttributesById(String id) {
        return null;
    }

    /**
     * When adding group through SCIM Resource endpoint, add the group attributes to the
     * Identity_SCIM_GROUP table, in addition to the ones added in UserStore (i.e display name, users)
     *
     * @param group
     */
    public void createSCIMAttributes(Group group) throws IdentitySCIMException {
        try {
            Map<String, String> attributes = new HashMap<>();
            attributes.put(SCIMConstants.CommonSchemaConstants.ID_URI, group.getId());
            attributes.put(SCIMConstants.CommonSchemaConstants.CREATED_URI, AttributeUtil.formatDateTime(
                    group.getCreatedDate().toInstant()));
            attributes.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, AttributeUtil.formatDateTime(
                    group.getLastModified().toInstant()));
            attributes.put(SCIMConstants.CommonSchemaConstants.LOCATION_URI, group.getLocation());
            GroupDAO groupDAO = new GroupDAO();
            groupDAO.addSCIMGroupAttributes(tenantId, group.getDisplayName(), attributes);
        } catch (CharonException e) {
            throw new IdentitySCIMException("Error getting group name from SCIM Group.", e);
        }
    }

    /**
     * Get the group name by Id.
     *
     * @param id
     * @return
     */
    public String getGroupName(String id) throws IdentitySCIMException {

        GroupDAO groupDAO = new GroupDAO();
        String roleName = groupDAO.getGroupNameById(tenantId, id);
        if (roleName == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Role doesn't exist with id: " + id);
            }
            return null;
        } else {
            return roleName;
        }
    }

    /**
     * Get group id by name.
     *
     * @param name
     * @return
     */
    public String getGroupId(String name) {
        return null;
    }

    /**
     * Set the attributes retrieved from the Identity table, in the given group object.
     *
     * @param group
     * @return
     */
    public Group getGroupWithAttributes(Group group, String groupName)
            throws IdentitySCIMException, CharonException, BadRequestException {

        GroupDAO groupDAO = new GroupDAO();
        Map<String, String> attributes = groupDAO.getSCIMGroupAttributes(tenantId, groupName);

        if (attributes.isEmpty()) {
            if (logger.isDebugEnabled()) {
                logger.debug("The group: " + groupName + ", is not a SCIM group. Skipping..");
            }
            return group;
        }

        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            if (SCIMConstants.CommonSchemaConstants.ID_URI.equals(entry.getKey())) {
                group.setId(entry.getValue());
            } else if (SCIMConstants.CommonSchemaConstants.CREATED_URI.equals(entry.getKey())) {
                group.setCreatedDate(Date.from(AttributeUtil.parseDateTime(entry.getValue())));
            } else if (SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI.equals(entry.getKey())) {
                group.setLastModified(Date.from(AttributeUtil.parseDateTime(entry.getValue())));
            } else if (SCIMConstants.CommonSchemaConstants.LOCATION_URI.equals(entry.getKey())) {
                group.setLocation(SCIMCommonUtils.getSCIMGroupURL(group.getId()));
            }
        }
        return group;
    }

    /**
     * Check whether attributes related to the given group name and tenant Id exist in the identity table.
     *
     * @param groupName
     * @return
     * @throws IdentitySCIMException
     */
    public boolean isGroupExisting(String groupName) throws IdentitySCIMException {
        GroupDAO groupDAO = new GroupDAO();
        return groupDAO.isExistingGroup(groupName, tenantId);
    }

    /**
     * Delete the attributes related with the group name and the tenant Id..
     *
     * @param groupName
     * @throws IdentitySCIMException
     */
    public void deleteGroupAttributes(String groupName) throws IdentitySCIMException {
        GroupDAO groupDAO = new GroupDAO();
        if (groupDAO.isExistingGroup(groupName, this.tenantId)) {
            groupDAO.removeSCIMGroup(tenantId, groupName);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Information for the group: " + groupName +
                        " doesn't contain in the identity scim table.");
            }
        }
    }

    public void updateRoleName(String oldRoleName, String newRoleName)
            throws IdentitySCIMException {
        GroupDAO groupDAO = new GroupDAO();
        if (groupDAO.isExistingGroup(oldRoleName, this.tenantId)) {
            groupDAO.updateRoleName(this.tenantId, oldRoleName, newRoleName);
        } else {
            throw new IdentitySCIMException("Non-existent group: " + oldRoleName +
                    " is trying to be updated.");
        }
    }

    /**
     * Lists the Groups created from SCIM
     *
     * @return list of SCIM groups
     * @throws IdentitySCIMException
     */
    public Set<String> listSCIMRoles() throws IdentitySCIMException {
        GroupDAO groupDAO = new GroupDAO();
        return groupDAO.listSCIMGroups(tenantId);
    }

    /**
     * Lists the Groups created from SCIM with a attribute filter and search regex.
     *
     * @param attributeName   Search attribute name
     * @param searchAttribute Search attribute value
     * @return List of SCIM groups.
     * @throws IdentitySCIMException IdentitySCIMException when reading the SCIM Group information.
     * @since 1.2.44
     * @deprecated Method does not support domain filtering. Use
     * {@link org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler#getGroupListFromAttributeName(String,
     * String, String)}
     */
    @Deprecated
    public String[] getGroupListFromAttributeName(String attributeName, String searchAttribute)
            throws IdentitySCIMException {

        GroupDAO groupDAO = new GroupDAO();
        return groupDAO.getGroupNameList(attributeName, searchAttribute, this.tenantId);
    }

    /**
     * Lists the Groups created from SCIM with a attribute filter and search regex.
     *
     * @param attributeName   Search attribute name
     * @param searchAttribute Search attribute value
     * @param domainName      Domain to search
     * @return List of SCIM groups.
     * @throws IdentitySCIMException IdentitySCIMException when reading the SCIM Group information.
     */
    public String[] getGroupListFromAttributeName(String attributeName, String searchAttribute, String domainName)
            throws IdentitySCIMException {

        GroupDAO groupDAO = new GroupDAO();
        return groupDAO.getGroupNameList(attributeName, searchAttribute, this.tenantId, domainName);
    }

    /**
     * Update SCIM attributes of the group.
     *
     * @param groupName     The display name of the group.
     * @param attributes    The attributes to be updated.
     * @throws IdentitySCIMException IdentitySCIMException when updating the SCIM Group information.
     */
    public void updateSCIMAttributes(String groupName, Map<String, String> attributes) throws IdentitySCIMException {

        GroupDAO groupDAO = new GroupDAO();
        groupDAO.updateSCIMGroupAttributes(tenantId, groupName, attributes);
    }
}
