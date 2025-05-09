/*
 * Copyright (c) 2017-2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.scim2.common.DAO;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * JDBC based Data Access layer for managing SCIM specific attributes that are not stored in
 * user store.
 */
public class GroupDAO {

    private static final Log log = LogFactory.getLog(GroupDAO.class);

    /**
     * This method is deprecated.
     *
     * @since 1.4.43
     * @deprecated New APIs have been provided to list the groups that belong to a tenant by its tenant id that are
     * created from SCIM
     * Use {@link org.wso2.carbon.identity.scim2.common.DAO.GroupDAO#listSCIMGroups(int tenantId)} method.
     */
    @Deprecated
    public Set<String> listSCIMGroups() throws IdentitySCIMException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Set<String> groups = new HashSet<>();

        try {
            if (log.isDebugEnabled()) {
                log.debug("Retrieving all SCIM groups from database");
            }
            //retrieve groups from the DB
            prepStmt = connection.prepareStatement(SQLQueries.LIST_SCIM_GROUPS_SQL);
            prepStmt.setString(1, SCIMConstants.CommonSchemaConstants.ID_URI);
            resultSet = prepStmt.executeQuery();
            while (resultSet.next()) {
                String group = resultSet.getString(1);
                if (StringUtils.isNotEmpty(group)) {
                    group = SCIMCommonUtils.getPrimaryFreeGroupName(group);
                    groups.add(group);
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Retrieved " + groups.size() + " SCIM groups from database");
            }
        } catch (SQLException e) {
            log.error("Error when reading SCIM Group information from persistence store", e);
            throw new IdentitySCIMException("Error when reading the SCIM Group information from persistence store.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return groups;
    }

    /**
     * Lists the groups that belong to a tenant by its tenant id that are created from SCIM.
     *
     * @param tenantId tenant Id
     * @return The set of groups that were created from SCIM
     * @throws IdentitySCIMException If an error occurred while reading from persistence store.
     */
    public Set<String> listSCIMGroups(int tenantId) throws IdentitySCIMException {

        Set<String> groups = new HashSet<>();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.LIST_SCIM_GROUPS_BY_TENANT_ID_SQL);) {
            if (log.isDebugEnabled()) {
                log.debug("Retrieving SCIM groups for tenant ID: " + tenantId);
            }
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, SCIMConstants.CommonSchemaConstants.ID_URI);
            try (ResultSet resultSet = prepStmt.executeQuery();) {
                while (resultSet.next()) {
                    String group = resultSet.getString(1);
                    if (StringUtils.isNotEmpty(group)) {
                        group = SCIMCommonUtils.getPrimaryFreeGroupName(group);
                        groups.add(group);
                    }
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Retrieved " + groups.size() + " SCIM groups for tenant ID: " + tenantId);
            }
        } catch (SQLException e) {
            log.error("Error when reading SCIM Group information for tenant ID: " + tenantId, e);
            throw new IdentitySCIMException("Error when reading the SCIM Group information from persistence store.", e);
        }
        return groups;
    }

    public boolean isExistingGroup(String groupName, int tenantId) throws IdentitySCIMException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;

        boolean isExistingGroup = false;
        String groupNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(groupName);

        try {
            if (log.isDebugEnabled()) {
                log.debug("Checking if group exists: " + groupNameWithDomain + " for tenant ID: " + tenantId);
            }
            prepStmt = connection.prepareStatement(SQLQueries.CHECK_EXISTING_ATTRIBUTE_SQL);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, groupNameWithDomain);

            // Specifically checking SCIM 2.0 ID attribute to avoid conflict with SCIM 1.1
            prepStmt.setString(3, SCIMConstants.CommonSchemaConstants.ID_URI);

            rSet = prepStmt.executeQuery();
            if (rSet.next()) {
                isExistingGroup = true;
                if (log.isDebugEnabled()) {
                    log.debug("Group exists: " + groupNameWithDomain + " for tenant ID: " + tenantId);
                }
            } else if (log.isDebugEnabled()) {
                log.debug("Group does not exist: " + groupNameWithDomain + " for tenant ID: " + tenantId);
            }
            connection.commit();
        } catch (SQLException e) {
            log.error("Error when checking if group exists: " + groupNameWithDomain + " for tenant ID: " + tenantId, e);
            throw new IdentitySCIMException("Error when reading the group information from the persistence store.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }
        return isExistingGroup;
    }

    private boolean isExistingAttribute(String attributeName, String groupName, int tenantId)
            throws IdentitySCIMException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;
        boolean isExistingAttribute = false;
        String groupNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(groupName);

        try {
            if (log.isDebugEnabled()) {
                log.debug("Checking if attribute exists: " + attributeName + " for group: " + 
                        groupNameWithDomain + " in tenant ID: " + tenantId);
            }
            prepStmt = connection.prepareStatement(SQLQueries.CHECK_EXISTING_ATTRIBUTE_SQL);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, groupNameWithDomain);
            prepStmt.setString(3, attributeName);

            rSet = prepStmt.executeQuery();
            if (rSet.next()) {
                isExistingAttribute = true;
                if (log.isDebugEnabled()) {
                    log.debug("Attribute exists: " + attributeName + " for group: " + 
                            groupNameWithDomain + " in tenant ID: " + tenantId);
                }
            } else if (log.isDebugEnabled()) {
                log.debug("Attribute does not exist: " + attributeName + " for group: " + 
                        groupNameWithDomain + " in tenant ID: " + tenantId);
            }
            connection.commit();
        } catch (SQLException e) {
            log.error("Error when checking if attribute exists: " + attributeName + " for group: " + 
                    groupNameWithDomain + " in tenant ID: " + tenantId, e);
            throw new IdentitySCIMException("Error when reading the group attribute information from " +
                    "the persistence store.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }
        return isExistingAttribute;
    }

    public void addSCIMGroupAttributes(int tenantId, String roleName, Map<String, String> attributes)
            throws IdentitySCIMException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String roleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(roleName);

        if (log.isDebugEnabled()) {
            log.debug("Adding SCIM attributes for group: " + roleNameWithDomain + " in tenant ID: " + tenantId);
        }

        if (!isExistingGroup(roleNameWithDomain, tenantId)) {
            try {
                prepStmt = connection.prepareStatement(SQLQueries.ADD_ATTRIBUTES_SQL);
                prepStmt.setInt(1, tenantId);
                prepStmt.setString(2, roleName);

                for (Map.Entry<String, String> entry : attributes.entrySet()) {
                    if (!isExistingAttribute(entry.getKey(), roleNameWithDomain, tenantId)) {
                        prepStmt.setString(3, entry.getKey());
                        prepStmt.setString(4, entry.getValue());
                        prepStmt.addBatch();
                        if (log.isDebugEnabled()) {
                            log.debug("Adding attribute: " + entry.getKey() + " with value: " + entry.getValue() + 
                                    " for group: " + roleNameWithDomain + " in tenant ID: " + tenantId);
                        }
                    } else {
                        String errorMsg = "Error when adding SCIM Attribute: " + entry.getKey() + 
                                " An attribute with the same name already exists.";
                        log.error(errorMsg + " Group: " + roleNameWithDomain + " in tenant ID: " + tenantId);
                        throw new IdentitySCIMException(errorMsg);
                    }
                }
                prepStmt.executeBatch();
                connection.commit();
                log.info("Successfully added SCIM attributes for group: " + roleNameWithDomain + 
                        " in tenant ID: " + tenantId);
            } catch (SQLException e) {
                log.error("Error when adding SCIM attributes for group: " + roleNameWithDomain + 
                        " in tenant ID: " + tenantId, e);
                throw new IdentitySCIMException("Error when adding SCIM attributes for the group: "
                        + roleName, e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
            }
        } else {
            String errorMsg = "Error when adding SCIM Attributes for the group: " + roleName + 
                    " A Group with the same name already exists.";
            log.error(errorMsg + " Tenant ID: " + tenantId);
            throw new IdentitySCIMException(errorMsg);
        }
    }

    public void addSCIMRoleV2Attributes(int tenantId, String roleName, int roleAudienceRefId,
                                        Map<String, String> attributes) throws IdentitySCIMException {

        if (log.isDebugEnabled()) {
            log.debug("Adding SCIM V2 attributes for role: " + roleName + " with audience ref ID: " + 
                    roleAudienceRefId + " in tenant ID: " + tenantId);
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.ADD_ATTRIBUTES_WITH_AUDIENCE_SQL)) {
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, roleName);
            prepStmt.setInt(3, roleAudienceRefId);

            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                if (!isExistingRoleV2Attribute(entry.getKey(), roleName, roleAudienceRefId, tenantId)) {
                    prepStmt.setString(4, entry.getKey());
                    prepStmt.setString(5, entry.getValue());
                    prepStmt.addBatch();
                    if (log.isDebugEnabled()) {
                        log.debug("Adding V2 attribute: " + entry.getKey() + " with value: " + entry.getValue() + 
                                " for role: " + roleName + " in tenant ID: " + tenantId);
                    }
                } else {
                    String errorMsg = "Error when adding SCIM Attribute: " + entry.getKey() +
                            ". An attribute with the same name already exists.";
                    log.error(errorMsg + " Role: " + roleName + " with audience ref ID: " + 
                            roleAudienceRefId + " in tenant ID: " + tenantId);
                    throw new IdentitySCIMException(errorMsg);
                }
            }
            prepStmt.executeBatch();
            log.info("Successfully added SCIM V2 attributes for role: " + roleName + 
                    " with audience ref ID: " + roleAudienceRefId + " in tenant ID: " + tenantId);
        } catch (SQLException e) {
            log.error("Error when adding SCIM V2 attributes for role: " + roleName + 
                    " with audience ref ID: " + roleAudienceRefId + " in tenant ID: " + tenantId, e);
            throw new IdentitySCIMException("Error when adding SCIM meta data for the role : " + roleName, e);
        }
    }

    private boolean isExistingRoleV2Attribute(String attributeName, String roleName, int audienceRefId, int tenantId)
            throws IdentitySCIMException {

        if (log.isDebugEnabled()) {
            log.debug("Checking if V2 attribute exists: " + attributeName + " for role: " + roleName + 
                    " with audience ref ID: " + audienceRefId + " in tenant ID: " + tenantId);
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(
                     SQLQueries.CHECK_EXISTING_ATTRIBUTE_WITH_AUDIENCE_SQL)) {
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, roleName);
            prepStmt.setString(3, attributeName);
            prepStmt.setInt(4, audienceRefId);

            ResultSet resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                if (log.isDebugEnabled()) {
                    log.debug("V2 attribute exists: " + attributeName + " for role: " + roleName + 
                            " with audience ref ID: " + audienceRefId + " in tenant ID: " + tenantId);
                }
                return true;
            }
            if (log.isDebugEnabled()) {
                log.debug("V2 attribute does not exist: " + attributeName + " for role: " + roleName + 
                        " with audience ref ID: " + audienceRefId + " in tenant ID: " + tenantId);
            }
        } catch (SQLException e) {
            log.error("Error when checking if V2 attribute exists: " + attributeName + " for role: " + 
                    roleName + " with audience ref ID: " + audienceRefId + " in tenant ID: " + tenantId, e);
            throw new IdentitySCIMException("Error when reading the RoleV2 SCIM meta data from the persistence store.",
                    e);
        }
        return false;
    }

    /**
     * Add SCIM attributes to hybrid roles created while SCIM was disabled in the user store.
     *
     * @param tenantId       tenant id.
     * @param attributesList SCIM attribute list.
     * @throws IdentitySCIMException Error when reading from persistence store.
     */
    public void addSCIMGroupAttributesToSCIMDisabledHybridRoles(int tenantId,
                                                                Map<String, Map<String, String>> attributesList)
            throws IdentitySCIMException {

        if (log.isDebugEnabled()) {
            log.debug("Adding SCIM attributes to hybrid roles created while SCIM was disabled. Tenant ID: " + tenantId + 
                    ", Number of groups: " + attributesList.size());
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(); PreparedStatement prepStmt =
                connection.prepareStatement(SQLQueries.ADD_ATTRIBUTES_SQL)) {
            prepStmt.setInt(1, tenantId);
            for (Map.Entry<String, Map<String, String>> entry : attributesList.entrySet()) {
                String groupName = entry.getKey();
                String groupNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(groupName);
                prepStmt.setString(2, groupName);

                if (log.isDebugEnabled()) {
                    log.debug("Processing group: " + groupNameWithDomain + " with " + 
                            entry.getValue().size() + " attributes");
                }

                for (Map.Entry<String, String> attributes : entry.getValue().entrySet()) {
                    if (!isExistingAttribute(attributes.getKey(), groupNameWithDomain, tenantId)) {
                        prepStmt.setString(3, attributes.getKey());
                        prepStmt.setString(4, attributes.getValue());
                        prepStmt.addBatch();
                        if (log.isDebugEnabled()) {
                            log.debug("Adding attribute: " + attributes.getKey() + " with value: " + 
                                    attributes.getValue() + " for group: " + groupNameWithDomain);
                        }
                    } else {
                        String errorMsg = "Error when adding SCIM Attribute: " + attributes.getKey() +
                                ". An attribute with the same name already exists.";
                        log.error(errorMsg + " Group: " + groupNameWithDomain + " in tenant ID: " + tenantId);
                        throw new IdentitySCIMException(errorMsg);
                    }
                }
            }
            prepStmt.executeBatch();
            connection.commit();
            log.info("Successfully added SCIM attributes to " + attributesList.size() + 
                    " hybrid groups in tenant ID: " + tenantId);
        } catch (SQLException e) {
            log.error("Error when adding SCIM attributes for hybrid groups in tenant ID: " + tenantId, e);
            throw new IdentitySCIMException("Error when adding SCIM attributes for hybrid groups.", e);
        }
    }

    /**
     * Update SCIM group attributes.
     *
     * @param tenantId      Tenant id.
     * @param roleName      Group name.
     * @param attributes    Attributes to be updated.
     * @throws IdentitySCIMException If an error occurred while updating the attributes.
     */
    public void updateSCIMGroupAttributes(int tenantId, String roleName,
                                          Map<String, String> attributes) throws IdentitySCIMException {

        if (log.isDebugEnabled()) {
            log.debug("Updating SCIM attributes for group: " + roleName + " in tenant ID: " + tenantId);
        }
        doUpdateSCIMGroupAttributes(tenantId, roleName, attributes, SQLQueries.UPDATE_ATTRIBUTES_SQL);
    }

    /**
     * Do update SCIM group attributes.
     *
     * @param tenantId      Tenant id.
     * @param roleName      Group name.
     * @param attributes    Attributes to be updated.
     * @param sqlQuery      SQL query to update the attributes.
     * @throws IdentitySCIMException If an error occurred while updating the attributes.
     */
    private void doUpdateSCIMGroupAttributes(int tenantId, String roleName, Map<String, String> attributes,
                                             String sqlQuery) throws IdentitySCIMException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement prepStmt = null;
        String roleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(roleName);

        if (log.isDebugEnabled()) {
            log.debug("Updating SCIM attributes for group: " + roleNameWithDomain + " in tenant ID: " + tenantId + 
                    " with " + attributes.size() + " attributes");
        }

        if (isExistingGroup(roleNameWithDomain, tenantId)) {
            try {
                prepStmt = connection.prepareStatement(sqlQuery);
                prepStmt.setInt(2, tenantId);
                prepStmt.setString(3, roleName);

                for (Map.Entry<String, String> entry : attributes.entrySet()) {
                    if (isExistingAttribute(entry.getKey(), roleNameWithDomain, tenantId)) {
                        prepStmt.setString(4, entry.getKey());
                        prepStmt.setString(1, entry.getValue());
                        prepStmt.addBatch();
                        if (log.isDebugEnabled()) {
                            log.debug("Updating attribute: " + entry.getKey() + " with value: " + entry.getValue() + 
                                    " for group: " + roleNameWithDomain);
                        }
                    } else {
                        String errorMsg = "Error when adding SCIM Attribute: " + entry.getKey() + 
                                " An attribute with the same name doesn't exists.";
                        log.error(errorMsg + " Group: " + roleNameWithDomain + " in tenant ID: " + tenantId);
                        throw new IdentitySCIMException(errorMsg);
                    }
                }
                int[] returnCount = prepStmt.executeBatch();
                if (log.isDebugEnabled()) {
                    log.debug("No. of records updated for updating SCIM Group: " + roleNameWithDomain + 
                            " in tenant ID: " + tenantId + ": " + returnCount.length);
                }
                connection.commit();
                log.info("Successfully updated SCIM attributes for group: " + roleNameWithDomain + 
                        " in tenant ID: " + tenantId);
            } catch (SQLException e) {
                log.error("Error updating SCIM attributes for group: " + roleNameWithDomain + 
                        " in tenant ID: " + tenantId, e);
                throw new IdentitySCIMException("Error updating the SCIM Group Attributes.", e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
            }
        } else {
            String errorMsg = "Error when updating SCIM Attributes for the group: " + roleName + 
                    " A Group with the same name doesn't exists.";
            log.error(errorMsg + " Tenant ID: " + tenantId);
            throw new IdentitySCIMException(errorMsg);
        }
    }

    public void removeSCIMGroup(int tenantId, String roleName) throws IdentitySCIMException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String roleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(roleName);

        if (log.isDebugEnabled()) {
            log.debug("Removing SCIM group: " + roleNameWithDomain + " from tenant ID: " + tenantId);
        }

        try {
            prepStmt = connection.prepareStatement(SQLQueries.DELETE_GROUP_SQL);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, roleNameWithDomain);

            int rowCount = prepStmt.executeUpdate();
            connection.commit();
            
            if (log.isDebugEnabled()) {
                log.debug("Removed " + rowCount + " entries for SCIM group: " + roleNameWithDomain + 
                        " from tenant ID: " + tenantId);
            }
            
            if (rowCount > 0) {
                log.info("Successfully removed SCIM group: " + roleNameWithDomain + " from tenant ID: " + tenantId);
            } else {
                log.warn("No SCIM group attributes found to remove for group: " + roleNameWithDomain + 
                        " in tenant ID: " + tenantId);
            }
        } catch (SQLException e) {
            log.error("Error when removing SCIM group: " + roleNameWithDomain + " from tenant ID: " + tenantId, e);
            throw new IdentitySCIMException("Error deleting the SCIM Group.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    public Map<String, String> getSCIMGroupAttributes(int tenantId, String roleName)
            throws IdentitySCIMException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;
        Map<String, String> attributes = new HashMap<>();
        String roleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(roleName);

        if (log.isDebugEnabled()) {
            log.debug("Retrieving SCIM attributes for group: " + roleNameWithDomain + " in tenant ID: " + tenantId);
        }

        try {
            prepStmt = connection.prepareStatement(SQLQueries.GET_ATTRIBUTES_SQL);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, roleNameWithDomain);

            rSet = prepStmt.executeQuery();
            while (rSet.next()) {
                if (StringUtils.isNotEmpty(rSet.getString(1))) {
                    String attributeName = rSet.getString(1);
                    String attributeValue = rSet.getString(2);
                    attributes.put(attributeName, attributeValue);
                    if (log.isDebugEnabled()) {
                        log.debug("Retrieved attribute: " + attributeName + " with value: " + attributeValue + 
                                " for group: " + roleNameWithDomain);
                    }
                }
            }
            connection.commit();
            
            if (log.isDebugEnabled()) {
                log.debug("Retrieved " + attributes.size() + " SCIM attributes for group: " + 
                        roleNameWithDomain + " in tenant ID: " + tenantId);
            }
        } catch (SQLException e) {
            log.error("Error when retrieving SCIM attributes for group: " + roleNameWithDomain + 
                    " in tenant ID: " + tenantId, e);
            throw new IdentitySCIMException("Error when reading the SCIM Group information from the " +
                    "persistence store.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }
        return attributes;
    }

    /**
     * Get the id of the group with the given name.
     *
     * @param tenantId  Tenant id.
     * @param groupName Name of the group.
     * @return Id of the group with the given name.
     * @throws IdentitySCIMException If an error occurred while getting the group id.
     */
    public String getGroupIdByName(int tenantId, String groupName) throws IdentitySCIMException {

        String groupId = null;
        String groupNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(groupName);

        if (log.isDebugEnabled()) {
            log.debug("Retrieving group ID for group: " + groupNameWithDomain + " in tenant ID: " + tenantId);
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.GET_GROUP_ID_BY_NAME_SQL)) {
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, groupNameWithDomain);
            prepStmt.setString(3, SCIMConstants.CommonSchemaConstants.ID_URI);
            try (ResultSet rs = prepStmt.executeQuery()) {
                while (rs.next()) {
                    groupId = rs.getString(1);
                }
            } catch (SQLException e) {
                log.error("Error when querying group ID for group: " + groupNameWithDomain + 
                        " in tenant ID: " + tenantId, e);
                throw new IdentitySCIMException(String.format("Error when getting the SCIM Group information " +
                        "from the persistence store for group: %s in tenant: %s", groupName, tenantId), e);
            }
            connection.commit();
            
            if (groupId != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved group ID: " + groupId + " for group: " + groupNameWithDomain + 
                            " in tenant ID: " + tenantId);
                }
            } else if (log.isDebugEnabled()) {
                log.debug("No group ID found for group: " + groupNameWithDomain + " in tenant ID: " + tenantId);
            }
        } catch (SQLException e) {
            log.error("Error establishing database connection to retrieve group ID for group: " + 
                    groupNameWithDomain + " in tenant ID: " + tenantId, e);
            throw new IdentitySCIMException(String.format("Error when getting the SCIM Group information from the " +
                    "persistence store for group: %s in tenant: %s", groupName, tenantId), e);
        }
        return groupId;
    }

    public String getGroupNameById(int tenantId, String id) throws IdentitySCIMException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;
        String roleName = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving group name for group ID: " + id + " in tenant ID: " + tenantId);
        }

        try {
            prepStmt = connection.prepareStatement(SQLQueries.GET_GROUP_NAME_BY_ID_SQL);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, id);
            prepStmt.setString(3, SCIMConstants.CommonSchemaConstants.ID_URI);
            rSet = prepStmt.executeQuery();
            while (rSet.next()) {
                //we assume only one result since group id and tenant id is unique.
                roleName = rSet.getString(1);
            }
            connection.commit();
            
            if (StringUtils.isNotEmpty(roleName)) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved group name: " + roleName + " for group ID: " + id + 
                            " in tenant ID: " + tenantId);
                }
            } else if (log.isDebugEnabled()) {
                log.debug("No group name found for group ID: " + id + " in tenant ID: " + tenantId);
            }
        } catch (SQLException e) {
            log.error("Error when retrieving group name for group ID: " + id + " in tenant ID: " + tenantId, e);
            throw new IdentitySCIMException("Error when reading the SCIM Group information from the persistence store.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }
        // Verify whether the roleName is not empty, and it's not contain any prefix Application/Internal
        if (StringUtils.isNotEmpty(roleName) && !SCIMCommonUtils.isHybridRole(roleName)) {
            String primaryFreeGroupName = SCIMCommonUtils.getPrimaryFreeGroupName(roleName);
            if (log.isDebugEnabled()) {
                log.debug("Returning primary-domain-free group name: " + primaryFreeGroupName + 
                        " for group ID: " + id);
            }
            return primaryFreeGroupName;
        }
        
        if (log.isDebugEnabled()) {
            if (StringUtils.isEmpty(roleName)) {
                log.debug("Group name is empty for group ID: " + id + " in tenant ID: " + tenantId);
            } else if (SCIMCommonUtils.isHybridRole(roleName)) {
                log.debug("Group: " + roleName + " is a hybrid role, not returning for group ID: " + id);
            }
        }
        
        return null;
    }

    public void updateRoleName(int tenantId, String oldRoleName, String newRoleName)
            throws IdentitySCIMException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String oldRoleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(oldRoleName);
        String newRoleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(newRoleName);

        if (log.isDebugEnabled()) {
            log.debug("Updating role name from: " + oldRoleNameWithDomain + " to: " + newRoleNameWithDomain + 
                    " in tenant ID: " + tenantId);
        }

        if (isExistingGroup(oldRoleNameWithDomain, tenantId)) {
            try {
                prepStmt = connection.prepareStatement(SQLQueries.UPDATE_GROUP_NAME_SQL);

                prepStmt.setString(1, newRoleNameWithDomain);
                prepStmt.setInt(2, tenantId);
                prepStmt.setString(3, oldRoleNameWithDomain);

                int count = prepStmt.executeUpdate();
                if (log.isDebugEnabled()) {
                    log.debug("Updated " + count + " records for group: " + oldRoleNameWithDomain + 
                            " to new name: " + newRoleNameWithDomain + " in tenant ID: " + tenantId);
                }
                
                if (count > 0) {
                    log.info("Successfully updated role name from: " + oldRoleNameWithDomain + 
                            " to: " + newRoleNameWithDomain + " in tenant ID: " + tenantId);
                } else {
                    log.warn("No records were updated when changing role name from: " + oldRoleNameWithDomain + 
                            " to: " + newRoleNameWithDomain + " in tenant ID: " + tenantId);
                }
                
                connection.commit();
            } catch (SQLException e) {
                log.error("Error updating role name from: " + oldRoleNameWithDomain + " to: " + 
                        newRoleNameWithDomain + " in tenant ID: " + tenantId, e);
                throw new IdentitySCIMException("Error updating the SCIM Group Attributes", e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
            }
        } else {
            String errorMsg = "Error when updating role name of the role: " + oldRoleName;
            log.error(errorMsg + ". Group does not exist in tenant ID: " + tenantId);
            throw new IdentitySCIMException(errorMsg);
        }
    }

    /**
     * Lists the Groups created from SCIM with a attribute filter and search regex
     *
     * @param searchAttributeName  Search attribute name.
     * @param searchAttributeValue Search attribute value.
     * @param tenantId             Tenant ID.
     * @return list of SCIM groups
     * @throws IdentitySCIMException
     * @since 1.2.44
     * @deprecated Method does not support domain filtering. Use
     * {@link org.wso2.carbon.identity.scim2.common.DAO.GroupDAO#getGroupNameList(String, String, Integer, String)}
     */
    @Deprecated
    public String[] getGroupNameList(String searchAttributeName, String searchAttributeValue, Integer tenantId)
            throws IdentitySCIMException {

        List<String> roleList = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection
                    .prepareStatement(SQLQueries.LIST_SCIM_GROUPS_SQL_BY_ATT_AND_ATT_VALUE)) {

                prepStmt.setInt(1, tenantId);
                prepStmt.setString(2, searchAttributeName);
                prepStmt.setString(3, searchAttributeValue);

                try (ResultSet rSet = prepStmt.executeQuery()) {
                    while (rSet.next()) {
                        String roleName = rSet.getString(1);
                        if (StringUtils.isNotEmpty(roleName)) {
                            if (!roleName.toLowerCase().contains(UserCoreConstants.INTERNAL_DOMAIN.toLowerCase())
                                    && roleName.contains(CarbonConstants.DOMAIN_SEPARATOR)) {
                                String[] parts = roleName.split(CarbonConstants.DOMAIN_SEPARATOR);
                                roleList.add(parts[parts.length - 1]);
                            } else {
                                roleList.add(roleName);
                            }
                        }
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + SQLQueries.LIST_SCIM_GROUPS_SQL_BY_ATT_AND_ATT_VALUE);
            throw new IdentitySCIMException("Error when reading the SCIM Group information from the persistence store.",
                    e);
        }
        return roleList.toArray(new String[roleList.size()]);
    }

    /**
     * List the groups created from SCIM with a attribute filter and search regex.
     *
     * @param searchAttributeName  Search attribute name.
     * @param searchAttributeValue Search attribute value.
     * @param tenantId             Tenant ID.
     * @param domainName           Domain that needs to be filtered.
     * @return List of SCIM groups.
     * @throws IdentitySCIMException IdentitySCIMException when reading the SCIM Group information.
     */
    public String[] getGroupNameList(String searchAttributeName, String searchAttributeValue, Integer tenantId,
            String domainName) throws IdentitySCIMException {

        List<String> roleList = new ArrayList<>();
        String sqlQuery;

        // Resolve sql query for filtering.
        if (StringUtils.isNotEmpty(domainName)) {
            // if the domain is given, domain needs to be searched in ROLE_NAME column as well.
            sqlQuery = SQLQueries.LIST_SCIM_GROUPS_SQL_BY_ATT_AND_ATT_VALUE_AND_ROLE_NAME;
        } else {
            sqlQuery = SQLQueries.LIST_SCIM_GROUPS_SQL_BY_ATT_AND_ATT_VALUE;
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(sqlQuery)) {
                prepStmt.setInt(1, tenantId);
                prepStmt.setString(2, searchAttributeName);
                prepStmt.setString(3, searchAttributeValue);

                // Append SQL_FILTERING_DELIMITER to ROLE_NAME param to filter in a given domain.
                if (StringUtils.isNotEmpty(domainName)) {
                    prepStmt.setString(4, domainName.toUpperCase() + "%");
                }
                try (ResultSet rSet = prepStmt.executeQuery()) {
                    while (rSet.next()) {
                        String roleName = rSet.getString(1);
                        if (StringUtils.isNotEmpty(roleName)) {
                            // Remove the primary domain name from roleNames.
                            roleList.add(removePrimaryDomainName(roleName));
                        }
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sqlQuery);
            throw new IdentitySCIMException("Error when reading the SCIM Group information from the persistence store.",
                    e);
        }
        return roleList.toArray(new String[0]);
    }

    /**
     * List the groups created from SCIM with the group name filter.
     *
     * @param tenantId        Tenant ID.
     * @param groupNameFilter Group name filter to be applied.
     * @return List of SCIM group names.
     * @throws IdentitySCIMException If an error occurred while reading the SCIM Group information.
     */
    public String[] getGroupNameList(Integer tenantId, String groupNameFilter)
            throws IdentitySCIMException {

        List<String> roleList = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(
                    SQLQueries.LIST_SCIM_GROUPS_SQL_BY_ROLE_NAME)) {
                prepStmt.setInt(1, tenantId);
                prepStmt.setString(2, groupNameFilter);

                try (ResultSet rSet = prepStmt.executeQuery()) {
                    while (rSet.next()) {
                        String roleName = rSet.getString(1);
                        if (StringUtils.isNotEmpty(roleName)) {
                            // Remove the primary domain name from roleNames.
                            roleList.add(removePrimaryDomainName(roleName));
                        }
                    }
                }
            }
        } catch (SQLException e) {
            throw new IdentitySCIMException("Error when reading the SCIM Group information from the persistence store.",
                    e);
        }
        return roleList.toArray(new String[0]);
    }

    /**
     * Remove the primary domain name from the display names of groups in the primary user store to maintain
     * consistency.
     *
     * @param roleName Role names with Domain
     * @return Role names.
     */
    private String removePrimaryDomainName(String roleName) {

        // If a domain is embedded, then the length would equal to 2. The first element of the array will be the
        // domain name.
        String[] domainSplitFromRoleName = roleName.split(CarbonConstants.DOMAIN_SEPARATOR, 2);

        // Length equal to one would imply that no domain separator is included in the roleName.
        if (domainSplitFromRoleName.length > 1) {
            if (UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(domainSplitFromRoleName[0])) {
                return domainSplitFromRoleName[1];
            } else {
                return roleName;
            }
        } else {
            return roleName;
        }
    }
}
