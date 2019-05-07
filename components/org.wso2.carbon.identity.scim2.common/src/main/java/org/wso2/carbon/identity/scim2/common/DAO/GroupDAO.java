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

    private static Log log = LogFactory.getLog(GroupDAO.class);

    /**
     * Lists the groups that are created from SCIM
     *
     * @return The set of groups that were created from SCIM
     * @throws IdentitySCIMException
     */
    public Set<String> listSCIMGroups() throws IdentitySCIMException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Set<String> groups = new HashSet<>();

        try {
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
        } catch (SQLException e) {
            throw new IdentitySCIMException("Error when reading the SCIM Group information from persistence store.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return groups;
    }

    public boolean isExistingGroup(String groupName, int tenantId) throws IdentitySCIMException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;

        boolean isExistingGroup = false;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.CHECK_EXISTING_ATTRIBUTE_SQL);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, SCIMCommonUtils.getGroupNameWithDomain(groupName));

            // Specifically checking SCIM 2.0 ID attribute to avoid conflict with SCIM 1.1
            prepStmt.setString(3, SCIMConstants.CommonSchemaConstants.ID_URI);

            rSet = prepStmt.executeQuery();
            if (rSet.next()) {
                isExistingGroup = true;
            }
            connection.commit();
        } catch (SQLException e) {
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

        try {
            prepStmt = connection.prepareStatement(SQLQueries.CHECK_EXISTING_ATTRIBUTE_SQL);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, SCIMCommonUtils.getGroupNameWithDomain(groupName));
            prepStmt.setString(3, attributeName);

            rSet = prepStmt.executeQuery();
            if (rSet.next()) {
                isExistingAttribute = true;
            }
            connection.commit();
        } catch (SQLException e) {
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

        if (!isExistingGroup(SCIMCommonUtils.getGroupNameWithDomain(roleName), tenantId)) {
            try {
                prepStmt = connection.prepareStatement(SQLQueries.ADD_ATTRIBUTES_SQL);
                prepStmt.setInt(1, tenantId);
                prepStmt.setString(2, roleName);

                for (Map.Entry<String, String> entry : attributes.entrySet()) {
                    if (!isExistingAttribute(entry.getKey(),
                            SCIMCommonUtils.getGroupNameWithDomain(roleName), tenantId)) {
                        prepStmt.setString(3, entry.getKey());
                        prepStmt.setString(4, entry.getValue());
                        prepStmt.addBatch();

                    } else {
                        throw new IdentitySCIMException("Error when adding SCIM Attribute: "
                                + entry.getKey()
                                + " An attribute with the same name already exists.");
                    }
                }
                prepStmt.executeBatch();
                connection.commit();

            } catch (SQLException e) {
                throw new IdentitySCIMException("Error when adding SCIM attributes for the group: "
                        + roleName, e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
            }
        } else {
            throw new IdentitySCIMException("Error when adding SCIM Attributes for the group: "
                    + roleName + " A Group with the same name already exists.");
        }
    }

    public void updateSCIMGroupAttributes(int tenantId, String roleName,
                                          Map<String, String> attributes) throws IdentitySCIMException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        if (isExistingGroup(SCIMCommonUtils.getGroupNameWithDomain(roleName), tenantId)) {
            try {
                prepStmt = connection.prepareStatement(SQLQueries.UPDATE_ATTRIBUTES_SQL);

                prepStmt.setInt(2, tenantId);
                prepStmt.setString(3, roleName);

                for (Map.Entry<String, String> entry : attributes.entrySet()) {
                    if (isExistingAttribute(entry.getKey(),
                            SCIMCommonUtils.getGroupNameWithDomain(roleName), tenantId)) {
                        prepStmt.setString(4, entry.getKey());
                        prepStmt.setString(1, entry.getValue());
                        prepStmt.addBatch();

                    } else {
                        throw new IdentitySCIMException("Error when adding SCIM Attribute: "
                                + entry.getKey()
                                + " An attribute with the same name doesn't exists.");
                    }
                }
                int[] return_count = prepStmt.executeBatch();
                if (log.isDebugEnabled()) {
                    log.debug("No. of records updated for updating SCIM Group : " + return_count.length);
                }
                connection.commit();

            } catch (SQLException e) {
                throw new IdentitySCIMException("Error updating the SCIM Group Attributes.", e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
            }
        } else {
            throw new IdentitySCIMException("Error when updating SCIM Attributes for the group: "
                    + roleName + " A Group with the same name doesn't exists.");
        }
    }

    public void removeSCIMGroup(int tenantId, String roleName) throws IdentitySCIMException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.DELETE_GROUP_SQL);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, SCIMCommonUtils.getGroupNameWithDomain(roleName));

            prepStmt.execute();
            connection.commit();

        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + SQLQueries.DELETE_GROUP_SQL);
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

        try {
            prepStmt = connection.prepareStatement(SQLQueries.GET_ATTRIBUTES_SQL);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, SCIMCommonUtils.getGroupNameWithDomain(roleName));

            rSet = prepStmt.executeQuery();
            while (rSet.next()) {
                if (StringUtils.isNotEmpty(rSet.getString(1))) {
                    attributes.put(rSet.getString(1), rSet.getString(2));
                }
            }
            connection.commit();
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + SQLQueries.GET_ATTRIBUTES_SQL);
            throw new IdentitySCIMException("Error when reading the SCIM Group information from the " +
                    "persistence store.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }
        return attributes;
    }

    public String getGroupNameById(int tenantId, String id) throws IdentitySCIMException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;
        String roleName = null;

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
        } catch (SQLException e) {
            throw new IdentitySCIMException("Error when reading the SCIM Group information from the persistence store.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }
        if (StringUtils.isNotEmpty(roleName)) {
            return SCIMCommonUtils.getPrimaryFreeGroupName(roleName);
        }
        return null;
    }

    public void updateRoleName(int tenantId, String oldRoleName, String newRoleName)
            throws IdentitySCIMException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        if (isExistingGroup(SCIMCommonUtils.getGroupNameWithDomain(oldRoleName), tenantId)) {
            try {
                prepStmt = connection.prepareStatement(SQLQueries.UPDATE_GROUP_NAME_SQL);

                prepStmt.setString(1, SCIMCommonUtils.getGroupNameWithDomain(newRoleName));
                prepStmt.setInt(2, tenantId);
                prepStmt.setString(3, SCIMCommonUtils.getGroupNameWithDomain(oldRoleName));

                int count = prepStmt.executeUpdate();
                if (log.isDebugEnabled()) {
                    log.debug("No. of records updated for updating SCIM Group : " + count);
                }
                connection.commit();
            } catch (SQLException e) {
                throw new IdentitySCIMException("Error updating the SCIM Group Attributes", e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
            }
        } else {
            throw new IdentitySCIMException("Error when updating role name of the role: " + oldRoleName);
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
        return roleList.toArray(new String[roleList.size()]);
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
