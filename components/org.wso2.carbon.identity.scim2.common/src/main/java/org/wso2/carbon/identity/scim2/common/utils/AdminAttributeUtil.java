/*
 * Copyright (c) 2017-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.scim2.common.utils;


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.mgt.core.util.UserIDResolver;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.stratos.common.util.ClaimsMgtUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.AttributeUtil;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


/**
 * AdminAttributeUtil for managing the admin user's and group's SCIM attributes.
 */
public class AdminAttributeUtil {

    private static final Log log = LogFactory.getLog(AdminAttributeUtil.class);

    /**
     * Update admin user attribute under given tenant.
     *
     * @param tenantId
     *         is tenant unique id that we need to update the admin user.
     * @param validateSCIMID
     *         is allow to validate the existing SCIm ID before do the updates.
     */
    public static void updateAdminUser(int tenantId, boolean validateSCIMID) {

        try {
            UserStoreManager userStoreManager = (UserStoreManager) SCIMCommonComponentHolder.getRealmService().
                            getTenantUserRealm(tenantId).getUserStoreManager();
            if (log.isDebugEnabled()) {
                log.debug("SCIM enable in Userstore level : " + userStoreManager.isSCIMEnabled() + ", for "
                          + "Tenant ID : " + tenantId + ", validating for the existing SCIM ID : " + validateSCIMID);
            }
            //User store level property to enable/disable SCIM
            if (userStoreManager.isSCIMEnabled()) {
                String adminUsername = ClaimsMgtUtil.getAdminUserNameFromTenantId(IdentityTenantUtil.getRealmService(),
                                                                                  tenantId);
                //Validate for existing SCIM ID before do the update for admin user.
                if (validateSCIMID) {
                    String scimId = userStoreManager.getUserClaimValue(adminUsername, SCIMConstants
                            .CommonSchemaConstants.ID_URI, UserCoreConstants.DEFAULT_PROFILE);
                    if (log.isDebugEnabled()) {
                        log.debug("Existing SCIM ID : " + scimId + " for Admin User : " + adminUsername + " in "
                                  + "Tenant ID : " +
                                  tenantId);
                    }
                    if (StringUtils.isEmpty(scimId)) {
                        //Generate User Attributes.
                        Map<String, String> scimClaims = generateSCIMClaims(adminUsername);
                        userStoreManager
                                .setUserClaimValues(adminUsername, scimClaims, UserCoreConstants.DEFAULT_PROFILE);
                    }
                } else {
                    //No validation before do the update for admin user.
                    Map<String, String> scimClaims = generateSCIMClaims(adminUsername);
                    userStoreManager.setUserClaimValues(adminUsername, scimClaims, UserCoreConstants.DEFAULT_PROFILE);
                }
            }
        } catch (Exception e) {
            log.error("Error occurred while updating the admin user's attributes in Tenant ID : " + tenantId + ", "
                      + "Error : " + e.getMessage(), e);
        }
    }

    /**
     * Update admin group for given tenant.
     *
     * @param tenantId
     */
    public static void updateAdminGroup(int tenantId) {
        try {
            UserStoreManager userStoreManager = (UserStoreManager) SCIMCommonComponentHolder.getRealmService().
                    getTenantUserRealm(tenantId).getUserStoreManager();
            if (log.isDebugEnabled()) {
                log.debug("SCIM enable in Userstore level : " + userStoreManager.isSCIMEnabled() + ", for "
                          + "Tenant ID : " + tenantId);
            }
            //User store level property to enable/disable SCIM
            if (userStoreManager.isSCIMEnabled()) {
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(userStoreManager.getTenantId());
                String domainName = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
                if (domainName == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Domain name is null and setting default domain as "
                                  + IdentityUtil.getPrimaryDomainName());
                    }
                    domainName = IdentityUtil.getPrimaryDomainName();
                }

                String adminRoleName = userStoreManager.getRealmConfiguration().getAdminRoleName();
                String roleNameWithDomain = UserCoreUtil.addDomainToName(adminRoleName, domainName);
                // UserCore Util functionality does not append primary domain.
                roleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(roleNameWithDomain);
                try {
                    // Validate the SCIM ID is available for Groups.
                    if (!scimGroupHandler.isGroupExisting(roleNameWithDomain) &&
                            ((AbstractUserStoreManager) userStoreManager).isRoleAndGroupSeparationEnabled()) {
                        // Adding the SCIM attributes to internal roles in user core (ex. Internal/admin).
                        // This admin role is introduced after the role and group separation was introduced.
                        // These are mapped to roles in SCIM
                        if (log.isDebugEnabled()) {
                            log.debug(
                                    "Group does not exist, setting scim attribute group value: " + roleNameWithDomain);
                        }
                        if (CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME) {
                            scimGroupHandler.addMandatoryAttributes(roleNameWithDomain);
                        } else {
                            scimGroupHandler.addRoleV2MandatoryAttributes(roleNameWithDomain);
                        }
                    }

                    // Adding the SCIM attributes for admin group
                    String groupNameWithDomain = getAdminGroupName(adminRoleName, domainName);
                    // Validate the SCIM ID is available for groups.
                    if (userStoreManager.isExistingRole(groupNameWithDomain) && !scimGroupHandler
                            .isGroupExisting(groupNameWithDomain)) {
                        // Adding the SCIM attributes to userstore roles in user core (ex. PRIMARY/admin).
                        // This admin role was available before the role and group separation was introduced.
                        // These are mapped to groups in SCIM
                        if (log.isDebugEnabled()) {
                            log.debug("Group does not exist, setting scim attributes for group: "
                                    + groupNameWithDomain);
                        }
                        scimGroupHandler.addMandatoryAttributes(groupNameWithDomain);
                    }
                } catch (IdentitySCIMException e) {
                    throw new UserStoreException(
                            "Error retrieving group information from SCIM Tables for tenant ID: " + userStoreManager
                                    .getTenantId(), e);
                }
            }
        } catch (Exception e) {
            log.error("Error occurred while updating the admin groups's attributes in Tenant ID : " + tenantId + ", "
                      + "Error : " + e.getMessage(), e);
        }
    }

    /**
     * This will derive the admin group name.
     *
     * @param adminRoleName Admin role name.
     * @param domainName    Domain name.
     * @return Admin group name.
     */
    private static String getAdminGroupName(String adminRoleName, String domainName) {

        String adminGroupName = UserCoreUtil.removeDomainFromName(adminRoleName);
        String groupNameWithDomain = UserCoreUtil.addDomainToName(adminGroupName, domainName);
        // UserCore Util functionality does not append primary domain.
        groupNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(groupNameWithDomain);
        return groupNameWithDomain;
    }

/**
     * Get super admin ID.
     *
     * @return Super admin ID.
     */
    public static String getSuperAdminID() throws CharonException {

        try {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            RealmService realmService = SCIMCommonComponentHolder.getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
            RealmConfiguration realmConfig = userRealm.getRealmConfiguration();
            String adminUser = realmConfig.getAdminUserName();

            UserIDResolver userIDResolver = new UserIDResolver();
            String adminUserID = userIDResolver.getIDByName(adminUser, tenantDomain);

            return adminUserID;

        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new CharonException("Error obtaining user realm.", e);
        } catch (IdentityRoleManagementException e) {
            throw new CharonException("Error occurred while retrieving super admin ID.", e);
        }
    }

    /**
     * Generate new SCIM ID and create the claim mappings.
     *
     * @param userName
     * @return
     */
    private static Map<String, String> generateSCIMClaims(String userName) {

        Map<String, String> claimsList = new HashMap<>();

        // Generating new SCIM ID.
        String id = UUID.randomUUID().toString();
        if (log.isDebugEnabled()) {
            log.debug("Generated SCIM ID : " + id + " for User : " + userName);
        }

        String createdDate = AttributeUtil.formatDateTime(Instant.now());
        claimsList.put(SCIMConstants.CommonSchemaConstants.CREATED_URI, createdDate);
        claimsList.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, createdDate);
        if (log.isDebugEnabled()) {
            for (Map.Entry<String, String> entry : claimsList.entrySet()) {
                log.debug("SCIM URI : " + entry.getKey() + " >> Value : " + entry.getValue());
            }
        }
        return claimsList;
    }
}
