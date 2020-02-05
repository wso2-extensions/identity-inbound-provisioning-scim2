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

package org.wso2.carbon.identity.scim2.common.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.AttributeUtil;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * This is to perform SCIM related operation on User Operations.
 * For eg: when a user is created through UserAdmin API, we need to set some SCIM specific properties
 * as user attributes.
 */
public class SCIMUserOperationListener extends AbstractIdentityUserOperationEventListener {

    private static final Log log = LogFactory.getLog(SCIMUserOperationListener.class);

    @Override
    public int getExecutionOrderId() {

        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 90;
    }

    @Override
    public boolean doPreAddUserWithID(String userID, Object credential, String[] roleList, Map<String, String> claims,
                                      String profile, UserStoreManager userStoreManager) throws UserStoreException {

        try {
            if (!isEnable() || userStoreManager == null || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
            this.populateSCIMAttributes(userID, claims);
            return true;
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }
    }

    @Override
    public boolean doPostAddUserWithID(User user, Object credential, String[] roleList, Map<String, String> claims,
                                       String profile, UserStoreManager userStoreManager) throws UserStoreException {

        try {
            if (!isEnable() || userStoreManager == null || !userStoreManager.isSCIMEnabled()) {
                return true;
            }

            Map<String, String> scimToLocalMappings = SCIMCommonUtils.getSCIMtoLocalMappings();
            String userIdLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants.ID_URI);

            Pattern pattern = Pattern.compile("urn:.*scim:schemas:core:.\\.0:id");
            boolean containsSCIMIdClaim = false;
            for (String claimUri : claims.keySet()) {
                if (pattern.matcher(claimUri).matches()) {
                    containsSCIMIdClaim = true;
                    break;
                }
                if (StringUtils.equals(claimUri, userIdLocalClaimUri)) {
                    containsSCIMIdClaim = true;
                    break;
                }
            }

            // If the SCIM ID claims is already there, we don't need to re-generate it.
            if (!containsSCIMIdClaim) {
                if (StringUtils.isBlank(user.getUserID())) {
                    String userId = UUID.randomUUID().toString();
                    claims.put(userIdLocalClaimUri, userId);
                    userStoreManager.setUserClaimValue(user.getUsername(), userIdLocalClaimUri, userId,
                            UserCoreConstants.DEFAULT_PROFILE);
                } else {
                    claims.put(userIdLocalClaimUri, user.getUserID());
                    ((AbstractUserStoreManager) userStoreManager).setUserClaimValueWithID(user.getUserID(),
                            userIdLocalClaimUri, user.getUserID(), UserCoreConstants.DEFAULT_PROFILE);
                }
            }
            return true;
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isSCIMEnabled from user store manager", e);
        }
    }

    @Override
    public boolean doPostUpdateCredentialWithID(String userId, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {
        return doPostUpdateCredentialByAdminWithID(userId, credential, userStoreManager);
    }

    @Override
    public boolean doPostUpdateCredentialByAdminWithID(String userID, Object credential,
                                                       UserStoreManager userStoreManager) throws UserStoreException {

        try {
            if (!isEnable() || userStoreManager == null || !userStoreManager.isSCIMEnabled()
                    || !(userStoreManager instanceof AbstractUserStoreManager)) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        // Update last-modified-date.
        try {
            AbstractUserStoreManager abstractUserStoreManager = (AbstractUserStoreManager) userStoreManager;
            String lastModifiedDate = AttributeUtil.formatDateTime(Instant.now());
            abstractUserStoreManager.setUserClaimValueWithID(
                    userID, SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, lastModifiedDate, null);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (e.getMessage().contains("UserNotFound")) {
                if (log.isDebugEnabled()) {
                    log.debug("User " + userID + " doesn't exist");
                }
            } else {
                throw new UserStoreException("Error updating SCIM metadata in doPostUpdateCredentialByAdmin " +
                        "listener", e);
            }
        }
        return true;
    }

    @Override
    public boolean doPostSetUserClaimValueWithID(String s, UserStoreManager userStoreManager)
            throws UserStoreException {
        //TODO: need to set last modified time.
        return true;
    }

    @Override
    public boolean doPreSetUserClaimValuesWithID(String userID, Map<String, String> claims, String profileName,
                                                 UserStoreManager userStoreManager) throws UserStoreException {
        try {
            if (!isEnable() || userStoreManager == null || !userStoreManager.isSCIMEnabled()
                    || userStoreManager.isReadOnly()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        String lastModifiedDate = AttributeUtil.formatDateTime(Instant.now());
        Map<String, String> scimToLocalMappings = SCIMCommonUtils.getSCIMtoLocalMappings();
        String modifiedLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI);
        claims.put(modifiedLocalClaimUri, lastModifiedDate);
        return true;
    }

    @Override
    public boolean doPostAddInternalRoleWithID(String roleName, String[] userList, org.wso2.carbon.user.api.Permission[]
            permissions, UserStoreManager userStoreManager) throws UserStoreException {

        return doPostAddRoleWithID(roleName, userList, permissions, userStoreManager);
    }

    @Override
    public boolean doPostAddRoleWithID(String roleName, String[] userList,
                                       org.wso2.carbon.user.api.Permission[] permissions,
                                       UserStoreManager userStoreManager) throws UserStoreException {

        try {
            if (!isEnable() || userStoreManager == null) {
                return true;
            } else if (!userStoreManager.isSCIMEnabled() && SCIMCommonUtils.isHybridRole(roleName)) {
                log.info("Persisting SCIM metadata for hybrid role: " + roleName + ", created while SCIM is " +
                        "disabled in the user store.");
                return postAddRole(roleName, userStoreManager);
            } else if (!userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        return postAddRole(roleName, userStoreManager);
    }

    private boolean postAddRole(String roleName, UserStoreManager userStoreManager) throws UserStoreException {

        try {

            SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(userStoreManager.getTenantId());

            String domainName = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
            if (domainName == null) {
                domainName = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
            }
            String roleNameWithDomain = UserCoreUtil.addDomainToName(roleName, domainName);
            // UserCore Util functionality does not append primary.
            roleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(roleNameWithDomain);

            // Query role name from identity table.
            try {
                if (!scimGroupHandler.isGroupExisting(roleNameWithDomain)) {
                    // If no attributes - i.e: group added via mgt console, not via SCIM endpoint.
                    // Add META.
                    scimGroupHandler.addMandatoryAttributes(roleNameWithDomain);
                }
            } catch (IdentitySCIMException e) {
                throw new UserStoreException("Error retrieving group information from SCIM Tables.", e);
            }

            return true;

        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException(e);
        }
    }

    @Override
    public boolean doPreDeleteInternalRole(String roleName, UserStoreManager userStoreManager) throws
            UserStoreException {

        return doPreDeleteRole(roleName, userStoreManager);
    }

    @Override
    public boolean doPreDeleteRole(String roleName, UserStoreManager userStoreManager) throws UserStoreException {

        try {
            if (!isEnable() || userStoreManager == null || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        try {
            SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(userStoreManager.getTenantId());

            String domainName = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
            if (domainName == null) {
                domainName = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
            }
            String roleNameWithDomain = IdentityUtil.addDomainToName(roleName, domainName);
            try {
                // Delete group attributes - no need to check existence here, since it is checked in below method.
                scimGroupHandler.deleteGroupAttributes(roleNameWithDomain);
            } catch (IdentitySCIMException e) {
                throw new UserStoreException("Error retrieving group information from SCIM Tables.", e);
            }
            return true;

        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException(e);
        }
    }

    @Override
    public boolean doPostUpdateInternalRoleName(String roleName, String newRoleName, UserStoreManager userStoreManager)
            throws UserStoreException {

        return doPostUpdateRoleName(roleName, newRoleName, userStoreManager);
    }

    @Override
    public boolean doPostUpdateRoleName(String roleName, String newRoleName, UserStoreManager userStoreManager)
            throws UserStoreException {

        try {
            if (!isEnable() || userStoreManager == null || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        try {
            //TODO:set last update date
            SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(userStoreManager.getTenantId());

            String domainName = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
            if (domainName == null) {
                domainName = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
            }
            String roleNameWithDomain = UserCoreUtil.addDomainToName(roleName, domainName);
            String newRoleNameWithDomain = UserCoreUtil.addDomainToName(newRoleName, domainName);
            try {
                scimGroupHandler.updateRoleName(roleNameWithDomain, newRoleNameWithDomain);
            } catch (IdentitySCIMException e) {
                throw new UserStoreException("Error updating group information in SCIM Tables.", e);
            }
            return true;
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException(e);
        }
    }

    @Deprecated
    public Map<String, String> getSCIMAttributes(String userName, Map<String, String> claimsMap) {
        return populateSCIMAttributes(userName, claimsMap);
    }

    /**
     * Populate SCIM Attributes map.
     *
     * @param userId  userName
     * @param claimsMap claimsMap
     * @return attributes map
     */
    public Map<String, String> populateSCIMAttributes(String userId, Map<String, String> claimsMap) {

        Map<String, String> attributes;
        if (claimsMap != null) {
            attributes = claimsMap;
        } else {
            attributes = new HashMap<>();
        }

        try {
            Map<String, String> scimToLocalMappings = SCIMCommonUtils.getSCIMtoLocalMappings();
            String createdLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants.CREATED_URI);
            String modifiedLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants
                    .LAST_MODIFIED_URI);
            String resourceTypeLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants
                    .RESOURCE_TYPE_URI);

            String createdDate = AttributeUtil.formatDateTime(Instant.now());
            attributes.put(createdLocalClaimUri, createdDate);
            attributes.put(modifiedLocalClaimUri, createdDate);
            attributes.put(resourceTypeLocalClaimUri, SCIMConstants.USER);
        } catch (UserStoreException ex) {
            log.error("Error occurred while retrieving SCIM-to-Local claims map.", ex);
        }
        return attributes;
    }
}
