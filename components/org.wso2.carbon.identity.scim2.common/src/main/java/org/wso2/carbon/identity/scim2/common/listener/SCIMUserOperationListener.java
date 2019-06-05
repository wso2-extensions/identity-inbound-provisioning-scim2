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
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.AttributeUtil;

import java.time.Instant;
import java.util.Date;
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

    private static Log log = LogFactory.getLog(SCIMUserOperationListener.class);

    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 90;
    }

    @Override
    public boolean doPreAuthenticate(String s, Object o, UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostAuthenticate(String userName, boolean authenticated, UserStoreManager userStoreManager)
            throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPreAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
                                String profile, UserStoreManager userStoreManager) throws UserStoreException {
        try {
            if (!isEnable() || userStoreManager == null || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }
        this.populateSCIMAttributes(userName, claims);
        return true;
    }

    @Override
    public boolean doPostAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
                                 String profile, UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPreUpdateCredential(String s, Object o, Object o1, UserStoreManager userStoreManager)
            throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostUpdateCredential(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {
        return doPostUpdateCredentialByAdmin(userName, credential, userStoreManager);
    }

    @Override
    public boolean doPreUpdateCredentialByAdmin(String s, Object o, UserStoreManager userStoreManager)
            throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostUpdateCredentialByAdmin(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {
        try {
            if (!isEnable() || userStoreManager == null || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        // Update last-modified-date.
        try {
            String lastModifiedDate = AttributeUtil.formatDateTime(Instant.now());
            userStoreManager.setUserClaimValue(
                    userName, SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, lastModifiedDate, null);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (e.getMessage().contains("UserNotFound")) {
                if (log.isDebugEnabled()) {
                    log.debug("User " + userName + " doesn't exist");
                }
            } else {
                throw new UserStoreException("Error updating SCIM metadata in doPostUpdateCredentialByAdmin " +
                        "listener", e);
            }
        }
        return true;
    }

    @Override
    public boolean doPreDeleteUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostDeleteUser(String s, UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPreSetUserClaimValue(String s, String s1, String s2, String s3, UserStoreManager
            userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostSetUserClaimValue(String s, UserStoreManager userStoreManager) throws UserStoreException {
        //TODO: need to set last modified time.
        return true;
    }

    @Override
    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                           UserStoreManager userStoreManager) throws UserStoreException {
        try {
            if (!isEnable() || userStoreManager == null || !userStoreManager.isSCIMEnabled() || userStoreManager
                    .isReadOnly()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        String lastModifiedDate = AttributeUtil.formatDateTime(Instant.now());
        claims.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, lastModifiedDate);

        return true;
    }

    @Override
    public boolean doPostSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                            UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPreDeleteUserClaimValues(String s, String[] strings, String s1, UserStoreManager userStoreManager)
            throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostDeleteUserClaimValues(String s, UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPreDeleteUserClaimValue(String s, String s1, String s2, UserStoreManager userStoreManager)
            throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostDeleteUserClaimValue(String s, UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPreAddRole(String s, String[] strings, org.wso2.carbon.user.api.Permission[] permissions,
                                UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostAddInternalRole(String roleName, String[] userList, org.wso2.carbon.user.api.Permission[]
            permissions, UserStoreManager userStoreManager) throws UserStoreException {

        return doPostAddRole(roleName, userList, permissions, userStoreManager);
    }

    @Override
    public boolean doPostAddRole(String roleName, String[] userList, org.wso2.carbon.user.api.Permission[] permissions,
                                 UserStoreManager userStoreManager) throws UserStoreException {
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
                //delete group attributes - no need to check existence here,
                //since it is checked in below method.
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
    public boolean doPostDeleteRole(String roleName, UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPreUpdateRoleName(String s, String s1, UserStoreManager userStoreManager)
            throws UserStoreException {
        return true;
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

    @Override
    public boolean doPreUpdateUserListOfRole(String s, String[] strings, String[] strings1,
                                             UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostUpdateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers,
                                              UserStoreManager userStoreManager) throws UserStoreException {
        return true;

    }

    @Override
    public boolean doPreUpdateRoleListOfUser(String s, String[] strings, String[] strings1,
                                             UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPostUpdateRoleListOfUser(String s, String[] strings, String[] strings1,
                                              UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Deprecated
    public Map<String, String> getSCIMAttributes(String userName, Map<String, String> claimsMap) {
        return populateSCIMAttributes(userName, claimsMap);
    }

    /**
     * Populate SCIM Attributes map.
     *
     * @param userName  userName
     * @param claimsMap claimsMap
     * @return attributes map
     */
    public Map<String, String> populateSCIMAttributes(String userName, Map<String, String> claimsMap) {
        Map<String, String> attributes;
        if (claimsMap != null) {
            attributes = claimsMap;
        } else {
            attributes = new HashMap<>();
        }

        try {
            Map<String, String> scimToLocalMappings = SCIMCommonUtils.getSCIMtoLocalMappings();
            String userIdLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants.ID_URI);
            String createdLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants.CREATED_URI);
            String modifiedLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI);
            String usernameLocalClaimUri = scimToLocalMappings.get(SCIMConstants.UserSchemaConstants.USER_NAME_URI);
            String resourceTypeLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants
                    .RESOURCE_TYPE_URI);

            Pattern pattern = Pattern.compile("urn:.*scim:schemas:core:.\\.0:id");
            boolean containsScimIdClaim = false;
            for (String claimUri : attributes.keySet()) {
                if (pattern.matcher(claimUri).matches()) {
                    containsScimIdClaim = true;
                    break;
                }
                if (StringUtils.equals(claimUri, userIdLocalClaimUri)) {
                    containsScimIdClaim = true;
                    break;
                }
            }
            if (!containsScimIdClaim) {
                String id = UUID.randomUUID().toString();
                attributes.put(userIdLocalClaimUri, id);
            }

            String createdDate = AttributeUtil.formatDateTime(Instant.now());
            attributes.put(createdLocalClaimUri, createdDate);
            attributes.put(modifiedLocalClaimUri, createdDate);
            attributes.put(usernameLocalClaimUri, userName);
            attributes.put(resourceTypeLocalClaimUri, SCIMConstants.USER);

        } catch (UserStoreException ex) {
            log.error("Error occurred while retrieving SCIM-to-Local claims map.", ex);
        }

        return attributes;
    }

}
