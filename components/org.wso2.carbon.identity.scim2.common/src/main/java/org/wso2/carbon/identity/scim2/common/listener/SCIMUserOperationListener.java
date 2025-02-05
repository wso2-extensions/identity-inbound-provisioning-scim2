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

package org.wso2.carbon.identity.scim2.common.listener;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.AttributeUtil;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.DATE_OF_BIRTH_LOCAL_CLAIM;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.DATE_OF_BIRTH_REGEX;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.DOB_REG_EX_VALIDATION_DEFAULT_ERROR;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.INTERNAL_DOMAIN;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.MOBILE_LOCAL_CLAIM;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.MOBILE_REGEX;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.MOBILE_REGEX_VALIDATION_DEFAULT_ERROR;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.DEFAULT_REGEX;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.PROP_REG_EX;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.PROP_REG_EX_VALIDATION_ERROR;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.COMMON_REGEX_VALIDATION_ERROR;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.GROUPS_LOCAL_CLAIM;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.PROP_DISPLAYNAME;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.NOT_EXISTING_GROUPS_ERROR;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.MAX_LENGTH;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.MIN_LENGTH;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.REQUIRED;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.ErrorMessages.ERROR_CODE_LENGTH_VIOLATION;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.ErrorMessages.ERROR_CODE_REGEX_VIOLATION;

/**
 * This is to perform SCIM related operation on User Operations.
 * For eg: when a user is created through UserAdmin API, we need to set some SCIM specific properties
 * as user attributes.
 */
public class SCIMUserOperationListener extends AbstractIdentityUserOperationEventListener {

    private static final Log log = LogFactory.getLog(SCIMUserOperationListener.class);
    private static final String DEFAULT_VALUE_SEPARATOR = ",";

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
            // Validate claim value against the regex if user claim input regex validation configuration is enabled.
            if (SCIMCommonUtils.isRegexValidationForUserClaimEnabled()) {
                validateClaimValue(claims, userStoreManager);
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

            // If the SCIM ID claims is already there, we don't need to re-generate it.
            if (StringUtils.isBlank(user.getUserID())) {
                String userId = UUID.randomUUID().toString();
                claims.put(userIdLocalClaimUri, userId);
                userStoreManager.setUserClaimValue(user.getUsername(), userIdLocalClaimUri, userId,
                        UserCoreConstants.DEFAULT_PROFILE);
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
    public boolean doPreSetUserClaimValueWithID(String userID, String claimURI, String claimValue, String profileName,
                                                UserStoreManager userStoreManager) throws UserStoreException {

        if (FrameworkUtils.isJITProvisionEnhancedFeatureEnabled() && StringUtils.isNotBlank(claimURI) &&
                !isIdentityClaimUpdate(claimURI)) {
            // Validate whether claim update request is for a provisioned user.
            validateClaimUpdate(getUsernameFromUserID(userID, userStoreManager));
        }
        // Validate claim value against the regex if user claim input regex validation configuration is enabled.
        if (SCIMCommonUtils.isRegexValidationForUserClaimEnabled()) {
            validateClaimValue(claimURI, claimValue, userStoreManager);
        }
        // Validate if the groups are updated.
        validateUserGroupClaim(userID, claimURI, claimValue, userStoreManager);
        return true;
    }

    /**
     * Validate claim values against regex. Specially handles the dob and mobile claim values.
     * This method can be removed once https://github.com/wso2/product-is/issues/9816 is fixed.
     *
     * @param claimURI         Claim URI.
     * @param claimValue       Claim value.
     * @param userStoreManager Userstore manager.
     * @throws UserStoreException When claim value doesn't match with regex.
     */
    private void validateClaimValue(String claimURI, String claimValue, UserStoreManager userStoreManager)
            throws UserStoreException {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        switch (claimURI) {
            case DATE_OF_BIRTH_LOCAL_CLAIM:
                validateClaimValueForRegex(claimURI, claimValue, tenantDomain, DATE_OF_BIRTH_REGEX,
                        DOB_REG_EX_VALIDATION_DEFAULT_ERROR);
                break;
            case MOBILE_LOCAL_CLAIM:
                validateClaimValueForRegex(claimURI, claimValue, tenantDomain, MOBILE_REGEX,
                        MOBILE_REGEX_VALIDATION_DEFAULT_ERROR);
                break;
            default:
                validateClaimValueForRegex(claimURI, claimValue, tenantDomain, DEFAULT_REGEX, null);
                validateLength(claimURI, claimValue, tenantDomain);
                break;
        }
    }

    /**
     * Validate claim value against regex.
     *
     * @param claimURI                    Claim URI.
     * @param claimValue                  Claim value.
     * @param tenantDomain                Tenant domain.
     * @param defaultRegex                Default regex of the claim.
     * @param defaultRegexValidationError Default error of claim for regex validation failure.
     * @throws UserStoreClientException When regex validation is failed.
     */
    private void validateClaimValueForRegex(String claimURI, String claimValue, String tenantDomain,
                                            String defaultRegex, String defaultRegexValidationError)
            throws UserStoreClientException {

        if (StringUtils.isBlank(claimURI)) {
            if (log.isDebugEnabled()) {
                log.debug("The claim URI is empty.");
            }
            return;
        }
        Map<String, String> claimProperties = getClaimProperties(tenantDomain, claimURI);
        if (MapUtils.isNotEmpty(claimProperties)) {
            String claimRegex = claimProperties.get(PROP_REG_EX);
            if (StringUtils.isEmpty(claimRegex)) {
                // If there is no configured claimRegex and default regex is blank nothing to validate.
                if (StringUtils.isBlank(defaultRegex)) {
                    return;
                }
                claimRegex = defaultRegex;
            }
            if (StringUtils.isNotBlank(claimValue) && !claimValue.matches(claimRegex)) {
                String regexError = claimProperties.get(PROP_REG_EX_VALIDATION_ERROR);
                if (StringUtils.isEmpty(regexError)) {
                    regexError = StringUtils.isNotBlank(defaultRegexValidationError) ? defaultRegexValidationError :
                            String.format(COMMON_REGEX_VALIDATION_ERROR, claimProperties.get(PROP_DISPLAYNAME));
                }
                throw new UserStoreClientException(regexError, ERROR_CODE_REGEX_VIOLATION.getCode());
            }
        }
    }

    /**
     * Validate attribute values against length limits.
     *
     * @param claimURI      Claim URI.
     * @param value         Claim value.
     * @param tenantDomain  Tenant domain name..
     * @throws UserStoreClientException If an error occurred in validating claim.
     */
    private void validateLength(String claimURI, String value, String tenantDomain) throws UserStoreClientException {

        if (StringUtils.isBlank(claimURI)) {
            if (log.isDebugEnabled()) {
                log.debug("The claim URI is empty.");
            }
            return;
        }
        Map<String, String> claimProperties = getClaimProperties(tenantDomain, claimURI);
        if (MapUtils.isEmpty(claimProperties)) {
            return;
        }
        String minLength = claimProperties.get(MIN_LENGTH);
        String maxLength = claimProperties.get(MAX_LENGTH);
        boolean required = false;
        if (StringUtils.isNotBlank(claimProperties.get(REQUIRED))) {
            required = Boolean.parseBoolean(claimProperties.get(REQUIRED));
        }

        if (!required && StringUtils.isBlank(value)) {
            return;
        }
        if ((StringUtils.isNotBlank(minLength) && Integer.parseInt(minLength) > value.length()) ||
                (StringUtils.isNotBlank(maxLength) && Integer.parseInt(maxLength) < value.length())) {
            throw new UserStoreClientException(String.format(ERROR_CODE_LENGTH_VIOLATION.getDescription(),
                    claimProperties.get(PROP_DISPLAYNAME), StringUtils.isNotEmpty(minLength) ? minLength : 0,
                    StringUtils.isNotEmpty(maxLength) ? maxLength : 1024), ERROR_CODE_LENGTH_VIOLATION.getCode());
        }
    }

    /**
     * Get claim properties of a claim in a given tenant.
     *
     * @param tenantDomain The tenant domain.
     * @param claimURI     Claim URI.
     * @return Properties of the claim.
     */
    private Map<String, String> getClaimProperties(String tenantDomain, String claimURI) {

        try {
            List<LocalClaim> localClaims =
                    SCIMCommonComponentHolder.getClaimManagementService().getLocalClaims(tenantDomain);
            if (localClaims == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Returned claim list from ClaimManagementService is null");
                }
                return null;
            }
            for (LocalClaim localClaim : localClaims) {
                if (StringUtils.equalsIgnoreCase(claimURI, localClaim.getClaimURI())) {
                    return localClaim.getClaimProperties();
                }
            }
        } catch (ClaimMetadataException e) {
            log.error("Error while retrieving local claim meta data.", e);
        }
        return null;
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

        if (FrameworkUtils.isJITProvisionEnhancedFeatureEnabled() && !claims.isEmpty() &&
                !isIdentityClaimsUpdate(claims)) {
            // Validate whether claim update request is for a JIT provisioned user.
            validateClaimUpdate(getUsernameFromUserID(userID, userStoreManager));
        }

        String lastModifiedDate = AttributeUtil.formatDateTime(Instant.now());
        Map<String, String> scimToLocalMappings = SCIMCommonUtils.getSCIMtoLocalMappings();
        String modifiedLocalClaimUri = scimToLocalMappings.get(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI);
        claims.put(modifiedLocalClaimUri, lastModifiedDate);

        // Validate claim value against the regex if user claim input regex validation configuration is enabled.
        if (SCIMCommonUtils.isRegexValidationForUserClaimEnabled()) {
            validateClaimValue(claims, userStoreManager);
        }
        // Validate if the groups are updated.
        validateUserGroups(userID, claims, userStoreManager);
        return true;
    }

    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                           UserStoreManager userStoreManager) throws UserStoreException {

        if (FrameworkUtils.isJITProvisionEnhancedFeatureEnabled() && !claims.isEmpty() &&
                !isIdentityClaimsUpdate(claims)) {
            // Validate whether claim update request is for a JIT provisioned user.
            validateClaimUpdate(userName);
        }
        // Validate if the groups are updated.
        validateUserGroups(userName, claims, userStoreManager);
        return true;
    }

    public boolean doPreSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName,
                                          UserStoreManager userStoreManager) throws UserStoreException {

        if (FrameworkUtils.isJITProvisionEnhancedFeatureEnabled() && StringUtils.isNotBlank(claimURI)
                && !isIdentityClaimUpdate(claimURI)) {
            validateClaimUpdate(userName);
        }
        // Validate if the groups are updated.
        validateUserGroupClaim(userName, claimURI, claimValue, userStoreManager);
        return true;
    }

    private String getUsernameFromUserID(String userID, UserStoreManager userStoreManager) throws UserStoreException {

        return ((AbstractUserStoreManager) userStoreManager).getUserNameFromUserID(userID);
    }

    /**
     * Validate whether the claim update request is from a provisioned user.
     *
     * @param username Username.
     * @throws UserStoreException if an error occurred while retrieving the user claim list.
     */
    private void validateClaimUpdate(String username) throws UserStoreException {

        boolean isAttributeSyncingEnabled = true;

        /*
        If attribute syncing is disabled, blocking the attribute editing is not required.
        ToDo: There should be an option to disable attribute syncing.
        (https://github.com/wso2/product-is/issues/12414)
         */
        if (!isAttributeSyncingEnabled) {
            return;
        }

        /*
        Check whether this is an attribute syncing flow by checking the PROVISIONED_USER thread local property.
        If it is an attribute syncing flow, blocking the attribute editing is not required.
         */
        if (IdentityUtil.threadLocalProperties.get().get(FrameworkConstants.JIT_PROVISIONING_FLOW) != null &&
                (Boolean) IdentityUtil.threadLocalProperties.get().get(FrameworkConstants.JIT_PROVISIONING_FLOW)) {
            return;
        }

        boolean isExistingJITProvisionedUser;
        try {
            isExistingJITProvisionedUser = UserSessionStore.getInstance().isExistingUser(username);
        } catch (UserSessionException e) {
            throw new UserStoreException("Error while checking the federated user existence for the user: " +
                    (LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(username) : username));
        }

        // If federated user is already provisioned, block that user's synced attribute editing.
        if (isExistingJITProvisionedUser) {
            throw new UserStoreClientException(
                    SCIMCommonConstants.ErrorMessages.ERROR_CODE_INVALID_ATTRIBUTE_UPDATE.getMessage(),
                    SCIMCommonConstants.ErrorMessages.ERROR_CODE_INVALID_ATTRIBUTE_UPDATE.getCode());
        }
    }

    /**
     * Validate whether the updating groups do exist in the system.
     *
     * @param userIdentifier   User identifier.
     * @param claimURI         Claim uri.
     * @param value            Claim value.
     * @param userStoreManager Userstore manager.
     * @throws UserStoreException If the group does not exist in the system or if an error occurred while checking
     *                            for group existence.
     */
    private void validateUserGroupClaim(String userIdentifier, String claimURI, String value,
                                        UserStoreManager userStoreManager)
            throws UserStoreException {

        Map<String, String> claimsMap = new HashMap<>();
        claimsMap.put(claimURI, value);
        validateUserGroups(userIdentifier, claimsMap, userStoreManager);
    }

    /**
     * Validate whether the updated groups does exist in the system.
     *
     * @param userIdentifier   User identifier.
     * @param claims           List of claims to be updated.
     * @param userStoreManager Userstore manager.
     * @throws UserStoreException If the group does not exist in the system or if an error occurred while checking
     *                            for group existence.
     */
    private void validateUserGroups(String userIdentifier, Map<String, String> claims,
                                    UserStoreManager userStoreManager)
            throws UserStoreException {

        if (claims == null || !claims.containsKey(GROUPS_LOCAL_CLAIM)) {
            return;
        }
        /*
         * We do not need to validate the groups for JIT provisioned users. That will be handled when resolved group
         * mappings for the provisioned users. Therefore, this check can be skipped for the JIT provisioned users.
         */
        if (IdentityUtil.threadLocalProperties.get().get(FrameworkConstants.JIT_PROVISIONING_FLOW) != null &&
                (Boolean) IdentityUtil.threadLocalProperties.get().get(FrameworkConstants.JIT_PROVISIONING_FLOW)) {
            return;
        }
        String value = claims.get(GROUPS_LOCAL_CLAIM);
        if (StringUtils.isBlank(value)) {
            return;
        }
        // Resolve the multi attribute
        String attributeSeparator =
                userStoreManager.getRealmConfiguration().getUserStoreProperty(MULTI_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isEmpty(attributeSeparator)) {
            attributeSeparator = DEFAULT_VALUE_SEPARATOR;
        }
        int tenant = userStoreManager.getTenantId();
        // We need to split if the user has provided a list of groups.
        String[] groups = value.split(attributeSeparator);
        boolean hasInvalidGroups = false;
        for (String groupName : groups) {
            // We need to identify the groups that does not exist in the system.
            if (!userStoreManager.isExistingRole(groupName)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Invalid group: %s found for the claim update of user: %s in tenant: %s",
                            groupName, userIdentifier, tenant));
                }
                hasInvalidGroups = true;
            }
        }
        if (hasInvalidGroups) {
            // At least one group does not exist. We need to throw an error and abort the flow.
            throw new UserStoreClientException(NOT_EXISTING_GROUPS_ERROR);
        }
    }

    /**
     * Validate claim values against the regex. Specially handles the dob and mobile claim values.
     * This method can be removed once https://github.com/wso2/product-is/issues/9816 is fixed.
     *
     * @param claims           List of claims.
     * @param userStoreManager Userstore manager.
     * @throws UserStoreException When regex validation fails.
     */
    private void validateClaimValue(Map<String, String> claims, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (MapUtils.isEmpty(claims)) {
            if (log.isDebugEnabled()) {
                log.debug("claim set is empty.");
            }
            return;
        }
        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        for (Map.Entry<String, String> claim : claims.entrySet()) {
            if (StringUtils.isBlank(claim.getKey())) {
                return;
            }
            switch (claim.getKey()) {
                case DATE_OF_BIRTH_LOCAL_CLAIM:
                    validateClaimValueForRegex(DATE_OF_BIRTH_LOCAL_CLAIM, claims.get(DATE_OF_BIRTH_LOCAL_CLAIM),
                            tenantDomain, DATE_OF_BIRTH_REGEX, DOB_REG_EX_VALIDATION_DEFAULT_ERROR);
                    break;
                case MOBILE_LOCAL_CLAIM:
                    validateClaimValueForRegex(MOBILE_LOCAL_CLAIM, claims.get(MOBILE_LOCAL_CLAIM), tenantDomain,
                            MOBILE_REGEX, MOBILE_REGEX_VALIDATION_DEFAULT_ERROR);
                    break;
                default:
                    validateClaimValueForRegex(claim.getKey(), claim.getValue(), tenantDomain, DEFAULT_REGEX, null);
                    validateLength(claim.getKey(), claim.getValue(), tenantDomain);
            }
        }
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
                if (log.isDebugEnabled()) {
                    log.debug("Persisting SCIM metadata for hybrid role: " + roleName + ", created while SCIM is " +
                            "disabled in the user store.");
                }
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
                    /*
                     Extracting the domain name here, because resolved domainName is userstore based domains.
                     If the roleName passed to the method with Internal domain that will be remain as same in
                     roleNameWithDomain.
                     */
                    if (INTERNAL_DOMAIN.equalsIgnoreCase(UserCoreUtil.extractDomainFromName(roleNameWithDomain)) &&
                            !CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME) {
                        scimGroupHandler.addRoleV2MandatoryAttributes(roleNameWithDomain);
                    } else {
                        if (!((AbstractUserStoreManager) userStoreManager).isUniqueGroupIdEnabled()) {
                            scimGroupHandler.addMandatoryAttributes(roleNameWithDomain);
                        }
                    }
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
            if (userStoreManager instanceof AbstractUserStoreManager &&
                    ((AbstractUserStoreManager) userStoreManager).isUniqueGroupIdEnabled()) {
                if (log.isDebugEnabled()) {
                    log.debug("UniqueGroupId is enabled. Skipping doPostUpdateRoleName in " +
                            "SCIMUserOperationListener");
                }
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
            String newRoleNameWithDomain = UserCoreUtil.addDomainToName(newRoleName, domainName);
            try {
                scimGroupHandler.updateRoleName(roleNameWithDomain, newRoleNameWithDomain);
            } catch (IdentitySCIMException e) {
                throw new UserStoreException("Error updating group information in SCIM Tables.", e);
            }

            // Update the last modified time of the group.
            Date groupLastUpdatedTime = new Date();
            Map<String, String> attributes = new HashMap<>();
            attributes.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI,
                    AttributeUtil.formatDateTime(groupLastUpdatedTime.toInstant()));
            try {
                scimGroupHandler.updateSCIMAttributes(newRoleNameWithDomain, attributes);
            } catch (IdentitySCIMException e) {
                throw new UserStoreException("Failed to update group's last modified date in SCIM tables.", e);
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

    @Override
    public boolean doPostGetUserClaimValuesWithID(String userID, String[] claims, String profileName,
                                                  Map<String, String> claimMap, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }

        if (log.isDebugEnabled()) {
            log.debug("doPostGetUserClaimValues getting executed in the SCIMUserOperationListener for user id: " +
                    userID);
        }

        // Check whether http://wso2.org/claims/identity/isReadOnlyUser claim is requested.
        if (claims == null || !Arrays.asList(claims).contains(SCIMCommonConstants.READ_ONLY_USER_CLAIM)) {
            return true;
        }

        if (claimMap == null) {
            claimMap = new HashMap<>();
        }

        // If http://wso2.org/claims/identity/isReadOnlyUser claim is requested, set the value checking the user store.
        claimMap.put(SCIMCommonConstants.READ_ONLY_USER_CLAIM, String.valueOf(userStoreManager.isReadOnly()));
        return true;
    }

    private boolean isIdentityClaimsUpdate(Map<String, String> claims) {

        return claims.entrySet().stream().anyMatch(claim -> isIdentityClaimUpdate(claim.getKey()));
    }

    private boolean isIdentityClaimUpdate(String claimURI) {

        return claimURI.startsWith(UserCoreConstants.ClaimTypeURIs.IDENTITY_CLAIM_URI_PREFIX);
    }
}
