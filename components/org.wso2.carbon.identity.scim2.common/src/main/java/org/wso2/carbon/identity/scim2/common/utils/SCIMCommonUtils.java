/*
 * Copyright (c) 2017-2023, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.mgt.core.util.UserIDResolver;
import org.wso2.carbon.identity.scim2.common.cache.SCIMCustomAttributeSchemaCache;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.charon3.core.attributes.SCIMCustomAttribute;
import org.wso2.charon3.core.config.SCIMCustomSchemaExtensionBuilder;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.InternalErrorException;
import org.wso2.charon3.core.schema.AttributeSchema;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.charon3.core.schema.SCIMConstants.CUSTOM_USER_SCHEMA_URI;

/**
 * This class is to be used as a Util class for SCIM common things.
 * TODO:rename class name.
 */
public class SCIMCommonUtils {

    private static final Log log = LogFactory.getLog(SCIMCommonUtils.class);

    /**
     * Since we need perform provisioning through UserOperationEventListener implementation -
     * SCIMUserOperationListener- there can be cases where multiple methods in the listener are
     * called for same operation - such as when adding a user with claims, both postAddUserListener
     * as well as setClaimValuesListener are called. But we do not need setClaimValuesLister to be
     * called at user creation - it is supposed to do provisioning at user update. So we make use of
     * this thread local variable to skip the second lister.
     */
    private static ThreadLocal<Boolean> threadLocalToSkipSetUserClaimsListeners = new ThreadLocal<>();
    /**
     * Provisioning to other providers is initiated at SCIMUserOperationListener which is invoked
     * by UserStoreManager. It doesn't have any clue about through which path the user management operation
     * came. If it came through SCIMEndPoint, we treat it differently when deciding SCIMConsumerId.
     * Therefore we need this thread local to signal the SCIMUserOperationListener to take the decision.
     */
    private static ThreadLocal<Boolean> threadLocalIsManagedThroughSCIMEP = new ThreadLocal<>();

    public static String getSCIMUserURL(String id) {
        return StringUtils.isNotBlank(id) ? getSCIMUserURL() + SCIMCommonConstants.URL_SEPERATOR + id : null;
    }

    public static String getSCIMGroupURL(String id) {
        return StringUtils.isNotBlank(id) ? getSCIMGroupURL() + SCIMCommonConstants.URL_SEPERATOR + id : null;
    }

    public static String getSCIMRoleURL(String id) {

        return StringUtils.isNotBlank(id) ? getSCIMRoleURL() + SCIMCommonConstants.URL_SEPERATOR + id : null;
    }

    public static String getSCIMRoleV2URL(String id) {

        return StringUtils.isNotBlank(id) ? getSCIMRoleV2URL() + SCIMCommonConstants.URL_SEPERATOR + id : null;
    }

    public static String getSCIMServiceProviderConfigURL(String id) {
        return getSCIMServiceProviderConfigURL() ;
    }

    /*Handling ThreadLocals*/

    public static String getSCIMUserURL() {

        String scimURL = getSCIMURL(true);
        return scimURL + SCIMCommonConstants.USERS;
    }

    public static String getSCIMGroupURL() {

        String scimURL = getSCIMURL(true);
        return scimURL + SCIMCommonConstants.GROUPS;
    }

    public static String getSCIMRoleURL() {

        String scimURL = getSCIMURL(false);
        return scimURL + SCIMCommonConstants.ROLES;
    }

    public static String getSCIMRoleV2URL() {

        String scimURL = getSCIMURL(true);
        return scimURL + SCIMCommonConstants.ROLES_V2;
    }

    public static String getApplicationRefURL(String id) {

        String applicationURL;
        String path = "/api/server/v1/applications";
        try {
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                applicationURL = ServiceURLBuilder.create().addPath(path).build()
                        .getAbsolutePublicURL();
            } else {
                applicationURL = getURLIfTenantQualifiedURLDisabled(path);
            }
            return StringUtils.isNotBlank(id) ? applicationURL + SCIMCommonConstants.URL_SEPERATOR + id : null;
        } catch (URLBuilderException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while building the application endpoint with tenant/organization " +
                        "qualified URL.", e);
            }
            return null;
        }
    }

    public static String getIdpGroupURL(String idpId, String groupId) {

        String idpGroupURL;
        String path = "/api/server/v1/identity-providers";
        try {
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                idpGroupURL = ServiceURLBuilder.create().addPath(path).build()
                        .getAbsolutePublicURL();
            } else {
                idpGroupURL = getURLIfTenantQualifiedURLDisabled(path);
            }
            return StringUtils.isNotBlank(idpId) && StringUtils.isNotBlank(groupId) ?
                    new StringBuilder().append(idpGroupURL).append(SCIMCommonConstants.URL_SEPERATOR).append(idpId)
                            .append(SCIMCommonConstants.URL_SEPERATOR).append(groupId).toString() : null;
        } catch (URLBuilderException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while building the identity provider's group endpoint with " +
                                "tenant/organization qualified URL.", e);
            }
            return null;
        }
    }

    public static String getPermissionRefURL(String apiId, String permissionName) {

        String apiResourceURL;
        String apiResourcePath = "/api/server/v1/api-resources";
        try {
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                apiResourceURL = ServiceURLBuilder.create().addPath(apiResourcePath).build()
                        .getAbsolutePublicURL();
            } else {
                apiResourceURL = getURLIfTenantQualifiedURLDisabled(apiResourcePath);
            }
            return StringUtils.isNotBlank(apiId) && StringUtils.isNotBlank(permissionName) ?
                    new StringBuilder().append(apiResourceURL).append(SCIMCommonConstants.URL_SEPERATOR).append(apiId)
                            .append(SCIMCommonConstants.URL_SEPERATOR).append("scopes")
                            .append(SCIMCommonConstants.URL_SEPERATOR).append(permissionName).toString() : null;
        } catch (URLBuilderException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while building the application endpoint with tenant/organization " +
                        "qualified URL.", e);
            }
            return null;
        }
    }

    private static String getURLIfTenantQualifiedURLDisabled(String resourcePath) throws URLBuilderException {

        String serverUrl = ServiceURLBuilder.create().build().getAbsolutePublicURL();
        String tenantDomain = getTenantDomainFromContext();
        if (isNotASuperTenantFlow(tenantDomain)) {
            return serverUrl + "/t/" + tenantDomain + resourcePath;
        }
        return serverUrl + resourcePath;
    }

    public static String getTenantDomainFromContext() {

        String tenantDomain = IdentityTenantUtil.getTenantDomainFromContext();
        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        }
        return tenantDomain;
    }

    private static String getSCIMURL(boolean organizationRoutingSupported) {

        String scimURL;
        try {
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                scimURL = ServiceURLBuilder.create().addPath(SCIMCommonConstants.SCIM2_ENDPOINT).build()
                        .getAbsolutePublicURL();
            } else {
                String serverUrl = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                String tenantDomain = getTenantDomainFromContext();
                if (isNotASuperTenantFlow(tenantDomain)) {
                    scimURL = serverUrl + "/t/" + tenantDomain + SCIMCommonConstants.SCIM2_ENDPOINT;
                } else {
                    scimURL = serverUrl + SCIMCommonConstants.SCIM2_ENDPOINT;
                }
            }
            return scimURL;
        } catch (URLBuilderException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while building the SCIM2 endpoint with tenant/organization " +
                        "qualified URL.", e);
            }
            // Fallback to legacy approach during error scenarios to maintain backward compatibility.
            return getSCIMURLLegacy(organizationRoutingSupported);
        }
    }

    private static String getSCIMURLLegacy(boolean organizationRoutingSupported) {

        String scimURL;
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (isNotASuperTenantFlow(tenantDomain)) {
            String organizationId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getOrganizationId();
            if (organizationRoutingSupported && StringUtils.isNotBlank(organizationId)) {
                scimURL = IdentityUtil.getServerURL(
                        SCIMCommonConstants.ORGANIZATION_PATH_PARAM + organizationId +
                                SCIMCommonConstants.SCIM2_ENDPOINT, true, true);
            } else {
                scimURL = IdentityUtil.getServerURL(
                        SCIMCommonConstants.TENANT_URL_SEPERATOR + tenantDomain + SCIMCommonConstants.SCIM2_ENDPOINT,
                        true, true);
            }
        } else {
            scimURL = IdentityUtil.getServerURL(SCIMCommonConstants.SCIM2_ENDPOINT, true, true);
        }
        return scimURL;
    }

    private static boolean isNotASuperTenantFlow(String tenantDomain) {
        return !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain);
    }

    public static String getSCIMServiceProviderConfigURL() {

        String scimURL = getSCIMURL(false);
        String scimServiceProviderConfig = scimURL + SCIMCommonConstants.SERVICE_PROVIDER_CONFIG;
        return scimServiceProviderConfig;
    }

    public static String getSCIMResourceTypeURL() {

        String scimURL = getSCIMURL(false);
        String scimResourceType = scimURL + SCIMCommonConstants.RESOURCE_TYPE;
        return scimResourceType;
    }

    public static String getGroupNameWithDomain(String groupName) {

        if (groupName == null) {
            return null;
        }

        if (groupName.indexOf(CarbonConstants.DOMAIN_SEPARATOR) > 0) {
            return groupName;
        } else {
            return IdentityUtil.getPrimaryDomainName()
                    + CarbonConstants.DOMAIN_SEPARATOR + groupName;
        }
    }

    public static String getPrimaryFreeGroupName(String groupName) {

        if (groupName == null) {
            return null;
        }

        int index = groupName.indexOf(CarbonConstants.DOMAIN_SEPARATOR);

        // Check whether we have a secondary UserStoreManager setup.
        if (index > 0) {
            // Using the short-circuit. User name comes with the domain name.
            String domain = groupName.substring(0, index);
            if (UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(domain)) {
                return groupName.substring(index + 1);
            }
        }
        return groupName;
    }

    public static void unsetThreadLocalToSkipSetUserClaimsListeners() {
        threadLocalToSkipSetUserClaimsListeners.remove();
    }

    public static Boolean getThreadLocalToSkipSetUserClaimsListeners() {
        return threadLocalToSkipSetUserClaimsListeners.get();
    }

    public static void setThreadLocalToSkipSetUserClaimsListeners(Boolean value) {
        threadLocalToSkipSetUserClaimsListeners.set(value);
    }

    public static void unsetThreadLocalIsManagedThroughSCIMEP() {
        threadLocalIsManagedThroughSCIMEP.remove();
    }

    public static Boolean getThreadLocalIsManagedThroughSCIMEP() {
        return threadLocalIsManagedThroughSCIMEP.get();
    }

    public static void setThreadLocalIsManagedThroughSCIMEP(Boolean value) {
        threadLocalIsManagedThroughSCIMEP.set(value);
    }

    public static String getGlobalConsumerId() {
        return getTenantDomainFromContext();
    }

    public static String getUserConsumerId() {
        String userName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String currentTenantDomain = getTenantDomainFromContext();
        return UserCoreUtil.addTenantDomainToEntry(userName, currentTenantDomain);
    }

    /**
     * SCIM datetime format function.
     *
     * @param date
     * @return
     */
    public static String formatDateTime(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat(SCIMConstants.DATE_TIME_FORMAT);
        String formattedDate = sdf.format(date);
        return formattedDate;
    }


    /**
     * Converts claims in SCIM dialect to local WSO2 dialect.
     *
     * @param claimsMap         Map of SCIM claims and claim values.
     * @return                  map of Local WSO2 Claims and corresponding claim values.
     * @throws UserStoreException
     */
    public static Map<String, String> convertSCIMtoLocalDialect(Map<String, String> claimsMap)
            throws UserStoreException {

        // Retrieve SCIM to Local Claim Mappings.
        Map<String, String> scimToLocalClaimMappings;
        Map<String, String> claimsInLocalDialect = new HashMap<>();
        scimToLocalClaimMappings = getSCIMtoLocalMappings();
        if (MapUtils.isNotEmpty(scimToLocalClaimMappings)) {
            for (Map.Entry entry : claimsMap.entrySet()) {
                String scimClaimtUri = (String) entry.getKey();
                String localClaimUri = scimToLocalClaimMappings.get(scimClaimtUri);
                if (StringUtils.isNotEmpty(localClaimUri)) {
                    claimsInLocalDialect.put(localClaimUri, (String) entry.getValue());
                }
            }
        }

        return claimsInLocalDialect;
    }

    /**
     * Converts claims in local WSO2 dialect to SCIM dialect.
     *
     * @param claimsMap         Map of local claims and claim values.
     * @return                  map of SCIM claims and corresponding claim values.
     * @throws UserStoreException
     */
    public static Map<String, String> convertLocalToSCIMDialect(Map<String, String> claimsMap, Map<String, String>
            scimToLocalClaimMappings) throws UserStoreException {

        if (MapUtils.isEmpty(scimToLocalClaimMappings)) {
            // Retrieve Local to SCIM Claim Mappings from db.
            scimToLocalClaimMappings = getSCIMtoLocalMappings();
        }

        Map<String, String> claimsInSCIMDialect = new HashMap<>();
        if (MapUtils.isNotEmpty(scimToLocalClaimMappings)) {
            for (Map.Entry entry : scimToLocalClaimMappings.entrySet()) {
                String claimValue = claimsMap.get(entry.getValue());
                if (StringUtils.isNotEmpty(claimValue)) {
                    String scimClaimUri = (String) entry.getKey();
                    claimsInSCIMDialect.put(scimClaimUri, claimValue);
                }
            }
        }
        return claimsInSCIMDialect;
    }

    /**
     * Retrieves SCIM to Local Claim Mappings.
     *
     * @return Map of SCIM claims and corresponding Local WSO2 claims.
     * @throws UserStoreException
     */
    public static Map<String, String> getSCIMtoLocalMappings() throws UserStoreException {

        String tenantDomain = getTenantDomain();

        Map<String, String> scimToLocalClaimMap = new HashMap<>();
        try {
            // Get the SCIM "Core" claims.
            Map<String, String> coreClaims = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(SCIMCommonConstants.SCIM_CORE_CLAIM_DIALECT, null,
                            tenantDomain, false);
            scimToLocalClaimMap.putAll(coreClaims);

            // Get the SCIM "User" claims.
            Map<String, String> userClaims = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT, null,
                            tenantDomain, false);
            scimToLocalClaimMap.putAll(userClaims);

            // Get the extension claims, if there are any extensions enabled.
            if (SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema() != null) {
                Map<String, String> extensionClaims = ClaimMetadataHandler.getInstance()
                        .getMappingsMapFromOtherDialectToCarbon(SCIMUserSchemaExtensionBuilder.getInstance()
                                .getExtensionSchema().getURI(), null, tenantDomain, false);
                scimToLocalClaimMap.putAll(extensionClaims);
            }

            String userTenantDomain = getTenantDomain();
            Map<String, String> customExtensionClaims =
                    ClaimMetadataHandler.getInstance().getMappingsMapFromOtherDialectToCarbon(getCustomSchemaURI(),
                            null, userTenantDomain, false);
            scimToLocalClaimMap.putAll(customExtensionClaims);

            return scimToLocalClaimMap;
        } catch (ClaimMetadataException e) {
            throw new UserStoreException("Error occurred while retrieving SCIM to Local claim mappings for tenant " +
                    "domain : " + tenantDomain, e);
        }
    }

    /**
     * This is used to get tenant domain.
     *
     * @return user's tenant domain.
     */
    private static String getTenantDomain() {

        String tenantDomain;
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            tenantDomain = getTenantDomainFromContext();
        } else {
            tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        }

        if (StringUtils.isBlank(tenantDomain)){
            if (log.isDebugEnabled()) {
                log.debug("Tenant domain is empty, hence reading it as the super tenant domain.");
            }
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    /**
     * Checks whether the identity.xml config is available for applying filtering enhancements. This makes sure that Eq
     * should strictly check for the String match (in this case cross user store search should not be performed).
     * This config also enforces consistency on the filtered attribute formats in the response.
     *
     * @return whether 'EnableFilteringEnhancements' property is enabled in identity.xml.
     */
    public static boolean isFilteringEnhancementsEnabled() {

        return Boolean.parseBoolean(IdentityUtil.getProperty
                (SCIMCommonConstants.SCIM_ENABLE_FILTERING_ENHANCEMENTS));
    }

    /**
     * Checks whether the identity.xml config is available for applying filtering enhancements. If that property
     * enabled, then this will return true/false accordingly.
     *
     * @return whether 'FilterUsersAndGroupsOnlyFromPrimaryDomain' property is enabled in identity.xml.
     */
    public static boolean isFilterUsersAndGroupsOnlyFromPrimaryDomainEnabled() {

        return Boolean.parseBoolean(IdentityUtil
                .getProperty(SCIMCommonConstants.SCIM_ENABLE_FILTER_USERS_AND_GROUPS_ONLY_FROM_PRIMARY_DOMAIN));
    }

    /**
     * Checks whether the identity.xml config is available to consider max user limit for total results.If that property
     * enabled, then this will return true.
     *
     * @return whether 'ConsiderMaxLimitForTotalResult' property is enabled in identity.xml.
     */
    public static boolean isConsiderMaxLimitForTotalResultEnabled() {

        return Boolean.parseBoolean(IdentityUtil
                .getProperty(SCIMCommonConstants.SCIM_ENABLE_CONSIDER_MAX_LIMIT_FOR_TOTAL_RESULT));
    }

    /**
     * Checks whether the identity.xml config is available to consider total records matching the client
     * query for the 'totalResults' in LDAP. If that property enabled, then this will return true.
     *
     * @return whether 'ConsiderTotalRecordsForTotalResultLDAP' property is enabled in identity.xml.
     */
    public static boolean isConsiderTotalRecordsForTotalResultOfLDAPEnabled() {

        return Boolean.parseBoolean(IdentityUtil
                .getProperty(SCIMCommonConstants.SCIM_ENABLE_CONSIDER_TOTAL_RECORDS_FOR_TOTAL_RESULT_OF_LDAP));
    }

    /**
     * Checks whether the identity.xml config is available for prepending the 'PRIMARY/' in each role and
     * which belong to Primary domain in the response of Groups endpoints.
     *
     * @return whether 'MandateDomainForGroupNamesInGroupsResponse' property is enabled in identity.xml.
     */
    public static boolean mandateDomainForGroupNamesInGroupsResponse() {

        return Boolean.parseBoolean(IdentityUtil
                .getProperty(SCIMCommonConstants.SCIM_ENABLE_MANDATE_DOMAIN_FOR_GROUPNAMES_IN_GROUPS_RESPONSE));
    }

    /**
     * Checks whether the identity.xml config is available for prepending the 'PRIMARY/' in each role and
     * username which belong to Primary domain in the responses of both Users and Groups endpoints.
     *
     * @return whether 'MandateDomainForUsernamesAndGroupNamesInResponse' property is enabled in identity.xml.
     */
    public static boolean mandateDomainForUsernamesAndGroupNamesInResponse() {

        return Boolean.parseBoolean(IdentityUtil
                .getProperty(SCIMCommonConstants.SCIM_ENABLE_MANDATE_DOMAIN_FOR_USERNAMES_AND_GROUPNAMES_IN_RESPONSE));
    }

    /**
     * Method to prepend PRIMARY domain name to given String when that String not contains DOMAIN_SEPARATOR.
     * @param value
     * @return Given String if given String not contains DOMAIN_SEPARATOR, String with PRIMARY domain otherwise.
     */
    public static String prependDomain(String value) {

        if (StringUtils.contains(value, CarbonConstants.DOMAIN_SEPARATOR)) {
            return value;
        } else {
            return UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME + CarbonConstants.DOMAIN_SEPARATOR + value;
        }
    }

    /**
     * Method to extract domain name from the input value passed in to this method.
     *
     * @param nameWithDomain string which contains domain name
     * @return extracted domain value or empty string if no domain.
     */
    public static String extractDomain(String nameWithDomain) {

        if (nameWithDomain != null && nameWithDomain.indexOf(CarbonConstants.DOMAIN_SEPARATOR) > 0) {
            String domain = nameWithDomain.substring(0, nameWithDomain.indexOf(CarbonConstants.DOMAIN_SEPARATOR));
            return domain;
        } else {
            return null;
        }
    }

    /**
     * Checks whether the given role is an internal or application role.
     *
     * @param roleName Role name.
     * @return Whether the passed role is "internal" or "application".
     */
    public static boolean isHybridRole(String roleName) {

        return roleName.toLowerCase().startsWith((SCIMCommonConstants.INTERNAL_DOMAIN +
                CarbonConstants.DOMAIN_SEPARATOR).toLowerCase()) ||
                roleName.toLowerCase().startsWith((SCIMCommonConstants.APPLICATION_DOMAIN +
                        CarbonConstants.DOMAIN_SEPARATOR).toLowerCase());
    }

    /**
     * Check if SCIM enterprise user extension has been enabled.
     *
     * @return True if enterprise user extension enabled
     */
    public static boolean isEnterpriseUserExtensionEnabled() {

        return Boolean.parseBoolean(SCIMConfigProcessor.getInstance()
                .getProperty(SCIMCommonConstants.ENTERPRISE_USER_EXTENSION_ENABLED));
    }

    /**
     * Checks whether the identity.xml config is available to enable group based user filtering improvements.
     *
     * @return Whether 'SCIM_ENABLE_GROUP_BASED_USER_FILTERING_IMPROVEMENTS' property is enabled in identity.xml.
     */
    public static boolean isGroupBasedUserFilteringImprovementsEnabled() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(
                SCIMCommonConstants.SCIM_ENABLE_GROUP_BASED_USER_FILTERING_IMPROVEMENTS));
    }

    /**
     * Checks whether the identity.xml config is available to notify userstore availability.
     *
     * @return whether 'NotifyUserstoreStatus' property is enabled in the identity.xml.
     */
    public static boolean isNotifyUserstoreStatusEnabled() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(SCIMCommonConstants.SCIM_NOTIFY_USERSTORE_STATUS));
    }

    public static Map<ExternalClaim, LocalClaim> getMappedLocalClaimsForDialect(String externalClaimDialect,
                                                                                String tenantDomain) throws
            CharonException {

        try {
            ClaimMetadataManagementService claimMetadataManagementService =
                    SCIMCommonComponentHolder.getClaimManagementService();
            List<ExternalClaim> externalClaimList =
                    claimMetadataManagementService.getExternalClaims(externalClaimDialect, tenantDomain);
            List<LocalClaim> localClaimList = claimMetadataManagementService.getLocalClaims(tenantDomain);
            Map<ExternalClaim, LocalClaim> externalClaimLocalClaimMap = new HashMap<>();
            if (externalClaimList != null && localClaimList != null) {
                externalClaimList.forEach(externalClaim ->
                        getMappedLocalClaim(externalClaim, localClaimList)
                                .ifPresent(mappedLocalClaim -> externalClaimLocalClaimMap.put(externalClaim,
                                        mappedLocalClaim)));
            }
            return externalClaimLocalClaimMap;
        } catch (ClaimMetadataException e) {
            throw new CharonException("Error while retrieving schema attribute details.", e);
        }
    }

    /**
     * Get mapped local claim for specified external claim.
     *
     * @param externalClaim
     * @param localClaimList
     * @return
     */
    private static Optional<LocalClaim> getMappedLocalClaim(ExternalClaim externalClaim,
                                                            List<LocalClaim> localClaimList) {

        if (localClaimList == null) {
            return Optional.empty();
        }
        return localClaimList.stream()
                .filter(localClaim -> localClaim.getClaimURI().equals(externalClaim.getMappedLocalClaim()))
                .findAny();
    }

    /**
     * Check if SCIM custom user schema has been enabled or not. By default, it is enabled.
     *
     * @return True if SCIM custom user schema is enabled.
     */
    public static boolean isCustomSchemaEnabled() {

        String isCustomSchemaEnabled =
                SCIMConfigProcessor.getInstance().getProperty(SCIMCommonConstants.CUSTOM_USER_SCHEMA_ENABLED);
        if (StringUtils.isNotBlank(isCustomSchemaEnabled)) {
            return Boolean.parseBoolean(isCustomSchemaEnabled);
        }
        return true;
    }

    /**
     * Return custom schema URI.
     *
     * @return custom schema URI.
     */
    public static String getCustomSchemaURI() {

        String customSchemaURI =
                SCIMConfigProcessor.getInstance().getProperty(SCIMCommonConstants.CUSTOM_USER_SCHEMA_URI);
        if (StringUtils.isNotBlank(customSchemaURI)) {
            return customSchemaURI;
        }
        return CUSTOM_USER_SCHEMA_URI;
    }

    /**
     * Build the search value after appending the delimiters according to the attribute name to be filtered.
     *
     * @param attributeName   Filter attribute name.
     * @param filterOperation Operator value.
     * @param attributeValue  Search value.
     * @param delimiter       Filter delimiter based on search type.
     * @return Search attribute.
     */
    private String buildSearchAttributeValue(String attributeName, String filterOperation, String attributeValue,
                                                   String delimiter) {

        String searchAttribute = null;
        if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.CO)) {
            searchAttribute = createSearchValueForCoOperation(attributeName, filterOperation, attributeValue,
                    delimiter);
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.SW)) {
            searchAttribute = attributeValue + delimiter;
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EW)) {
            searchAttribute = createSearchValueForEwOperation(attributeName, filterOperation, attributeValue,
                    delimiter);
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EQ)) {
            searchAttribute = attributeValue;
        }
        return searchAttribute;
    }

    /**
     * Create search value for CO operation.
     *
     * @param attributeName   Filter attribute name.
     * @param filterOperation Operator value.
     * @param attributeValue  Filter attribute value.
     * @param delimiter       Filter delimiter based on search type.
     * @return Search attribute value.
     */
    private String createSearchValueForCoOperation(String attributeName, String filterOperation,
                                                          String attributeValue, String delimiter) {

        /*
         * For attributes which support domain embedding, create search value by appending the delimiter after the
         * domain separator.
         */
        if (isDomainSupportedAttribute(attributeName)) {

            // Check whether domain is embedded in the attribute value.
            String[] attributeItems = attributeValue.split(CarbonConstants.DOMAIN_SEPARATOR, 2);
            if (attributeItems.length > 1) {
                return createSearchValueWithDomainForCoEwOperations(attributeName, filterOperation, attributeValue,
                        delimiter, attributeItems);
            } else {
                return delimiter + attributeValue + delimiter;
            }
        } else {
            return delimiter + attributeValue + delimiter;
        }
    }

    /**
     * Check whether the filter attribute support filtering with the domain embedded in the attribute value.
     *
     * @param attributeName Attribute to filter.
     * @return True if the given attribute support embedding domain in attribute value.
     */
    private boolean isDomainSupportedAttribute(String attributeName) {

        return SCIMConstants.UserSchemaConstants.USER_NAME_URI.equalsIgnoreCase(attributeName)
                || SCIMConstants.CommonSchemaConstants.ID_URI.equalsIgnoreCase(attributeName)
                || SCIMConstants.UserSchemaConstants.GROUP_URI.equalsIgnoreCase(attributeName)
                || SCIMConstants.GroupSchemaConstants.DISPLAY_NAME_URI.equalsIgnoreCase(attributeName)
                || SCIMConstants.GroupSchemaConstants.DISPLAY_URI.equalsIgnoreCase(attributeName);
    }

    /**
     * Create search value for CO and EW operations when domain is detected in the filter attribute value.
     *
     * @param attributeName   Filter attribute name.
     * @param filterOperation Operator value.
     * @param attributeValue  Search value.
     * @param delimiter       Filter delimiter based on search type.
     * @param attributeItems  Extracted domain and filter value.
     * @return Search attribute value.
     */
    private String createSearchValueWithDomainForCoEwOperations(String attributeName, String filterOperation,
                                                                       String attributeValue, String delimiter,
                                                                       String[] attributeItems) {

        String searchAttribute;
        if (log.isDebugEnabled()) {
            log.debug(String.format("Domain detected in attribute value: %s for filter attribute: %s for filter " +
                    "operation: %s.", attributeValue, attributeName, filterOperation));
        }
        if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EW)) {
            searchAttribute = attributeItems[0] + CarbonConstants.DOMAIN_SEPARATOR + delimiter + attributeItems[1];
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.CO)) {
            searchAttribute =
                    attributeItems[0] + CarbonConstants.DOMAIN_SEPARATOR + delimiter + attributeItems[1] + delimiter;
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Filter operation: %s is not supported by method "
                        + "createSearchValueWithDomainForCoEwOperations to create a search value", filterOperation));
            }
            searchAttribute = attributeValue;
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("Search attribute value: %s is created for operation: %s created with domain : %s ",
                    searchAttribute, filterOperation, attributeItems[0]));
        }
        return searchAttribute;
    }

    /**
     * Create search value for EW operation.
     *
     * @param attributeName   Filter attribute name.
     * @param filterOperation Operator value.
     * @param attributeValue  Filter attribute value.
     * @param delimiter       Filter delimiter based on search type.
     * @return Search attribute value.
     */
    private String createSearchValueForEwOperation(String attributeName, String filterOperation, String attributeValue,
                                                          String delimiter) {

        /*
         *For attributes which support domain embedding, create search value by appending the delimiter after
         * the domain separator.
         */
        if (isDomainSupportedAttribute(attributeName)) {
            // Extract the domain attached to the attribute value and then append the delimiter.
            String[] attributeItems = attributeValue.split(CarbonConstants.DOMAIN_SEPARATOR, 2);
            if (attributeItems.length > 1) {
                return createSearchValueWithDomainForCoEwOperations(attributeName, filterOperation, attributeValue,
                        delimiter, attributeItems);
            } else {
                return delimiter + attributeValue;
            }
        } else {
            return delimiter + attributeValue;
        }
    }

    /**
     * Checks whether the regex validation for user claim input is enabled.
     *
     * @return True if regex validation for user claims enabled.
     */
    public static boolean isRegexValidationForUserClaimEnabled() {

        return Boolean.parseBoolean(IdentityUtil
                .getProperty(SCIMCommonConstants.ENABLE_REGEX_VALIDATION_FOR_USER_CLAIM_INPUTS));
    }

    /**
     * Returns SCIM2 custom AttributeSchema of the tenant.
     *
     * @param tenantId  Tenant ID.
     * @return scim2 custom schema.
     * @throws CharonException If an error occurred in retrieving custom schema.
     */
    public static AttributeSchema buildCustomSchema(int tenantId) throws CharonException {

        if (!SCIMCommonUtils.isCustomSchemaEnabled()) {
            return null;
        }
        try {
            SCIMCustomSchemaProcessor scimCustomSchemaProcessor = new SCIMCustomSchemaProcessor();
            List<SCIMCustomAttribute> attributes =
                    scimCustomSchemaProcessor.getCustomAttributes(IdentityTenantUtil.getTenantDomain(tenantId),
                            getCustomSchemaURI());
            AttributeSchema attributeSchema = SCIMCustomSchemaExtensionBuilder.getInstance()
                    .buildUserCustomSchemaExtension(attributes);
            SCIMCustomAttributeSchemaCache.getInstance().addSCIMCustomAttributeSchema(tenantId, attributeSchema);
            return attributeSchema;
        } catch (InternalErrorException | IdentitySCIMException e) {
            throw new CharonException("Error while building scim custom schema", e);
        }
    }

    public static void updateEveryOneRoleV2MetaData(int tenantId) {

        // Handle everyone role creation also here if legacy runtime is disabled.
        if (!CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME) {
            try {
                UserStoreManager userStoreManager = (UserStoreManager) SCIMCommonComponentHolder.getRealmService().
                        getTenantUserRealm(tenantId).getUserStoreManager();
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(userStoreManager.getTenantId());
                String everyoneRoleName = userStoreManager.getRealmConfiguration().getEveryOneRoleName();
                if (!scimGroupHandler.isGroupExisting(everyoneRoleName)) {
                    scimGroupHandler.addRoleV2MandatoryAttributes(everyoneRoleName);
                }
            } catch (org.wso2.carbon.user.api.UserStoreException | IdentitySCIMException e) {
                log.error(e);
            }
        }
    }

    /**
     * Update system role meta data.
     *
     * @param tenantId Tenant Id.
     */
    public static void updateSystemRoleV2MetaData(int tenantId) {

        // Handle system role creation also here if legacy runtime is disabled.
        if (!CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME) {
            try {
                UserStoreManager userStoreManager = (UserStoreManager) SCIMCommonComponentHolder.getRealmService().
                        getTenantUserRealm(tenantId).getUserStoreManager();
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(userStoreManager.getTenantId());
                if (!scimGroupHandler.isGroupExisting(AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE)) {
                    scimGroupHandler.addRoleV2MandatoryAttributes(AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE);
                }
            } catch (org.wso2.carbon.user.api.UserStoreException | IdentitySCIMException e) {
                log.error(e);
            }
        }
    }

    /**
     * Get the request initiating (logged in) user ID.
     *
     * @return logged in user ID.
     */
    public static String getLoggedInUserID() throws CharonException {

        if (PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserId() != null) {
            return PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserId();
        }
        try {
            String loggedInUserName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
            String loggedInUserTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            UserIDResolver userIDResolver = new UserIDResolver();
            return userIDResolver.getIDByName(loggedInUserName, loggedInUserTenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new CharonException("Error occurred while retrieving super admin ID.", e);
        }
    }

    /**
     * Check whether the given tenant domain is an organization.
     *
     * @param tenantDomain Tenant domain of the request.
     * @return True if the tenant domain is an organization.
     * @throws CharonException If an error occurred while checking the organization state.
     */
    public static boolean isOrganization(String tenantDomain) throws CharonException {

        try {
            return OrganizationManagementUtil.isOrganization(tenantDomain);
        } catch (OrganizationManagementException e) {
            throw new CharonException("Error occurred while checking the organization state.", e);
        }
    }

    /**
     * Validate the count query parameter.
     *
     * @param count Requested item count.
     * @return Validated count parameter.
     */
    public static int validateCountParameter(Integer count) {

        int maximumItemsPerPage = IdentityUtil.getMaximumItemPerPage();
        if (count > maximumItemsPerPage) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Given limit exceeds the maximum limit. Therefore the limit is set to %s.",
                        maximumItemsPerPage));
            }
            return maximumItemsPerPage;
        }

        return count;
    }
}
