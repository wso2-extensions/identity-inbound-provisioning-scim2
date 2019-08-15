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

package org.wso2.carbon.identity.scim2.common.utils;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ThreadLocalProvisioningServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is to be used as a Util class for SCIM common things.
 * TODO:rename class name.
 */
public class SCIMCommonUtils {

    private static Log log = LogFactory.getLog(SCIMCommonUtils.class);

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

    public static String getSCIMServiceProviderConfigURL(String id){
        return getSCIMServiceProviderConfigURL() ;
    }

    /*Handling ThreadLocals*/

    public static String getSCIMUserURL() {
        String scimURL = getSCIMURL();
        return scimURL + SCIMCommonConstants.USERS;
    }

    public static String getSCIMGroupURL() {
        String scimURL = getSCIMURL();
        return scimURL + SCIMCommonConstants.GROUPS;
    }

    private static String getSCIMURL() {
        String scimURL;
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (isNotASuperTenantFlow(tenantDomain)) {
            scimURL = IdentityUtil.getServerURL(
                    SCIMCommonConstants.TENANT_URL_SEPERATOR + tenantDomain + SCIMCommonConstants.SCIM2_ENDPOINT, true,
                    true);
        } else {
            scimURL = IdentityUtil.getServerURL(SCIMCommonConstants.SCIM2_ENDPOINT, true, true);
        }
        return scimURL;
    }

    private static boolean isNotASuperTenantFlow(String tenantDomain) {
        return !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain);
    }

    public static String getSCIMServiceProviderConfigURL() {
        String scimURL = IdentityUtil.getServerURL(SCIMCommonConstants.SCIM2_ENDPOINT, true, true);
        String scimServiceProviderConfig = scimURL + SCIMCommonConstants.SERVICE_PROVIDER_CONFIG;
        return scimServiceProviderConfig;
    }

    public static String getSCIMResourceTypeURL() {
        String scimURL = IdentityUtil.getServerURL(SCIMCommonConstants.SCIM2_ENDPOINT, true, true);
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
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }

    public static String getUserConsumerId() {
        String userName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String currentTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
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

        String spTenantDomain = getTenantDomainFromSP();

        Map<String, String> scimToLocalClaimMap = new HashMap<>();
        try {
            Map<String, String> coreClaims = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(SCIMCommonConstants.SCIM_CORE_CLAIM_DIALECT, null,
                            spTenantDomain, false);
            scimToLocalClaimMap.putAll(coreClaims);
            Map<String, String> userClaims = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT, null,
                            spTenantDomain, false);
            scimToLocalClaimMap.putAll(userClaims);
            if (SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema() != null){
                Map<String, String> extensionClaims = ClaimMetadataHandler.getInstance()
                        .getMappingsMapFromOtherDialectToCarbon(SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema().getURI(), null,
                                spTenantDomain, false);
                scimToLocalClaimMap.putAll(extensionClaims);
            }
            return scimToLocalClaimMap;
        } catch (ClaimMetadataException e) {
            throw new UserStoreException(
                    "Error occurred while retrieving SCIM to Local claim mappings for tenant domain : " +
                            spTenantDomain , e);
        }
    }

    /**
     * This is used to get tenant domain of thread local service provider.
     *
     * @return Service provider's tenant domain.
     */
    private static String getTenantDomainFromSP() {

        String tenantDomain;
        ThreadLocalProvisioningServiceProvider threadLocalSP = IdentityApplicationManagementUtil
                .getThreadLocalProvisioningServiceProvider();
        if (threadLocalSP != null) {
            return threadLocalSP.getTenantDomain();
        } else if (PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain() != null) {
            tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        } else {
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
}
