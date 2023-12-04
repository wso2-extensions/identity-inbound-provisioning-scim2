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

package org.wso2.carbon.identity.scim2.common.impl;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.utils.AuthenticationSchema;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.scim2.common.utils.SCIMConfigProcessor;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.charon3.core.config.CharonConfiguration;
import org.wso2.charon3.core.encoder.JSONEncoder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.extensions.RoleManager;
import org.wso2.charon3.core.extensions.RoleV2Manager;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.endpoints.AbstractResourceManager;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class IdentitySCIMManager {

    private static final Log log = LogFactory.getLog(IdentitySCIMManager.class);

    private static volatile IdentitySCIMManager identitySCIMManager;
    private JSONEncoder encoder = null;
    private static Map<String, String> endpointURLs = new HashMap<>();

    private IdentitySCIMManager() throws CharonException {

        init();
    }

    /**
     * Should return the static instance of CharonManager implementation.
     * Read the config and initialize extensions as specified in the config.
     *
     * @return
     */
    public static IdentitySCIMManager getInstance() throws CharonException {

        if (identitySCIMManager == null) {
            synchronized (IdentitySCIMManager.class) {
                if (identitySCIMManager == null) {
                    identitySCIMManager = new IdentitySCIMManager();
                    return identitySCIMManager;
                } else {
                    return identitySCIMManager;
                }
            }
        } else {
            return identitySCIMManager;
        }
    }

    /**
     * Perform initialization at the deployment of the webapp.
     */
    private void init() throws CharonException {

        // This is necessary to instantiate here as we need to encode exceptions if they occur.
        encoder = new JSONEncoder();

        // Define endpoint urls to be used in Location Header.
        endpointURLs.put(SCIMConstants.USER_ENDPOINT, SCIMCommonUtils.getSCIMUserURL());
        endpointURLs.put(SCIMConstants.GROUP_ENDPOINT, SCIMCommonUtils.getSCIMGroupURL());
        endpointURLs.put(SCIMConstants.ROLE_ENDPOINT, SCIMCommonUtils.getSCIMRoleURL());
        endpointURLs.put(SCIMConstants.ROLE_V2_ENDPOINT, SCIMCommonUtils.getSCIMRoleV2URL());
        endpointURLs.put(SCIMConstants.SERVICE_PROVIDER_CONFIG_ENDPOINT, SCIMCommonUtils
                .getSCIMServiceProviderConfigURL());
        endpointURLs.put(SCIMConstants.RESOURCE_TYPE_ENDPOINT, SCIMCommonUtils.getSCIMResourceTypeURL());

        // Register endpoint URLs in AbstractResourceEndpoint since they are called with in the API.
        registerEndpointURLs();

        // Register the charon related configurations.
        registerCharonConfig();
    }

    /**
     * return json encoder
     *
     * @return
     */
    public JSONEncoder getEncoder() {

        return encoder;
    }

    public UserManager getUserManager() throws CharonException {

        SCIMUserManager scimUserManager = null;
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            // Get super tenant context and get realm service which is an osgi service.
            RealmService realmService = SCIMCommonComponentHolder.getRealmService();
            if (realmService != null) {
                int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
                // Get tenant's user realm.
                UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
                if (userRealm != null) {
                    scimUserManager = new SCIMUserManager((AbstractUserStoreManager) userRealm.getUserStoreManager(),
                            SCIMCommonComponentHolder.getClaimManagementService(), tenantDomain);
                }
            } else {
                String error = "Can not obtain carbon realm service..";
                throw new CharonException(error);
            }
        } catch (UserStoreException e) {
            String error = "Error obtaining user realm for tenant: " + tenantDomain;
            throw new CharonException(error, e);
        }
        return scimUserManager;
    }

    /**
     * Obtain the role manager.
     *
     * @return RoleManager.
     */
    public RoleManager getRoleManager() {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        SCIMRoleManager scimRoleManager = new SCIMRoleManager(SCIMCommonComponentHolder.getRoleManagementService(),
                tenantDomain);
        return scimRoleManager;
    }

    /**
     * Obtain the RoleV2 manager.
     *
     * @return RoleV2Manager.
     */
    public RoleV2Manager getRoleV2Manager() {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        return new SCIMRoleManagerV2(SCIMCommonComponentHolder.getRoleManagementServiceV2(), tenantDomain);
    }

    /**
     * Resgister endpoint URLs in AbstractResourceEndpoint.
     */
    private void registerEndpointURLs() {

        AbstractResourceManager.setResourceURLBuilder(new IdentityResourceURLBuilder());
        if (MapUtils.isNotEmpty(endpointURLs)) {
            AbstractResourceManager.setEndpointURLMap(endpointURLs);
        }
    }

    /**
     * This create the basic operational configurations for charon
     */
    private void registerCharonConfig() throws CharonException {

        try {

            // Config charon.
            // This values will be used in /ServiceProviderConfigResource endpoint and some default charon configs.
            CharonConfiguration charonConfiguration = CharonConfiguration.getInstance();
            SCIMConfigProcessor scimConfigProcessor = SCIMConfigProcessor.getInstance();
            charonConfiguration.setDocumentationURL
                    (scimConfigProcessor.getProperty(SCIMCommonConstants.DOCUMENTATION_URL));
            charonConfiguration.setBulkSupport
                    (Boolean.parseBoolean(scimConfigProcessor.getProperty(SCIMCommonConstants.BULK_SUPPORTED)),
                            Integer.parseInt(scimConfigProcessor.getProperty(SCIMCommonConstants.BULK_MAX_OPERATIONS)),
                            Integer.parseInt(scimConfigProcessor.getProperty(SCIMCommonConstants
                                    .BULK_MAX_PAYLOAD_SIZE)));
            charonConfiguration.setSortSupport
                    (Boolean.parseBoolean(scimConfigProcessor.getProperty(SCIMCommonConstants.SORT_SUPPORTED)));
            charonConfiguration.setPatchSupport
                    (Boolean.parseBoolean(scimConfigProcessor.getProperty(SCIMCommonConstants.PATCH_SUPPORTED)));
            charonConfiguration.setETagSupport
                    (Boolean.parseBoolean(scimConfigProcessor.getProperty(SCIMCommonConstants.ETAG_SUPPORTED)));
            charonConfiguration.setChangePasswordSupport
                    (Boolean.parseBoolean(scimConfigProcessor.getProperty(SCIMCommonConstants
                            .CHNAGE_PASSWORD_SUPPORTED)));
            charonConfiguration.setFilterSupport
                    (Boolean.parseBoolean(scimConfigProcessor.getProperty(SCIMCommonConstants.FILTER_SUPPORTED)),
                            Integer.parseInt(scimConfigProcessor.getProperty(SCIMCommonConstants.FILTER_MAX_RESULTS)));
            charonConfiguration.setCountValueForPagination
                    (Integer.parseInt(scimConfigProcessor.getProperty(SCIMCommonConstants.PAGINATION_DEFAULT_COUNT)));

            ArrayList<Object[]> schemaList = new ArrayList<>();
            for (AuthenticationSchema authenticationSchema : scimConfigProcessor.getAuthenticationSchemas()) {
                Object[] schema = {authenticationSchema.getName(),
                        authenticationSchema.getDescription(),
                        authenticationSchema.getSpecUri(),
                        authenticationSchema.getDocumentationUri(),
                        authenticationSchema.getType(),
                        authenticationSchema.getPrimary()};
                schemaList.add(schema);
            }

            charonConfiguration.setAuthenticationSchemes(schemaList);
        } catch (Exception e) {
            throw new CharonException("Error in setting up charon configurations.", e);
        }
    }
}
