/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.inbound.provisioning.scim2.common.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.internal.IdentitySCIMDataHolder;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.mgt.service.RealmService;
import org.wso2.charon.core.v2.config.CharonConfiguration;
import org.wso2.charon.core.v2.encoder.JSONEncoder;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.protocol.endpoints.AbstractResourceManager;
import org.wso2.charon.core.v2.schema.SCIMConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Identity SCIM Manager which does the initialization.
 */
public class IdentitySCIMManager {
    private static Logger logger = LoggerFactory.getLogger(IdentitySCIMManager.class);

    private static volatile IdentitySCIMManager identitySCIMManager;
    private JSONEncoder encoder = null;
    private static Map<String, String> endpointURLs = new HashMap<String, String>();

    private IdentitySCIMManager() throws CharonException {
        init();
    }

    /*
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

    /*
     * Perform initialization at the deployment of the webapp.
     */
    private void init() throws CharonException {
        //this is necessary to instantiate here as we need to encode exceptions if they occur.
        encoder = new JSONEncoder();
        //Define endpoint urls to be used in Location Header
        endpointURLs.put(SCIMConstants.USER_ENDPOINT, SCIMCommonUtils.getSCIMUserURL());
        endpointURLs.put(SCIMConstants.GROUP_ENDPOINT, SCIMCommonUtils.getSCIMGroupURL());
        endpointURLs.put(SCIMConstants.SERVICE_PROVIDER_CONFIG_ENDPOINT, SCIMCommonUtils
                .getSCIMServiceProviderConfigURL());
        endpointURLs.put(SCIMConstants.RESOURCE_TYPE_ENDPOINT, SCIMCommonUtils.getSCIMResourceTypeURL());
        //register endpoint URLs in AbstractResourceEndpoint since they are called with in the API
        registerEndpointURLs();
        //register the charon related configurations
        registerCharonConfig();
    }

    /*
     * return json encoder
     *
     * @return
     */
    public JSONEncoder getEncoder() {
        return encoder;
    }


    public UserManager getUserManager() throws CharonException {
        CarbonUserManager carbonUserManager = null;
        RealmService realmService = (RealmService) IdentitySCIMDataHolder.getInstance().getRealmService();
        if (realmService != null) {
            carbonUserManager = new CarbonUserManager(realmService.getIdentityStore());
            return carbonUserManager;
        } else {
            String error = "Can not obtain carbon realm service..";
            throw new CharonException(error);
        }
    }


    /*
     * Resgister endpoint URLs in AbstractResourceEndpoint.
     */
    private void registerEndpointURLs() {
        if (endpointURLs != null && !endpointURLs.isEmpty()) {
            AbstractResourceManager.setEndpointURLMap(endpointURLs);
        }
    }

    /*
     * This create the basic operational configurations for charon
     */
    private void registerCharonConfig() {
        //config charon
        //this values will be used in /ServiceProviderConfigResource endpoint
        CharonConfiguration.getInstance().setDocumentationURL(SCIMCommonConstants.DOCUMENTATION_URL);
        CharonConfiguration.getInstance().setBulkSupport(false,
                SCIMCommonConstants.MAX_OPERATIONS,
                SCIMCommonConstants.MAX_PAYLOAD_SIZE);
        CharonConfiguration.getInstance().setSortSupport(false);
        CharonConfiguration.getInstance().setETagSupport(false);
        CharonConfiguration.getInstance().setChangePasswordSupport(true);
        CharonConfiguration.getInstance().setFilterSupport(true, SCIMCommonConstants.MAX_RESULTS);
        CharonConfiguration.getInstance().setPatchSupport(false);
        CharonConfiguration.getInstance().setCountValueForPagination(SCIMCommonConstants.COUNT_FOR_PAGINATION);

        Object[] auth1 = {SCIMCommonConstants.AUTHENTICATION_SCHEMES_NAME_1,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_DESCRIPTION_1,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_SPEC_URI_1,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_DOCUMENTATION_URL_1,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_TYPE_1,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_PRIMARY_1};

        Object[] auth2 = {SCIMCommonConstants.AUTHENTICATION_SCHEMES_NAME_2,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_DESCRIPTION_2,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_SPEC_URI_2,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_DOCUMENTATION_URL_2,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_TYPE_2,
                SCIMCommonConstants.AUTHENTICATION_SCHEMES_PRIMARY_2};
        ArrayList<Object[]> authList = new ArrayList<Object[]>();
        authList.add(auth1);
        authList.add(auth2);
        CharonConfiguration.getInstance().setAuthenticationSchemes(authList);
    }
}
