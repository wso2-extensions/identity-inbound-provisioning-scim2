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

package org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.claim.ClaimMapper;
import org.wso2.carbon.identity.mgt.IdentityStore;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.charon3.core.config.SCIMConfigConstants;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.InternalErrorException;

import java.io.File;
import java.util.Locale;

/**
 * This class is to be used as a Util class for SCIM common things.
 */
public class SCIMCommonUtils {

    private static Logger log = LoggerFactory.getLogger(SCIMCommonUtils.class);

    public static void init() {

        String schemaFilePath = System.getProperty(ClaimMapper.CARBON_HOME) + File.separator + "conf" +
                File.separator + "identity" + File.separator + SCIMConfigConstants.SCIM_SCHEMA_EXTENSION_CONFIG;
        try {
            SCIMUserSchemaExtensionBuilder.getInstance().buildUserSchemaExtension(schemaFilePath);
        } catch (CharonException | InternalErrorException e) {
            log.error("Error in building User Schema Extension", e);
        }
    }

    public static String getSCIMUserURL() {
        return SCIMCommonConstants.USERS_LOCATION;
    }

    public static String getSCIMGroupURL() {
        return SCIMCommonConstants.GROUPS_LOCATION;
    }

    public static String getSCIMServiceProviderConfigURL() {
        return SCIMCommonConstants.SERVICE_PROVIDER_CONFIG_LOCATION;
    }

    public static String getSCIMResourceTypeURL() {
        return SCIMCommonConstants.RESOURCE_TYPE_LOCATION;
    }

    /**
     * Extract user store domain from domain qualified name. If name doesn't have domain return primary domain
     * @param nameWithDomain domain qualified name
     * @param identityStore user store api
     * @return domain append to name
     * @throws IdentityStoreException if identityStore cannot retrieve primary domain
     */
    public static String extractDomainFromName(String nameWithDomain, IdentityStore identityStore) throws
            IdentityStoreException {

        if (nameWithDomain.indexOf(SCIMCommonConstants.DOMAIN_SEPARATOR) >= 0) {
            String domain = nameWithDomain.substring(0, nameWithDomain.indexOf(SCIMCommonConstants.DOMAIN_SEPARATOR));
            return domain.toUpperCase(Locale.ENGLISH);
        } else {
            return identityStore.getPrimaryDomainName();
        }
    }

    /**
     * Remove user store domain from name. If user store domain does not exist, do nothing.
     * @param name name of the entity
     * @return domain removed name
     */
    public static String removeDomainFromName(String name) {
        int index;
        if ((index = name.indexOf("/")) >= 0) {
            name = name.substring(index + 1);
        }

        return name;
    }

}
