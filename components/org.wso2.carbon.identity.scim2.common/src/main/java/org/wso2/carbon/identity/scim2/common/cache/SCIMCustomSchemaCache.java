/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.scim2.common.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCustomSchemaProcessor;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.charon3.core.attributes.SCIMCustomAttribute;

import java.util.List;

import static org.wso2.charon3.core.schema.SCIMConstants.CUSTOM_USER_SCHEMA_URI;

/**
 * This stores custom schema against tenants. THis is a DB-backed cache.
 */
public class SCIMCustomSchemaCache extends BaseCache<SCIMCustomSchemaCacheKey, SCIMCustomSchemaCacheEntry> {

    private static final String SCIM_CUSTOM_SCHEMA_CACHE = "SCIMCustomSchemaCache";
    private static final Log log = LogFactory.getLog(SCIMCustomSchemaCache.class);

    private static volatile SCIMCustomSchemaCache instance;

    private SCIMCustomSchemaCache() {

        super(SCIM_CUSTOM_SCHEMA_CACHE);
    }

    public static SCIMCustomSchemaCache getInstance() {

        if (instance == null) {
            synchronized (SCIMCustomSchemaCache.class) {
                if (instance == null) {
                    instance = new SCIMCustomSchemaCache();
                }
            }
        }
        return instance;
    }


    public SCIMCustomSchemaCacheEntry getCustomAttributesFromCacheByTenantId(int tenantId) throws IdentitySCIMException {

        SCIMCustomSchemaCacheKey cacheKey = new SCIMCustomSchemaCacheKey(tenantId);
        SCIMCustomSchemaCacheEntry cacheEntry = super.getValueFromCache(cacheKey);
        if (cacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache entry is null. Hence getting the attribute configurations from DB for tenant: " + tenantId);
            }
            List<SCIMCustomAttribute> schemaConfigurations = null;
            String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
            schemaConfigurations = new SCIMCustomSchemaProcessor().getCustomAttributes(tenantDomain,
                    CUSTOM_USER_SCHEMA_URI);
            cacheEntry = new SCIMCustomSchemaCacheEntry(schemaConfigurations);
            super.addToCache(cacheKey, cacheEntry);
        }
        return cacheEntry;
    }

    public void clearCustomAttributesFromCacheByTenantId(int tenantId) {

        SCIMCustomSchemaCacheKey cacheKey = new SCIMCustomSchemaCacheKey(tenantId);
        super.clearCacheEntry(cacheKey);
    }
}
