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
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.schema.AttributeSchema;

import java.util.List;

/**
 * This stores custom AttributeSchema against tenants.
 */
public class SCIMCustomAttributeSchemaCache extends BaseCache<SCIMCustomAttributeSchemaCacheKey, SCIMCustomAttributeSchemaCacheEntry> {

    private static final String SCIM_CUSTOM_SCHEMA_CACHE = "SCIMCustomAttributeSchemaCache";
    private static final Log log = LogFactory.getLog(SCIMCustomAttributeSchemaCache.class);

    private static volatile SCIMCustomAttributeSchemaCache instance;

    private SCIMCustomAttributeSchemaCache() {

        super(SCIM_CUSTOM_SCHEMA_CACHE);
    }

    public static SCIMCustomAttributeSchemaCache getInstance() {

        if (instance == null) {
            synchronized (SCIMCustomAttributeSchemaCache.class) {
                if (instance == null) {
                    instance = new SCIMCustomAttributeSchemaCache();
                }
            }
        }
        return instance;
    }

    /**
     * Add custom attribute schema to cache against tenantId.
     *
     * @param tenantId TenantId.
     * @param customAttributeSchema CustomAttributeSchema.
     */
    public void addSCIMCustomAttributeSchema(int tenantId, AttributeSchema customAttributeSchema){

        SCIMCustomAttributeSchemaCacheKey cacheKey = new SCIMCustomAttributeSchemaCacheKey(tenantId);
        SCIMCustomAttributeSchemaCacheEntry cacheEntry = new SCIMCustomAttributeSchemaCacheEntry(customAttributeSchema);
        super.addToCache(cacheKey, cacheEntry);
        if (log.isDebugEnabled()) {
            log.debug("Successfully added scim custom attributes into SCIMCustomSchemaCache for the tenant:"
                    + tenantId);
        }

    }


    /**
     * Get SCIM2 Custom AttributeSchema by tenantId.
     *
     * @param tenantId TenantId.
     * @return AttributeSchema.
     */
    public AttributeSchema getSCIMCustomAttributeSchemaByTenant(int tenantId) {

        SCIMCustomAttributeSchemaCacheKey cacheKey = new SCIMCustomAttributeSchemaCacheKey(tenantId);
        SCIMCustomAttributeSchemaCacheEntry cacheEntry = super.getValueFromCache(cacheKey);
        if (cacheEntry != null) {
            return cacheEntry.getSCIMCustomAttributeSchema();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Cache entry is null for tenantId: " + tenantId);
            }
            return null;
        }
    }

    /**
     * Clear SCIM2 Custom AttributeSchema by tenantId.
     *
     * For v0 organizations, this clears the cache of the current organization only.
     * For v1 organizations, this clears the caches of the current organization and its child organizations.
     *
     * @param tenantId TenantId.
     */
    public void clearSCIMCustomAttributeSchemaByTenant(int tenantId) {

        List<Integer> tenantIdsToBeInvalidated = SCIMCommonUtils.getOrganizationsToInvalidateCaches(tenantId);
        for (Integer tenantIdToBeInvalidated : tenantIdsToBeInvalidated) {
            if (log.isDebugEnabled()) {
                log.debug("Clearing SCIMCustomAttributeSchemaCache entry by the tenant with id: " +
                        tenantIdToBeInvalidated);
            }
            SCIMCustomAttributeSchemaCacheKey cacheKey = new SCIMCustomAttributeSchemaCacheKey(tenantIdToBeInvalidated);
            super.clearCacheEntry(cacheKey);
        }
    }
}
