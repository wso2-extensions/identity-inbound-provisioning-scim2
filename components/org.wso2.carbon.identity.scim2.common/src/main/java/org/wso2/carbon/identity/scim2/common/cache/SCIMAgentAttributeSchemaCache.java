/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.charon3.core.schema.AttributeSchema;

/**
 * This stores agent AttributeSchema against tenants.
 */
public class SCIMAgentAttributeSchemaCache 
        extends BaseCache<SCIMAgentAttributeSchemaCacheKey, SCIMAgentAttributeSchemaCacheEntry> {

    private static final String SCIM_AGENT_SCHEMA_CACHE = "SCIMAgentAttributeSchemaCache";
    private static final Log log = LogFactory.getLog(SCIMAgentAttributeSchemaCache.class);

    private static volatile SCIMAgentAttributeSchemaCache instance;

    private SCIMAgentAttributeSchemaCache() {

        super(SCIM_AGENT_SCHEMA_CACHE);
    }

    public static SCIMAgentAttributeSchemaCache getInstance() {

        if (instance == null) {
            synchronized (SCIMAgentAttributeSchemaCache.class) {
                if (instance == null) {
                    instance = new SCIMAgentAttributeSchemaCache();
                }
            }
        }
        return instance;
    }

    /**
     * Add agent attribute schema to cache against tenantId.
     *
     * @param tenantId TenantId.
     * @param agentAttributeSchema AgentAttributeSchema.
     */
    public void addSCIMAgentAttributeSchema(int tenantId, AttributeSchema agentAttributeSchema){

        SCIMAgentAttributeSchemaCacheKey cacheKey = new SCIMAgentAttributeSchemaCacheKey(tenantId);
        SCIMAgentAttributeSchemaCacheEntry cacheEntry = new SCIMAgentAttributeSchemaCacheEntry(agentAttributeSchema);
        super.addToCache(cacheKey, cacheEntry);
        if (log.isDebugEnabled()) {
            log.debug("Successfully added scim agent attributes into SCIMAgentSchemaCache for the tenant:"
                    + tenantId);
        }

    }


    /**
     * Get SCIM2 Agent AttributeSchema by tenantId.
     *
     * @param tenantId TenantId.
     * @return AttributeSchema.
     */
    public AttributeSchema getSCIMAgentAttributeSchemaByTenant(int tenantId) {

        SCIMAgentAttributeSchemaCacheKey cacheKey = new SCIMAgentAttributeSchemaCacheKey(tenantId);
        SCIMAgentAttributeSchemaCacheEntry cacheEntry = super.getValueFromCache(cacheKey);
        if (cacheEntry != null) {
            return cacheEntry.getSCIMAgentAttributeSchema();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Cache entry is null for tenantId: " + tenantId);
            }
            return null;
        }
    }

    /**
     * Clear SCIM2 Agent AttributeSchema by tenantId.
     *
     * @param tenantId TenantId.
     */
    public void clearSCIMAgentAttributeSchemaByTenant(int tenantId) {

        if (log.isDebugEnabled()) {
            log.debug("Clearing SCIMAgentAttributeSchemaCache entry by the tenant with id: " + tenantId);
        }
        SCIMAgentAttributeSchemaCacheKey cacheKey = new SCIMAgentAttributeSchemaCacheKey(tenantId);
        super.clearCacheEntry(cacheKey);
    }
}
