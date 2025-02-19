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

package org.wso2.carbon.identity.scim2.common.handlers;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.util.DialectConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.scim2.common.cache.SCIMCustomAttributeSchemaCache;
import org.wso2.carbon.identity.scim2.common.cache.SCIMSystemAttributeSchemaCache;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.SCIM_CORE_CLAIM_DIALECT;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.SCIM_ENTERPRISE_USER_CLAIM_DIALECT;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.SCIM_SYSTEM_USER_CLAIM_DIALECT;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.getCustomSchemaURI;

/**
 * This handles the claim metadata operation related events and it will clear the SCIMCustomAttributeSchema
 * cache when the event is triggered. This depends on the local claim update, external claim on custom schema
 * related operations and deleting of the custom schema. When these relevant events are fired the cache will be
 * cleared based on the tenant and the cache will be rebuilt with the next SCIM api request.
 */
public class SCIMClaimOperationEventHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(SCIMClaimOperationEventHandler.class);
    public static final String WSO2_CARBON_DIALECT = "http://wso2.org/claims";

    /**
     * This handles the claim related operations that are subscribed and clear the SCIMCustomAttributeSchema which
     * contains the all the custom attributes belong to the custom schema of the tenant.
     *
     * @param event Event.
     * @throws IdentityEventException
     */
    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        int tenantId = (int) event.getEventProperties().get(IdentityEventConstants.EventProperty.TENANT_ID);
        if (log.isDebugEnabled()) {
            log.debug(event.getEventName() + " event received to SCIMClaimOperationEventHandler for the tenant with " +
                    "Id: " + tenantId);
        }

        if (IdentityEventConstants.Event.PRE_ADD_EXTERNAL_CLAIM.equals(event.getEventName())) {
            handleSCIMExternalClaimAddEvent(event);
        }

        if (!SCIMCommonUtils.isCustomSchemaEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("SCIM2 Custom user schema has disabled in server level.");
            }
            return;
        }

        String claimDialectUri =
                (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.CLAIM_DIALECT_URI);
        if (!getCustomSchemaURI().equalsIgnoreCase(claimDialectUri) &&
                !SCIM_SYSTEM_USER_CLAIM_DIALECT.equals(claimDialectUri) &&
                !WSO2_CARBON_DIALECT.equalsIgnoreCase(claimDialectUri)) {
            if (log.isDebugEnabled()) {
                String message = "The event triggered in the tenant %s is not related to either local dialect or " +
                        "SCIM2 system or custom schema dialect. Hence, we skip the logic of clearing the cache.";
                log.debug(String.format(message, tenantId));
            }
            return;
        }
        // If claim dialect rename happens, then we need to check whether the custom schema has renamed to another name.
        String oldClaimDialectUri =
                (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.OLD_CLAIM_DIALECT_URI);
        if (StringUtils.isNotBlank(oldClaimDialectUri) && !oldClaimDialectUri.equalsIgnoreCase(getCustomSchemaURI())) {
            if (log.isDebugEnabled()) {
                log.debug("Needs to clear the cache only if the SCIM2 custom schema has changed");
            }
            return;
        }

        if (SCIM_SYSTEM_USER_CLAIM_DIALECT.equalsIgnoreCase(claimDialectUri)) {
            SCIMSystemAttributeSchemaCache.getInstance().clearSCIMSystemAttributeSchemaByTenant(tenantId);
        } else if (getCustomSchemaURI().equalsIgnoreCase(claimDialectUri)) {
            SCIMCustomAttributeSchemaCache.getInstance().clearSCIMCustomAttributeSchemaByTenant(tenantId);
        }

        // It is a local claim update. Clear both caches.
        SCIMSystemAttributeSchemaCache.getInstance().clearSCIMSystemAttributeSchemaByTenant(tenantId);
        SCIMCustomAttributeSchemaCache.getInstance().clearSCIMCustomAttributeSchemaByTenant(tenantId);
    }

    @Override
    public String getName() {

        return "SCIMClaimOperationEventHandler";
    }

    private void handleSCIMExternalClaimAddEvent(Event event) {

        if (!IdentityEventConstants.Event.PRE_ADD_EXTERNAL_CLAIM.equals(event.getEventName())) {
            return;
        }

        String claimDialectUri = (String) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.CLAIM_DIALECT_URI);
        String externalClaimUri = (String) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.EXTERNAL_CLAIM_URI);
        Set<String> scimClaimDialects = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                SCIM_CORE_CLAIM_DIALECT,
                SCIM_USER_CLAIM_DIALECT,
                SCIM_ENTERPRISE_USER_CLAIM_DIALECT,
                SCIM_SYSTEM_USER_CLAIM_DIALECT
        )));

        /*
         * All spec-defined claims might not be added to dialects as external claims. All supported claims can be found
         * through the schemas.profile config defined in the identity.xml. The DialectConfigParser is used to read the
         * final server supported claims.
         */
        if (DialectConfigParser.getInstance().getClaimsMap().get(externalClaimUri) != null
                && DialectConfigParser.getInstance().getClaimsMap().get(externalClaimUri).equals(claimDialectUri)) {
            return;
        }

        IdentityUtil.threadLocalProperties.get().remove(ClaimConstants.EXTERNAL_CLAIM_ADDITION_NOT_ALLOWED_FOR_DIALECT);
        if (scimClaimDialects.contains(claimDialectUri)) {
            IdentityUtil.threadLocalProperties.get()
                    .put(ClaimConstants.EXTERNAL_CLAIM_ADDITION_NOT_ALLOWED_FOR_DIALECT, true);
        }
    }
}
