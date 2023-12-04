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
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.scim2.common.cache.SCIMCustomAttributeSchemaCache;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;

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

        if (!SCIMCommonUtils.isCustomSchemaEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("SCIM2 Custom user schema has disabled in server level.");
            }
            return;
        }

        String claimDialectUri =
                (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.CLAIM_DIALECT_URI);
        if (!getCustomSchemaURI().equalsIgnoreCase(claimDialectUri) &&
                !WSO2_CARBON_DIALECT.equalsIgnoreCase(claimDialectUri)) {
            if (log.isDebugEnabled()) {
                String message = "The event triggered in the tenant %s is not related to either local dialect or " +
                        "SCIM2 custom schema dialect. Hence, we skip the logic of clearing the " +
                        "SCIMCustomAttributeSchema cache";
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

        SCIMCustomAttributeSchemaCache.getInstance().clearSCIMCustomAttributeSchemaByTenant(tenantId);
    }

    @Override
    public String getName() {

        return "SCIMClaimOperationEventHandler";
    }
}
