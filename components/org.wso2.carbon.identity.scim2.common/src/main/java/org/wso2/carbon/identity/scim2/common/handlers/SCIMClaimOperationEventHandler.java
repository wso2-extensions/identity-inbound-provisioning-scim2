package org.wso2.carbon.identity.scim2.common.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.scim2.common.cache.SCIMCustomSchemaCache;

import static org.wso2.charon3.core.schema.SCIMConstants.CUSTOM_USER_SCHEMA_URI;

public class SCIMClaimOperationEventHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(SCIMClaimOperationEventHandler.class);
    public static final String WSO2_CARBON_DIALECT = "http://wso2.org/claims";

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        log.info(event.getEventName() + " event received to SCIMClaimOperationEventHandler.");
        if (log.isDebugEnabled()) {
            log.debug(event.getEventName() + " event received to SCIMClaimOperationEventHandler.");
        }
        if (!IdentityEventConstants.Event.POST_UPDATE_LOCAL_CLAIM.equals(event.getEventName()) &&
                !IdentityEventConstants.Event.POST_UPDATE_EXTERNAL_CLAIM.equals(event.getEventName()) &&
                !IdentityEventConstants.Event.POST_DELETE_EXTERNAL_CLAIM.equals(event.getEventName()) &&
                !IdentityEventConstants.Event.POST_ADD_LOCAL_CLAIM.equals(event.getEventName())) {
            return;
        }

        String claimDialectUri = (String) event.getEventProperties().get("ClaimDialect");

        if (!CUSTOM_USER_SCHEMA_URI.equals(claimDialectUri) && !WSO2_CARBON_DIALECT.equals(claimDialectUri)) {
            return;
        } else {
            int tenantId = (int) event.getEventProperties().get(IdentityEventConstants.EventProperty.TENANT_ID);
            SCIMCustomSchemaCache.getInstance().clearCustomAttributesFromCacheByTenantId(tenantId);
        }
    }

    @Override
    public String getName() {

        return "SCIMClaimOperationEventHandler";
    }
}
