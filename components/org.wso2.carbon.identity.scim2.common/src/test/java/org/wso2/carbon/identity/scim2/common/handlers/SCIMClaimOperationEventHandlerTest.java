package org.wso2.carbon.identity.scim2.common.handlers;

import org.mockito.MockedStatic;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.scim2.common.cache.SCIMCustomAttributeSchemaCache;
import org.wso2.carbon.identity.scim2.common.cache.SCIMSystemAttributeSchemaCache;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.schema.AttributeSchema;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.identity.scim2.common.handlers.SCIMClaimOperationEventHandler.WSO2_CARBON_DIALECT;

@WithCarbonHome
public class SCIMClaimOperationEventHandlerTest {

    private SCIMClaimOperationEventHandler handler;
    private Event mockEvent;

    @BeforeMethod
    public void setUp() {

        handler = new SCIMClaimOperationEventHandler();
        mockEvent = mock(Event.class);
    }

    @Test
    public void handleEvent_SCIMSystemUserClaimDialect_ClearsSystemCache() throws IdentityEventException {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, 1);
        eventProperties.put(IdentityEventConstants.EventProperty.CLAIM_DIALECT_URI, SCIMCommonConstants.SCIM_SYSTEM_USER_CLAIM_DIALECT);
        when(mockEvent.getEventProperties()).thenReturn(eventProperties);

        SCIMSystemAttributeSchemaCache cache = SCIMSystemAttributeSchemaCache.getInstance();
        cache.addSCIMSystemAttributeSchema(1, mock(AttributeSchema.class));

        handler.handleEvent(mockEvent);

        assertNull(cache.getSCIMSystemAttributeSchemaByTenant(1));
    }

    @Test
    public void handleEvent_CustomSchemaUri_ClearsCustomCache() throws IdentityEventException {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, 1);
        eventProperties.put(IdentityEventConstants.EventProperty.CLAIM_DIALECT_URI, SCIMCommonUtils.getCustomSchemaURI());
        when(mockEvent.getEventProperties()).thenReturn(eventProperties);

        SCIMCustomAttributeSchemaCache cache = SCIMCustomAttributeSchemaCache.getInstance();
        cache.addSCIMCustomAttributeSchema(1, mock(AttributeSchema.class));

        handler.handleEvent(mockEvent);

        assertNull(cache.getSCIMCustomAttributeSchemaByTenant(1));
    }

    @Test
    public void handleEvent_LocalClaimUpdate_ClearsBothCaches() throws IdentityEventException {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, 1);
        eventProperties.put(IdentityEventConstants.EventProperty.CLAIM_DIALECT_URI, WSO2_CARBON_DIALECT);
        when(mockEvent.getEventProperties()).thenReturn(eventProperties);

        SCIMSystemAttributeSchemaCache systemCache = SCIMSystemAttributeSchemaCache.getInstance();
        SCIMCustomAttributeSchemaCache customCache = SCIMCustomAttributeSchemaCache.getInstance();
        systemCache.addSCIMSystemAttributeSchema(1, mock(AttributeSchema.class));
        customCache.addSCIMCustomAttributeSchema(1, mock(AttributeSchema.class));

        handler.handleEvent(mockEvent);

        assertNull(systemCache.getSCIMSystemAttributeSchemaByTenant(1));
        assertNull(customCache.getSCIMCustomAttributeSchemaByTenant(1));
    }

    @Test
    public void handleEvent_CustomSchemaDisabled_DoesNotClearCache() throws IdentityEventException {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, 1);
        eventProperties.put(IdentityEventConstants.EventProperty.CLAIM_DIALECT_URI, SCIMCommonUtils.getCustomSchemaURI());
        when(mockEvent.getEventProperties()).thenReturn(eventProperties);

        MockedStatic<SCIMCommonUtils> mockUtils = mockStatic(SCIMCommonUtils.class);
        mockUtils.when(SCIMCommonUtils::isCustomSchemaEnabled).thenReturn(false);
        SCIMCustomAttributeSchemaCache cache = SCIMCustomAttributeSchemaCache.getInstance();
        cache.addSCIMCustomAttributeSchema(1, mock(AttributeSchema.class));

        handler.handleEvent(mockEvent);

        assertNotNull(cache.getSCIMCustomAttributeSchemaByTenant(1));

        mockUtils.close();
    }
}