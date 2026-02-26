/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.scim2.provider.extensions;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * Unit test for the setIsUserServingAgent() method in AgentResourceManager.
 *
 * Uses Java Reflection to test the private setIsUserServingAgent() method.
 * Tests verify that:
 * - IsUserServingAgent flag is extracted from SCIM request
 * - It is correctly set in thread local properties
 * - Handles missing fields and defaults to false
 * - Handles errors gracefully
 */
public class AgentResourceManagerTest {

    private AgentResourceManager agentResourceManager;
    private Map<String, Object> threadLocalMap;
    private Method setIsUserServingAgentMethod;

    @BeforeMethod
    public void setUp() throws Exception {
        // Initialize thread local for testing
        threadLocalMap = new HashMap<>();
        IdentityUtil.threadLocalProperties.set(threadLocalMap);

        // Create AgentResourceManager instance
        agentResourceManager = new AgentResourceManager();

        // Use Reflection to access the private setIsUserServingAgent method
        setIsUserServingAgentMethod = AgentResourceManager.class
            .getDeclaredMethod("setIsUserServingAgent", String.class);
        setIsUserServingAgentMethod.setAccessible(true); // Bypass private access
    }

    @AfterMethod
    public void tearDown() {
        IdentityUtil.threadLocalProperties.remove();
    }

    /**
     * Test that IsUserServingAgent is set to TRUE when present in the SCIM request.
     * Uses reflection to call the private method directly.
     */
    @Test
    public void testSetIsUserServingAgent_True() throws Exception {
        // Given - SCIM request with IsUserServingAgent = true
        String scimRequest = createScimRequest(true);

        // When - Call the private method using reflection
        setIsUserServingAgentMethod.invoke(agentResourceManager, scimRequest);

        // Then - Check thread local properties were set correctly
        Object isUserServingAgent = threadLocalMap.get("isUserServingAgent");
        Assert.assertNotNull(isUserServingAgent, "isUserServingAgent should be set in thread local");
        Assert.assertTrue((Boolean) isUserServingAgent,
            "isUserServingAgent should be TRUE when present in request");
    }

    /**
     * Test that IsUserServingAgent is set to FALSE when present in the SCIM request.
     */
    @Test
    public void testSetIsUserServingAgent_False() throws Exception {
        // Given - SCIM request with IsUserServingAgent = false
        String scimRequest = createScimRequest(false);

        // When - Call the private method using reflection
        setIsUserServingAgentMethod.invoke(agentResourceManager, scimRequest);

        // Then - Check thread local properties were set correctly
        Object isUserServingAgent = threadLocalMap.get("isUserServingAgent");
        Assert.assertNotNull(isUserServingAgent, "isUserServingAgent should be set in thread local");
        Assert.assertFalse((Boolean) isUserServingAgent,
            "isUserServingAgent should be FALSE when explicitly set to false in request");
    }

    /**
     * Test that IsUserServingAgent defaults to FALSE when NOT present in the SCIM request.
     */
    @Test
    public void testSetIsUserServingAgent_MissingField() throws Exception {
        // Given - SCIM request WITHOUT IsUserServingAgent field
        String scimRequest = createScimRequestWithoutIsUserServingAgent();

        // When - Call the private method using reflection
        setIsUserServingAgentMethod.invoke(agentResourceManager, scimRequest);

        // Then - Check thread local properties default to false
        Object isUserServingAgent = threadLocalMap.get("isUserServingAgent");
        Assert.assertNotNull(isUserServingAgent, "isUserServingAgent should be set in thread local");
        Assert.assertFalse((Boolean) isUserServingAgent,
            "isUserServingAgent should default to FALSE when not present in request");
    }

    /**
     * Test that IsUserServingAgent defaults to FALSE when agent schema is missing.
     */
    @Test
    public void testSetIsUserServingAgent_NoAgentSchema() throws Exception {
        // Given - SCIM request without agent schema
        String scimRequest = "{\"userName\":\"test-agent\"}";

        // When - Call the private method using reflection
        setIsUserServingAgentMethod.invoke(agentResourceManager, scimRequest);

        // Then - Check thread local properties default to false
        Object isUserServingAgent = threadLocalMap.get("isUserServingAgent");
        Assert.assertNotNull(isUserServingAgent, "isUserServingAgent should be set in thread local");
        Assert.assertFalse((Boolean) isUserServingAgent,
            "isUserServingAgent should default to FALSE when agent schema is missing");
    }

    /**
     * Test that null value for IsUserServingAgent is handled gracefully.
     */
    @Test
    public void testSetIsUserServingAgent_NullValue() throws Exception {
        // Given - SCIM request with null IsUserServingAgent
        String scimRequest = String.format(
            "{\"%s\":{\"Description\":\"Test Agent\",\"DisplayName\":\"TestAgent\",\"Owner\":\"test@carbon.super\",\"IsUserServingAgent\":null}}",
            SCIMConstants.AGENT_SCHEMA_URI
        );

        // When - Call the private method using reflection
        setIsUserServingAgentMethod.invoke(agentResourceManager, scimRequest);

        // Then - Check thread local properties default to false
        Object isUserServingAgent = threadLocalMap.get("isUserServingAgent");
        Assert.assertNotNull(isUserServingAgent, "isUserServingAgent should be set in thread local");
        Assert.assertFalse((Boolean) isUserServingAgent,
            "isUserServingAgent should default to FALSE when value is null");
    }

    /**
     * Test that empty JSON object defaults to FALSE.
     */
    @Test
    public void testSetIsUserServingAgent_EmptyJSON() throws Exception {
        // Given - Empty JSON object
        String scimRequest = "{}";

        // When - Call the private method using reflection
        setIsUserServingAgentMethod.invoke(agentResourceManager, scimRequest);

        // Then - Check thread local properties default to false
        Object isUserServingAgent = threadLocalMap.get("isUserServingAgent");
        Assert.assertNotNull(isUserServingAgent, "isUserServingAgent should be set in thread local");
        Assert.assertFalse((Boolean) isUserServingAgent,
            "isUserServingAgent should default to FALSE for empty JSON");
    }

    /**
     * Creates a SCIM request with IsUserServingAgent field.
     * This matches the actual API request format.
     */
    private String createScimRequest(boolean isUserServingAgent) {
        return String.format(
            "{\"%s\":{\"Description\":\"Test Agent\",\"DisplayName\":\"TestAgent\",\"Owner\":\"test@carbon.super\",\"IsUserServingAgent\":%s}}",
            SCIMConstants.AGENT_SCHEMA_URI,
            isUserServingAgent
        );
    }

    /**
     * Creates a SCIM request WITHOUT IsUserServingAgent field.
     */
    private String createScimRequestWithoutIsUserServingAgent() {
        return String.format(
            "{\"%s\":{\"Description\":\"Test Agent\",\"DisplayName\":\"TestAgent\",\"Owner\":\"test@carbon.super\"}}",
            SCIMConstants.AGENT_SCHEMA_URI
        );
    }
}
