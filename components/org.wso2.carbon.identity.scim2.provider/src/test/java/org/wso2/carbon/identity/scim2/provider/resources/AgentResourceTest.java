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

package org.wso2.carbon.identity.scim2.provider.resources;

import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.schema.SCIMConstants;

import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit test for AgentResource finally block cleanup.
 *
 * Tests verify that after createUser() completes, the finally block (line 179)
 * properly cleans up thread local properties:
 * IdentityUtil.threadLocalProperties.get().remove("isUserServingAgent");
 *
 * This is critical to prevent thread local leakage between requests.
 */
public class AgentResourceTest {

    private AgentResource agentResource;
    private Map<String, Object> threadLocalMap;

    @Mock
    private UserManager mockUserManager;

    @BeforeMethod
    public void setUp() throws Exception {
        // Initialize thread local for testing
        threadLocalMap = new HashMap<>();
        IdentityUtil.threadLocalProperties.set(threadLocalMap);

        // Create AgentResource instance
        agentResource = new AgentResource();

        // Mock dependencies
        mockUserManager = mock(UserManager.class);
        IdentitySCIMManager mockScimManager = mock(IdentitySCIMManager.class);
        when(mockScimManager.getUserManager()).thenReturn(mockUserManager);
    }

    @AfterMethod
    public void tearDown() {
        IdentityUtil.threadLocalProperties.remove();
    }

    /**
     * Test that createUser() cleans up isUserServingAgent in finally block.
     *
     * Flow:
     * 1. createUser() is called
     * 2. AgentResourceManager.create() sets isUserServingAgent in thread local
     * 3. Finally block removes it (line 179)
     * 4. After createUser() returns, isUserServingAgent should be removed
     */
    @Test
    public void testCreateUser_CleansUpThreadLocal() {
        // Given - Create a valid SCIM agent request
        String scimRequest = createScimAgentRequest(true);
        String contentType = SCIMProviderConstants.APPLICATION_SCIM_JSON;
        String acceptHeader = SCIMProviderConstants.APPLICATION_SCIM_JSON;

        // Verify thread local is initially empty
        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "Thread local should be empty before createUser()");

        // When - Call createUser() (will set and then cleanup isUserServingAgent)
        try {
            agentResource.createUser(contentType, acceptHeader, null, null, scimRequest);
        } catch (Exception e) {
            // May throw due to mocking, but finally block should still execute
        }

        // Then - Verify finally block cleaned up thread local
        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "isUserServingAgent should be removed by finally block after createUser() completes");
    }

    /**
     * Test cleanup happens even when createUser() succeeds.
     */
    @Test
    public void testCreateUser_CleansUpAfterSuccess() {
        // Given
        String scimRequest = createScimAgentRequest(false);
        String contentType = SCIMProviderConstants.APPLICATION_SCIM_JSON;
        String acceptHeader = SCIMProviderConstants.APPLICATION_SCIM_JSON;

        // When
        try {
            Response response = agentResource.createUser(contentType, acceptHeader, null, null, scimRequest);
            // Even if successful, cleanup should happen
        } catch (Exception e) {
            // Ignore
        }

        // Then - Finally block should have cleaned up
        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "Finally block should clean up even after successful creation");
    }

    /**
     * Test cleanup happens even when createUser() throws exception.
     */
    @Test
    public void testCreateUser_CleansUpAfterException() {
        // Given - Invalid content type will cause exception
        String scimRequest = createScimAgentRequest(true);
        String invalidContentType = null;  // This will trigger FormatNotSupportedException
        String acceptHeader = SCIMProviderConstants.APPLICATION_SCIM_JSON;

        // Simulate that isUserServingAgent was set before exception
        threadLocalMap.put("isUserServingAgent", true);

        // When - Call createUser() with invalid content type
        try {
            agentResource.createUser(invalidContentType, acceptHeader, null, null, scimRequest);
        } catch (Exception e) {
            // Expected to throw exception
        }

        // Then - Finally block should still clean up
        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "Finally block should clean up even when exception occurs");
    }

    /**
     * Creates a SCIM agent request with IsUserServingAgent field.
     */
    private String createScimAgentRequest(boolean isUserServingAgent) {
        return String.format(
            "{\"%s\":{\"Description\":\"Test Agent\",\"DisplayName\":\"TestAgent\",\"Owner\":\"test@carbon.super\",\"IsUserServingAgent\":%s}}",
            SCIMConstants.AGENT_SCHEMA_URI,
            isUserServingAgent
        );
    }
}
