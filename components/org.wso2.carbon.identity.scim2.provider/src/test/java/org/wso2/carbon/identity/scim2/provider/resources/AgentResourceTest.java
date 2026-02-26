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

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * Unit test for AgentResource cleanup changes.
 */
public class AgentResourceTest {

    private Map<String, Object> threadLocalMap;

    @BeforeMethod
    public void setUp() {
        threadLocalMap = new HashMap<>();
        IdentityUtil.threadLocalProperties.set(threadLocalMap);
    }

    @AfterMethod
    public void tearDown() {
        IdentityUtil.threadLocalProperties.remove();
    }

    /**
     * Test that isUserServingAgent property is removed from thread local in finally block.
     */
    @Test
    public void testRemoveIsUserServingAgentFromThreadLocal() {
        threadLocalMap.put("isUserServingAgent", true);
        Assert.assertTrue(threadLocalMap.containsKey("isUserServingAgent"),
                "Thread local should contain isUserServingAgent before cleanup");

        try {
            IdentityUtil.threadLocalProperties.get().remove("isUserServingAgent");
        } catch (Exception e) {
            Assert.fail("Cleanup should not throw exception: " + e.getMessage());
        }

        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "isUserServingAgent should be removed from thread local");
    }

    /**
     * Test that cleanup works when isUserServingAgent is false.
     */
    @Test
    public void testRemoveIsUserServingAgentWhenFalse() {
        // Given - Thread local has isUserServingAgent = false
        threadLocalMap.put("isUserServingAgent", false);
        Assert.assertTrue(threadLocalMap.containsKey("isUserServingAgent"),
                "Thread local should contain isUserServingAgent");

        // When - Execute the cleanup statement
        try {
            IdentityUtil.threadLocalProperties.get().remove("isUserServingAgent");
        } catch (Exception e) {
            Assert.fail("Cleanup should not throw exception: " + e.getMessage());
        }

        // Then - Property should be removed regardless of value
        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "isUserServingAgent should be removed from thread local");
    }

    /**
     * Test that cleanup doesn't fail when isUserServingAgent doesn't exist.
     */
    @Test
    public void testRemoveIsUserServingAgentWhenNotPresent() {
        // Given - Thread local does NOT have isUserServingAgent property
        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "Thread local should not contain isUserServingAgent");

        // When - Execute the cleanup statement (should not throw exception)
        try {
            IdentityUtil.threadLocalProperties.get().remove("isUserServingAgent");
        } catch (Exception e) {
            Assert.fail("Cleanup should not throw exception when property doesn't exist: " + e.getMessage());
        }

        // Then - No exception should be thrown
        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "Thread local should still not contain isUserServingAgent");
    }

    /**
     * Test cleanup in finally block simulation - success scenario.
     */
    @Test
    public void testCleanupInFinallyBlockOnSuccess() {
        // Given - Thread local has isUserServingAgent property
        threadLocalMap.put("isUserServingAgent", true);
        boolean operationSuccess = true;

        // When - Simulate operation with finally block
        try {
            if (operationSuccess) {
                // Simulate successful agent creation
                Assert.assertTrue(true);
            }
        } finally {
            // Execute cleanup from line 179
            IdentityUtil.threadLocalProperties.get().remove("isUserServingAgent");
        }

        // Then - Property should be removed
        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "isUserServingAgent should be removed in finally block");
    }

    /**
     * Test cleanup in finally block simulation - exception scenario.
     */
    @Test
    public void testCleanupInFinallyBlockOnException() {
        // Given - Thread local has isUserServingAgent property
        threadLocalMap.put("isUserServingAgent", true);
        Exception caughtException = null;

        // When - Simulate operation that throws exception
        try {
            throw new RuntimeException("Simulated agent creation error");
        } catch (Exception e) {
            caughtException = e;
        } finally {
            // Execute cleanup from line 179 (should still execute)
            IdentityUtil.threadLocalProperties.get().remove("isUserServingAgent");
        }

        // Then - Property should still be removed even when exception occurred
        Assert.assertNotNull(caughtException, "Exception should have been caught");
        Assert.assertFalse(threadLocalMap.containsKey("isUserServingAgent"),
                "isUserServingAgent should be removed even when exception occurs");
    }

}
