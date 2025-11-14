/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.schema.AttributeSchema;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;

/**
 * Unit tests for SCIMAgentAttributeSchemaCache.
 */
@WithCarbonHome
public class SCIMAgentAttributeSchemaCacheTest {

    private SCIMAgentAttributeSchemaCache cache;
    private AttributeSchema mockAttributeSchema;
    private MockedStatic<SCIMCommonUtils> scimCommonUtilsStaticMock;

    private final List<Integer> v0TenantList = new ArrayList<>(Collections.singletonList(1));
    private final List<Integer> v1TenantList = new ArrayList<>(Arrays.asList(1, 111));

    @BeforeClass
    public void setUpTests() {

        scimCommonUtilsStaticMock = mockStatic(SCIMCommonUtils.class);
    }

    @BeforeMethod
    public void setUp() {
        cache = SCIMAgentAttributeSchemaCache.getInstance();
        mockAttributeSchema = mock(AttributeSchema.class);
    }

    @Test
    public void testAddSCIMAgentAttributeSchema() {
        cache.addSCIMAgentAttributeSchema(1, mockAttributeSchema);
        AttributeSchema result = cache.getSCIMAgentAttributeSchemaByTenant(1);
        assertNotNull(result);
        assertEquals(mockAttributeSchema, result);
    }

    @Test
    public void testGetSCIMAgentAttributeSchemaByTenant() {
        cache.addSCIMAgentAttributeSchema(1, mockAttributeSchema);
        AttributeSchema result = cache.getSCIMAgentAttributeSchemaByTenant(1);
        assertNotNull(result);
        assertEquals(mockAttributeSchema, result);
    }

    @Test
    public void testGetSCIMAgentAttributeSchemaByTenant_NotFound() {
        AttributeSchema result = cache.getSCIMAgentAttributeSchemaByTenant(999);
        assertNull(result);
    }

    @Test
    public void testClearSCIMAgentAttributeSchemaByTenant() {

        scimCommonUtilsStaticMock.when(() -> SCIMCommonUtils.getOrganizationsToInvalidateCaches(1))
                .thenReturn(v0TenantList);
        cache.addSCIMAgentAttributeSchema(1, mockAttributeSchema);
        cache.addSCIMAgentAttributeSchema(111, mockAttributeSchema);
        cache.clearSCIMAgentAttributeSchemaByTenant(1);
        AttributeSchema result = cache.getSCIMAgentAttributeSchemaByTenant(1);
        assertNull(result);
        AttributeSchema subOrgResult = cache.getSCIMAgentAttributeSchemaByTenant(111);
        assertNotNull(subOrgResult);
    }

    @Test
    public void testClearSCIMAgentAttributeSchemaByV1Tenant() {

        scimCommonUtilsStaticMock.when(() -> SCIMCommonUtils.getOrganizationsToInvalidateCaches(1))
                .thenReturn(v1TenantList);
        cache.addSCIMAgentAttributeSchema(1, mockAttributeSchema);
        cache.addSCIMAgentAttributeSchema(111, mockAttributeSchema);
        cache.clearSCIMAgentAttributeSchemaByTenant(1);
        AttributeSchema result = cache.getSCIMAgentAttributeSchemaByTenant(1);
        assertNull(result);
        AttributeSchema subOrgResult = cache.getSCIMAgentAttributeSchemaByTenant(111);
        assertNull(subOrgResult);
    }

    @Test
    public void testSingletonInstance() {
        SCIMAgentAttributeSchemaCache instance1 = SCIMAgentAttributeSchemaCache.getInstance();
        SCIMAgentAttributeSchemaCache instance2 = SCIMAgentAttributeSchemaCache.getInstance();
        assertSame(instance1, instance2);
    }

    @Test
    public void testClearSCIMAgentAttributeSchemaByTenant_NonExistentTenant() {
        cache.clearSCIMAgentAttributeSchemaByTenant(999);
        // No exception should be thrown.
    }

    @Test
    public void testCacheKeyEquality() {
        SCIMAgentAttributeSchemaCacheKey key1 = new SCIMAgentAttributeSchemaCacheKey(1);
        SCIMAgentAttributeSchemaCacheKey key2 = new SCIMAgentAttributeSchemaCacheKey(1);
        SCIMAgentAttributeSchemaCacheKey key3 = new SCIMAgentAttributeSchemaCacheKey(2);

        assertEquals(key1, key2);
        assertNotEquals(key1, key3);
    }

    @Test
    public void testCacheKeyHashCode() {
        SCIMAgentAttributeSchemaCacheKey key1 = new SCIMAgentAttributeSchemaCacheKey(1);
        SCIMAgentAttributeSchemaCacheKey key2 = new SCIMAgentAttributeSchemaCacheKey(1);

        assertEquals(key1.hashCode(), key2.hashCode());
    }

    @Test
    public void testMultipleTenants() {
        AttributeSchema schema1 = mock(AttributeSchema.class);
        AttributeSchema schema2 = mock(AttributeSchema.class);

        cache.addSCIMAgentAttributeSchema(1, schema1);
        cache.addSCIMAgentAttributeSchema(2, schema2);

        assertEquals(schema1, cache.getSCIMAgentAttributeSchemaByTenant(1));
        assertEquals(schema2, cache.getSCIMAgentAttributeSchemaByTenant(2));
    }

    @Test
    public void testOverwriteExistingEntry() {
        AttributeSchema firstSchema = mock(AttributeSchema.class);
        AttributeSchema secondSchema = mock(AttributeSchema.class);

        cache.addSCIMAgentAttributeSchema(1, firstSchema);
        cache.addSCIMAgentAttributeSchema(1, secondSchema);

        AttributeSchema result = cache.getSCIMAgentAttributeSchemaByTenant(1);
        assertEquals(secondSchema, result);
        assertNotEquals(firstSchema, result);
    }

    @Test
    public void testCacheEntryConstructor() {
        SCIMAgentAttributeSchemaCacheEntry entry = new SCIMAgentAttributeSchemaCacheEntry(mockAttributeSchema);
        assertEquals(mockAttributeSchema, entry.getSCIMAgentAttributeSchema());
    }

    @Test
    public void testCacheKeyGetTenantId() {
        int tenantId = 123;
        SCIMAgentAttributeSchemaCacheKey key = new SCIMAgentAttributeSchemaCacheKey(tenantId);
        assertEquals(tenantId, key.getTenantId());
    }

    @Test
    public void testCacheKeyEqualityWithSameObject() {
        SCIMAgentAttributeSchemaCacheKey key = new SCIMAgentAttributeSchemaCacheKey(1);
        assertEquals(key, key);
    }

    @Test
    public void testCacheKeyEqualityWithNull() {
        SCIMAgentAttributeSchemaCacheKey key = new SCIMAgentAttributeSchemaCacheKey(1);
        assertNotEquals(key, null);
    }

    @Test
    public void testCacheKeyEqualityWithDifferentClass() {
        SCIMAgentAttributeSchemaCacheKey key = new SCIMAgentAttributeSchemaCacheKey(1);
        String differentObject = "different";
        assertNotEquals(key, differentObject);
    }

    @Test
    public void testNullAttributeSchema() {
        cache.addSCIMAgentAttributeSchema(1, null);
        AttributeSchema result = cache.getSCIMAgentAttributeSchemaByTenant(1);
        assertNull(result);
    }

    @Test
    public void testConcurrentAccess() throws InterruptedException {
        final int tenantId = 1;
        final AttributeSchema schema = mock(AttributeSchema.class);

        // Thread 1: Add schema
        Thread thread1 = new Thread(() -> cache.addSCIMAgentAttributeSchema(tenantId, schema));

        // Thread 2: Get schema
        Thread thread2 = new Thread(() -> {
            try {
                Thread.sleep(10); // Small delay to ensure add operation happens first
                AttributeSchema result = cache.getSCIMAgentAttributeSchemaByTenant(tenantId);
                assertNotNull(result);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        thread1.start();
        thread2.start();

        thread1.join();
        thread2.join();

        // Verify final state
        assertEquals(schema, cache.getSCIMAgentAttributeSchemaByTenant(tenantId));
    }

    @AfterClass
    public void tearDown() {

        scimCommonUtilsStaticMock.close();
    }
}
