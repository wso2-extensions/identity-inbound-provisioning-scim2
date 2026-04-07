/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 * Unit tests for SCIMCustomAttributeSchemaCache.
 */
@WithCarbonHome
public class SCIMCustomAttributeSchemaCacheTest {

    private SCIMCustomAttributeSchemaCache cache;
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

        cache = SCIMCustomAttributeSchemaCache.getInstance();
        mockAttributeSchema = mock(AttributeSchema.class);
    }

    // --- Write-path (addSCIMCustomAttributeSchema) tests ---

    @Test
    public void testAddSCIMCustomAttributeSchema() {

        cache.addSCIMCustomAttributeSchema(1, mockAttributeSchema);
        AttributeSchema result = cache.getSCIMCustomAttributeSchemaByTenant(1);
        assertNotNull(result);
        assertEquals(mockAttributeSchema, result);
    }

    @Test
    public void testGetSCIMCustomAttributeSchemaByTenant_NotFound() {

        AttributeSchema result = cache.getSCIMCustomAttributeSchemaByTenant(999);
        assertNull(result);
    }

    @Test
    public void testClearSCIMCustomAttributeSchemaByTenant() {

        scimCommonUtilsStaticMock.when(() -> SCIMCommonUtils.getOrganizationsToInvalidateCaches(1))
                .thenReturn(v0TenantList);
        cache.addSCIMCustomAttributeSchema(1, mockAttributeSchema);
        cache.addSCIMCustomAttributeSchema(111, mockAttributeSchema);
        cache.clearSCIMCustomAttributeSchemaByTenant(1);
        AttributeSchema result = cache.getSCIMCustomAttributeSchemaByTenant(1);
        assertNull(result);
        AttributeSchema subOrgResult = cache.getSCIMCustomAttributeSchemaByTenant(111);
        assertNotNull(subOrgResult);
    }

    @Test
    public void testClearSCIMCustomAttributeSchemaByV1Tenant() {

        scimCommonUtilsStaticMock.when(() -> SCIMCommonUtils.getOrganizationsToInvalidateCaches(1))
                .thenReturn(v1TenantList);
        cache.addSCIMCustomAttributeSchema(1, mockAttributeSchema);
        cache.addSCIMCustomAttributeSchema(111, mockAttributeSchema);
        cache.clearSCIMCustomAttributeSchemaByTenant(1);
        assertNull(cache.getSCIMCustomAttributeSchemaByTenant(1));
        assertNull(cache.getSCIMCustomAttributeSchemaByTenant(111));
    }

    @Test
    public void testClearSCIMCustomAttributeSchemaByTenant_NonExistentTenant() {

        cache.clearSCIMCustomAttributeSchemaByTenant(999);
        // No exception should be thrown.
    }

    @Test
    public void testSingletonInstance() {

        SCIMCustomAttributeSchemaCache instance1 = SCIMCustomAttributeSchemaCache.getInstance();
        SCIMCustomAttributeSchemaCache instance2 = SCIMCustomAttributeSchemaCache.getInstance();
        assertSame(instance1, instance2);
    }

    @Test
    public void testMultipleTenants() {

        AttributeSchema schema1 = mock(AttributeSchema.class);
        AttributeSchema schema2 = mock(AttributeSchema.class);

        cache.addSCIMCustomAttributeSchema(10, schema1);
        cache.addSCIMCustomAttributeSchema(20, schema2);

        assertEquals(schema1, cache.getSCIMCustomAttributeSchemaByTenant(10));
        assertEquals(schema2, cache.getSCIMCustomAttributeSchemaByTenant(20));
    }

    @Test
    public void testOverwriteExistingEntry() {

        AttributeSchema firstSchema = mock(AttributeSchema.class);
        AttributeSchema secondSchema = mock(AttributeSchema.class);

        cache.addSCIMCustomAttributeSchema(1, firstSchema);
        cache.addSCIMCustomAttributeSchema(1, secondSchema);

        AttributeSchema result = cache.getSCIMCustomAttributeSchemaByTenant(1);
        assertEquals(secondSchema, result);
        assertNotEquals(firstSchema, result);
    }

    @Test
    public void testNullAttributeSchema() {

        cache.addSCIMCustomAttributeSchema(1, null);
        assertNull(cache.getSCIMCustomAttributeSchemaByTenant(1));
    }

    @Test
    public void testCacheKeyEquality() {

        SCIMCustomAttributeSchemaCacheKey key1 = new SCIMCustomAttributeSchemaCacheKey(1);
        SCIMCustomAttributeSchemaCacheKey key2 = new SCIMCustomAttributeSchemaCacheKey(1);
        SCIMCustomAttributeSchemaCacheKey key3 = new SCIMCustomAttributeSchemaCacheKey(2);

        assertEquals(key1, key2);
        assertNotEquals(key1, key3);
    }

    @Test
    public void testCacheKeyHashCode() {

        SCIMCustomAttributeSchemaCacheKey key1 = new SCIMCustomAttributeSchemaCacheKey(1);
        SCIMCustomAttributeSchemaCacheKey key2 = new SCIMCustomAttributeSchemaCacheKey(1);

        assertEquals(key1.hashCode(), key2.hashCode());
    }

    @Test
    public void testCacheKeyEqualityWithSameObject() {

        SCIMCustomAttributeSchemaCacheKey key = new SCIMCustomAttributeSchemaCacheKey(1);
        assertEquals(key, key);
    }

    @Test
    public void testCacheKeyEqualityWithNull() {

        SCIMCustomAttributeSchemaCacheKey key = new SCIMCustomAttributeSchemaCacheKey(1);
        assertNotEquals(key, null);
    }

    @Test
    public void testCacheKeyEqualityWithDifferentClass() {

        SCIMCustomAttributeSchemaCacheKey key = new SCIMCustomAttributeSchemaCacheKey(1);
        assertNotEquals(key, "different");
    }

    @Test
    public void testCacheKeyGetTenantId() {

        int tenantId = 42;
        SCIMCustomAttributeSchemaCacheKey key = new SCIMCustomAttributeSchemaCacheKey(tenantId);
        assertEquals(tenantId, key.getTenantId());
    }

    @Test
    public void testCacheEntryGetSchema() {

        SCIMCustomAttributeSchemaCacheEntry entry = new SCIMCustomAttributeSchemaCacheEntry(mockAttributeSchema);
        assertEquals(mockAttributeSchema, entry.getSCIMCustomAttributeSchema());
    }

    // --- Read-path (addSCIMCustomAttributeSchemaOnRead) tests ---
    // Use dedicated tenant IDs (700+) to avoid collisions with write-path tests
    // running in the same singleton cache instance.

    @Test
    public void testAddSCIMCustomAttributeSchemaOnRead() {

        cache.addSCIMCustomAttributeSchemaOnRead(701, mockAttributeSchema);
        AttributeSchema result = cache.getSCIMCustomAttributeSchemaByTenant(701);
        assertNotNull(result);
        assertEquals(mockAttributeSchema, result);
    }

    @Test
    public void testAddSCIMCustomAttributeSchemaOnRead_NullSchema() {

        cache.addSCIMCustomAttributeSchemaOnRead(702, null);
        assertNull(cache.getSCIMCustomAttributeSchemaByTenant(702));
    }

    @Test
    public void testAddSCIMCustomAttributeSchemaOnRead_MultipleTenants() {

        AttributeSchema schema1 = mock(AttributeSchema.class);
        AttributeSchema schema2 = mock(AttributeSchema.class);

        cache.addSCIMCustomAttributeSchemaOnRead(710, schema1);
        cache.addSCIMCustomAttributeSchemaOnRead(720, schema2);

        assertEquals(schema1, cache.getSCIMCustomAttributeSchemaByTenant(710));
        assertEquals(schema2, cache.getSCIMCustomAttributeSchemaByTenant(720));
    }

    @Test
    public void testAddSCIMCustomAttributeSchemaOnRead_DoesNotOverwriteExistingEntry() {

        AttributeSchema firstSchema = mock(AttributeSchema.class);
        AttributeSchema secondSchema = mock(AttributeSchema.class);

        cache.addSCIMCustomAttributeSchemaOnRead(703, firstSchema);
        cache.addSCIMCustomAttributeSchemaOnRead(703, secondSchema);

        // putOnRead is a no-op if entry already exists; first value retained.
        AttributeSchema result = cache.getSCIMCustomAttributeSchemaByTenant(703);
        assertEquals(firstSchema, result);
        assertNotEquals(secondSchema, result);
    }

    @Test
    public void testAddSCIMCustomAttributeSchemaOnRead_OnReadDoesNotOverwriteWritePathEntry() {

        AttributeSchema writeSchema = mock(AttributeSchema.class);
        AttributeSchema readSchema = mock(AttributeSchema.class);

        cache.addSCIMCustomAttributeSchema(704, writeSchema);
        cache.addSCIMCustomAttributeSchemaOnRead(704, readSchema);

        // putOnRead should not overwrite; write-path value retained.
        assertEquals(writeSchema, cache.getSCIMCustomAttributeSchemaByTenant(704));
    }

    @Test
    public void testAddSCIMCustomAttributeSchemaOnRead_WritePathOverridesOnReadEntry() {

        AttributeSchema readSchema = mock(AttributeSchema.class);
        AttributeSchema writeSchema = mock(AttributeSchema.class);

        cache.addSCIMCustomAttributeSchemaOnRead(705, readSchema);
        cache.addSCIMCustomAttributeSchema(705, writeSchema);

        assertEquals(writeSchema, cache.getSCIMCustomAttributeSchemaByTenant(705));
    }

    @Test
    public void testOnReadEntry_ClearedByTenantClear() {

        final List<Integer> tenantList = new ArrayList<>(Collections.singletonList(706));
        scimCommonUtilsStaticMock.when(() -> SCIMCommonUtils.getOrganizationsToInvalidateCaches(706))
                .thenReturn(tenantList);
        cache.addSCIMCustomAttributeSchemaOnRead(706, mockAttributeSchema);
        cache.clearSCIMCustomAttributeSchemaByTenant(706);
        assertNull(cache.getSCIMCustomAttributeSchemaByTenant(706));
    }

    @AfterClass
    public void tearDown() {

        scimCommonUtilsStaticMock.close();
    }
}
