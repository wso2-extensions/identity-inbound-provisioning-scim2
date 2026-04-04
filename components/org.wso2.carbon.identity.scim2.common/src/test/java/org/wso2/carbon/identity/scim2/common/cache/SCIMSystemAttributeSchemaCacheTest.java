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

@WithCarbonHome
public class SCIMSystemAttributeSchemaCacheTest {

    private SCIMSystemAttributeSchemaCache cache;
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

        cache = SCIMSystemAttributeSchemaCache.getInstance();
        mockAttributeSchema = mock(AttributeSchema.class);
    }

    @Test
    public void testAddSCIMSystemAttributeSchema() {

        cache.addSCIMSystemAttributeSchema(1, mockAttributeSchema);
        AttributeSchema result = cache.getSCIMSystemAttributeSchemaByTenant(1);
        assertNotNull(result);
        assertEquals(mockAttributeSchema, result);
    }

    @Test
    public void testGetSCIMSystemAttributeSchemaByTenant() {

        cache.addSCIMSystemAttributeSchema(1, mockAttributeSchema);
        AttributeSchema result = cache.getSCIMSystemAttributeSchemaByTenant(1);
        assertNotNull(result);
        assertEquals(mockAttributeSchema, result);
    }

    @Test
    public void testGetSCIMSystemAttributeSchemaByTenant_NotFound() {

        AttributeSchema result = cache.getSCIMSystemAttributeSchemaByTenant(2);
        assertNull(result);
    }

    @Test
    public void testClearSCIMSystemAttributeSchemaByTenant() {

        scimCommonUtilsStaticMock.when(() -> SCIMCommonUtils.getOrganizationsToInvalidateCaches(1))
                .thenReturn(v0TenantList);
        cache.addSCIMSystemAttributeSchema(1, mockAttributeSchema);
        cache.addSCIMSystemAttributeSchema(111, mockAttributeSchema);
        cache.clearSCIMSystemAttributeSchemaByTenant(1);
        AttributeSchema result = cache.getSCIMSystemAttributeSchemaByTenant(1);
        assertNull(result);
        AttributeSchema subOrgResult = cache.getSCIMSystemAttributeSchemaByTenant(111);
        assertNotNull(subOrgResult);
    }

    @Test
    public void testClearSCIMSystemAttributeSchemaByV1Tenant() {

        scimCommonUtilsStaticMock.when(() -> SCIMCommonUtils.getOrganizationsToInvalidateCaches(1))
                .thenReturn(v1TenantList);
        cache.addSCIMSystemAttributeSchema(1, mockAttributeSchema);
        cache.addSCIMSystemAttributeSchema(111, mockAttributeSchema);
        cache.clearSCIMSystemAttributeSchemaByTenant(1);
        AttributeSchema result = cache.getSCIMSystemAttributeSchemaByTenant(1);
        assertNull(result);
        AttributeSchema subOrgResult = cache.getSCIMSystemAttributeSchemaByTenant(111);
        assertNull(subOrgResult);
    }

    @Test
    public void testSingletonInstance() {

        SCIMSystemAttributeSchemaCache instance1 = SCIMSystemAttributeSchemaCache.getInstance();
        SCIMSystemAttributeSchemaCache instance2 = SCIMSystemAttributeSchemaCache.getInstance();
        assertSame(instance1, instance2);
    }

    @Test
    public void testClearSCIMSystemAttributeSchemaByTenant_NonExistentTenant() {

        cache.clearSCIMSystemAttributeSchemaByTenant(2);
        // No exception should be thrown.
    }

    @Test
    public void testCacheKeyEquality() {

        SCIMSystemAttributeSchemaCacheKey key1 = new SCIMSystemAttributeSchemaCacheKey(1);
        SCIMSystemAttributeSchemaCacheKey key2 = new SCIMSystemAttributeSchemaCacheKey(1);
        SCIMSystemAttributeSchemaCacheKey key3 = new SCIMSystemAttributeSchemaCacheKey(2);

        assertEquals(key1, key2);
        assertNotEquals(key1, key3);
    }

    @Test
    public void testCacheKeyHashCode() {

        SCIMSystemAttributeSchemaCacheKey key1 = new SCIMSystemAttributeSchemaCacheKey(1);
        SCIMSystemAttributeSchemaCacheKey key2 = new SCIMSystemAttributeSchemaCacheKey(1);

        assertEquals(key1.hashCode(), key2.hashCode());
    }

    // --- Read-path (addSCIMSystemAttributeSchemaOnRead) tests ---
    // Use dedicated tenant IDs (600+) to avoid collisions with write-path tests
    // running in the same singleton cache instance.

    @Test
    public void testAddSCIMSystemAttributeSchemaOnRead() {

        cache.addSCIMSystemAttributeSchemaOnRead(601, mockAttributeSchema);
        AttributeSchema result = cache.getSCIMSystemAttributeSchemaByTenant(601);
        assertNotNull(result);
        assertEquals(mockAttributeSchema, result);
    }

    @Test
    public void testAddSCIMSystemAttributeSchemaOnRead_NullSchema() {

        cache.addSCIMSystemAttributeSchemaOnRead(602, null);
        assertNull(cache.getSCIMSystemAttributeSchemaByTenant(602));
    }

    @Test
    public void testAddSCIMSystemAttributeSchemaOnRead_MultipleTenants() {

        AttributeSchema schema1 = mock(AttributeSchema.class);
        AttributeSchema schema2 = mock(AttributeSchema.class);

        cache.addSCIMSystemAttributeSchemaOnRead(610, schema1);
        cache.addSCIMSystemAttributeSchemaOnRead(620, schema2);

        assertEquals(schema1, cache.getSCIMSystemAttributeSchemaByTenant(610));
        assertEquals(schema2, cache.getSCIMSystemAttributeSchemaByTenant(620));
    }

    @Test
    public void testAddSCIMSystemAttributeSchemaOnRead_DoesNotOverwriteExistingEntry() {

        AttributeSchema firstSchema = mock(AttributeSchema.class);
        AttributeSchema secondSchema = mock(AttributeSchema.class);

        cache.addSCIMSystemAttributeSchemaOnRead(603, firstSchema);
        cache.addSCIMSystemAttributeSchemaOnRead(603, secondSchema);

        // putOnRead is a no-op if entry already exists; first value retained.
        AttributeSchema result = cache.getSCIMSystemAttributeSchemaByTenant(603);
        assertEquals(firstSchema, result);
        assertNotEquals(secondSchema, result);
    }

    @Test
    public void testAddSCIMSystemAttributeSchemaOnRead_WritePathOverridesOnReadEntry() {

        AttributeSchema readSchema = mock(AttributeSchema.class);
        AttributeSchema writeSchema = mock(AttributeSchema.class);

        cache.addSCIMSystemAttributeSchemaOnRead(604, readSchema);
        cache.addSCIMSystemAttributeSchema(604, writeSchema);

        assertEquals(writeSchema, cache.getSCIMSystemAttributeSchemaByTenant(604));
    }

    @Test
    public void testAddSCIMSystemAttributeSchemaOnRead_OnReadDoesNotOverwriteWritePathEntry() {

        AttributeSchema writeSchema = mock(AttributeSchema.class);
        AttributeSchema readSchema = mock(AttributeSchema.class);

        cache.addSCIMSystemAttributeSchema(605, writeSchema);
        cache.addSCIMSystemAttributeSchemaOnRead(605, readSchema);

        // putOnRead should not overwrite; write-path value retained.
        assertEquals(writeSchema, cache.getSCIMSystemAttributeSchemaByTenant(605));
    }

    @Test
    public void testOnReadEntry_ClearedByTenantClear() {

        final List<Integer> tenantList = new ArrayList<>(Collections.singletonList(606));
        scimCommonUtilsStaticMock.when(() -> SCIMCommonUtils.getOrganizationsToInvalidateCaches(606))
                .thenReturn(tenantList);
        cache.addSCIMSystemAttributeSchemaOnRead(606, mockAttributeSchema);
        cache.clearSCIMSystemAttributeSchemaByTenant(606);
        assertNull(cache.getSCIMSystemAttributeSchemaByTenant(606));
    }

    @AfterClass
    public void tearDown() {

        scimCommonUtilsStaticMock.close();
    }
}
