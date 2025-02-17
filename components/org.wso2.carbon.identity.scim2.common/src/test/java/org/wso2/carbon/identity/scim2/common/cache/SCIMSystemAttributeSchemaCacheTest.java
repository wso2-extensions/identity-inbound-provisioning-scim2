package org.wso2.carbon.identity.scim2.common.cache;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.charon3.core.schema.AttributeSchema;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;

@WithCarbonHome
public class SCIMSystemAttributeSchemaCacheTest {

    private SCIMSystemAttributeSchemaCache cache;
    private AttributeSchema mockAttributeSchema;

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

        cache.addSCIMSystemAttributeSchema(1, mockAttributeSchema);
        cache.clearSCIMSystemAttributeSchemaByTenant(1);
        AttributeSchema result = cache.getSCIMSystemAttributeSchemaByTenant(1);
        assertNull(result);
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
}
