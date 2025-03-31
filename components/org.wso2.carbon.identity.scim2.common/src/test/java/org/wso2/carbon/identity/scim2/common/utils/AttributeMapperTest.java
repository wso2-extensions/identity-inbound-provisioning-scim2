/*
 * Copyright (c) 2017, WSO2 LLC. (http://www.wso2.org)
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

package org.wso2.carbon.identity.scim2.common.utils;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.encoder.JSONDecoder;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.AbstractSCIMObject;
import org.wso2.charon3.core.objects.SCIMObject;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.AttributeSchema;
import org.wso2.charon3.core.schema.SCIMAttributeSchema;
import org.wso2.charon3.core.schema.SCIMDefinitions;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED;

public class AttributeMapperTest {

    @Mock
    private UserManager userManager;
    @Mock
    private SCIMResourceTypeSchema scimResourceTypeSchema;

    private MockedStatic<IdentityUtil> mockedIdentityUtil;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);

        mockedIdentityUtil = mockStatic(IdentityUtil.class);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        mockedIdentityUtil.close();
    }

    @Test
    public void testGetClaimsMap() throws Exception {

        String scimObjectString = "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"]," +
                "\"id\":\"1819c223-7f76-453a-919d-413851904641\",\"externalId\":\"702984\",\"userName\":\"paul\"," +
                "\"name\":{\"formatted\":\"Ms.BarbaraJJensen,III\",\"familyName\":\"Jensen\"," +
                "\"givenName\":\"Barbara\",\"middleName\":\"Jane\",\"honorificPrefix\":\"Ms.\"," +
                "\"honorificSuffix\":\"III\"},\"displayName\":\"BabsJensen\",\"nickName\":\"Babs\"," +
                "\"emails\":[{\"value\":\"bjensen@example.com\",\"type\":\"work\",\"primary\":true}," +
                "{\"value\":\"babs@jensen.org\",\"type\":\"home\"}],\"addresses\":[{\"type\":\"work\"," +
                "\"streetAddress\":\"100UniversalCityPlaza\",\"locality\":\"Hollywood\",\"region\":\"CA\"," +
                "\"postalCode\":\"91608\",\"country\":\"USA\",\"formatted\":\"100UniversalCityPlaza\\nHollywood," +
                "CA91608USA\",\"primary\":true},{\"type\":\"home\",\"streetAddress\":\"456HollywoodBlvd\"," +
                "\"locality\":\"Hollywood\",\"region\":\"CA\",\"postalCode\":\"91608\",\"country\":\"USA\"," +
                "\"formatted\":\"456HollywoodBlvd\\nHollywood,CA91608USA\"}]," +
                "\"phoneNumbers\":[{\"value\":\"555-555-5555\",\"type\":\"work\"},{\"value\":\"555-555-4444\"," +
                "\"type\":\"mobile\"}]}";

        JSONDecoder decoder = new JSONDecoder();
        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        User user = (User) decoder.decodeResource(scimObjectString, schema, new User());

        assertNotNull(AttributeMapper.getClaimsMap(user));
        assertEquals(AttributeMapper.getClaimsMap(user).size(), 17);

    }

    @Test
    public void testConstructSCIMObjectFromAttributes() throws Exception {

        Map<String, String> attributes = new HashMap<>();
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:emails.home", "paul@abc.com");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.resourceType", "User");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.created", "2017-10-04T11:39:43Z");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.location",
                "https://localhost:9443/wso2/scim/v2/Users/4f6b38a0-0fd6-4852-8f87-5e9db6991357");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:emails.work", "paulSmith@abc.com");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:name.familyName", "Smith");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.lastModified", "2017-10-04T11:39:43Z");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:id", "4f6b38a0-0fd6-4852-8f87-5e9db6991357");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:userType", "User");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:userName", "Paul");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:name.givenName", "Paul");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:addresses.region", "CA");

        assertNotNull(AttributeMapper.constructSCIMObjectFromAttributes(attributes, 1));

    }

    @Test
    public void testAddressesAttribute() throws Exception {

        Map<String, String> attributes = new HashMap<>();
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:emails.home", "paul@abc.com");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.resourceType", "User");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.created", "2021-05-25T11:39:43Z");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.location",
                "https://localhost:9443/scim2/Users/4f6b38a0-0fd6-4852-8f87-5e9db6991357");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:emails.work", "paulSmith@abc.com");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:name.familyName", "Smith");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.lastModified", "2021-05-25T21:39:43Z");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:id", "4f6b38a0-0fd6-4852-8f87-5e9db6991357");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:userType", "User");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:userName", "Paul");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:name.givenName", "Paul");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:User:addresses.home",
                "100 Universal City Plaza Hollywood, CA 91608 USA");

        assertEquals(((User) AttributeMapper.constructSCIMObjectFromAttributes(attributes, 1)).getAddresses().get(0)
                .getType(), "home");
        assertEquals(((User) AttributeMapper.constructSCIMObjectFromAttributes(attributes, 1)).getAddresses().get(0)
                .getFormatted(), "100 Universal City Plaza Hollywood, CA 91608 USA");

    }

    @Test
    public void testConstructSCIMObjectFromAttributesOfLevelTwo() throws Exception {

        String dialectURI = "urn:ietf:params:scim:schemas:custom:User";
        String attributeName = "custom";
        String attributeURI = dialectURI + ":" + attributeName;
        String attributeValue = "test";

        Map.Entry<String, String> attributeEntry =
                new AbstractMap.SimpleEntry<>(attributeURI, attributeValue);
        String[] attributeNames = {dialectURI, attributeName};
        SCIMObject scimObject = new AbstractSCIMObject();
        int scimObjectType = 1; // User schema.

        mockedIdentityUtil.when(() -> IdentityUtil.getProperty(SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED))
                .thenReturn(Boolean.FALSE.toString());

        AttributeSchema attributeSchema = SCIMAttributeSchema.createSCIMAttributeSchema(
                attributeURI,
                attributeName,
                SCIMDefinitions.DataType.STRING,
                false,
                "Custom attribute",
                false,
                false,
                SCIMDefinitions.Mutability.READ_WRITE,
                SCIMDefinitions.Returned.DEFAULT,
                SCIMDefinitions.Uniqueness.NONE,
                null,
                null,
                null);

        AttributeSchema parentAttributeSchema = SCIMAttributeSchema.createSCIMAttributeSchema(
                dialectURI,
                dialectURI,
                SCIMDefinitions.DataType.COMPLEX,
                false,
                "Custom schema",
                false,
                false,
                SCIMDefinitions.Mutability.READ_WRITE,
                SCIMDefinitions.Returned.DEFAULT,
                SCIMDefinitions.Uniqueness.NONE,
                null,
                null,
                new ArrayList<>(Collections.singletonList(attributeSchema)));

        try (MockedStatic<SCIMResourceSchemaManager> localMockedSCIMResourceSchemaManager =
                     Mockito.mockStatic(SCIMResourceSchemaManager.class)) {

            SCIMResourceSchemaManager localScimResourceSchemaManager = mock(SCIMResourceSchemaManager.class);
            localMockedSCIMResourceSchemaManager.when(SCIMResourceSchemaManager::getInstance)
                    .thenReturn(localScimResourceSchemaManager);
            when(localScimResourceSchemaManager.getUserResourceSchema(eq(userManager)))
                    .thenReturn(scimResourceTypeSchema);
            when(scimResourceTypeSchema.getAttributesList()).thenReturn(
                    new ArrayList<>(Collections.singletonList(parentAttributeSchema))
                                                                       );
            AttributeMapper.constructSCIMObjectFromAttributesOfLevelTwo(userManager, attributeEntry, scimObject,
                    attributeNames, scimObjectType);
        }

        Attribute parentAttribute = scimObject.getAttributeList().get(dialectURI);
        Assert.assertNotNull(parentAttribute);

        Attribute subAttributes = parentAttribute.getSubAttribute(attributeName);
        Assert.assertNotNull(subAttributes);
        Assert.assertNotNull(((SimpleAttribute) subAttributes).getValue(), attributeValue);
    }

    @Test
    public void testConstructSCIMObjectFromAttributesOfLevelThree() throws Exception {

        String dialectURI = "urn:ietf:params:scim:schemas:custom:User";
        String instructorAttributeName = "instructor";
        String instructorURI = dialectURI + ":" + instructorAttributeName;
        String attributeName = "name";
        String attributeURI = instructorURI + "." + attributeName;
        String attributeValue = "john";

        Map.Entry<String, String> attributeEntry =
                new AbstractMap.SimpleEntry<>(attributeURI, attributeValue);
        String[] attributeNames = {dialectURI, instructorAttributeName, attributeName};
        SCIMObject scimObject = new AbstractSCIMObject();
        int scimObjectType = 1; // User schema.

        mockedIdentityUtil.when(() -> IdentityUtil.getProperty(SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED))
                .thenReturn(Boolean.FALSE.toString());

        AttributeSchema instructorNameSchema = SCIMAttributeSchema.createSCIMAttributeSchema(
                attributeURI,
                attributeName,
                SCIMDefinitions.DataType.STRING,
                false,
                "Instructor Name",
                false,
                false,
                SCIMDefinitions.Mutability.READ_WRITE,
                SCIMDefinitions.Returned.DEFAULT,
                SCIMDefinitions.Uniqueness.NONE,
                null,
                null,
                null);

        AttributeSchema instructorSchema = SCIMAttributeSchema.createSCIMAttributeSchema(
                instructorURI,
                instructorURI,
                SCIMDefinitions.DataType.COMPLEX,
                false,
                "Instructor attribute",
                false,
                false,
                SCIMDefinitions.Mutability.READ_WRITE,
                SCIMDefinitions.Returned.DEFAULT,
                SCIMDefinitions.Uniqueness.NONE,
                null,
                null,
                new ArrayList<>(Collections.singletonList(instructorNameSchema)));

        AttributeSchema parentAttributeSchema = SCIMAttributeSchema.createSCIMAttributeSchema(
                dialectURI,
                dialectURI,
                SCIMDefinitions.DataType.COMPLEX,
                false,
                "Custom schema",
                false,
                false,
                SCIMDefinitions.Mutability.READ_WRITE,
                SCIMDefinitions.Returned.DEFAULT,
                SCIMDefinitions.Uniqueness.NONE,
                null,
                null,
                new ArrayList<>(Collections.singletonList(instructorSchema)));

        try (MockedStatic<SCIMResourceSchemaManager> localMockedSCIMResourceSchemaManager =
                     Mockito.mockStatic(SCIMResourceSchemaManager.class)) {

            SCIMResourceSchemaManager localScimResourceSchemaManager = mock(SCIMResourceSchemaManager.class);
            localMockedSCIMResourceSchemaManager.when(SCIMResourceSchemaManager::getInstance)
                    .thenReturn(localScimResourceSchemaManager);
            when(localScimResourceSchemaManager.getUserResourceSchema(eq(userManager)))
                    .thenReturn(scimResourceTypeSchema);
            when(scimResourceTypeSchema.getAttributesList()).thenReturn(
                    new ArrayList<>(Collections.singletonList(parentAttributeSchema))
                                                                       );
            AttributeMapper.constructSCIMObjectFromAttributesOfLevelThree(userManager, attributeEntry, scimObject,
                    attributeNames, scimObjectType);
        }

        Attribute parentAttribute = scimObject.getAttributeList().get(dialectURI);
        Assert.assertNotNull(parentAttribute);

        Attribute instructorAttribute = parentAttribute.getSubAttribute(instructorAttributeName);
        Assert.assertNotNull(instructorAttribute);

        Attribute instructorNameAttribute = instructorAttribute.getSubAttribute(attributeName);
        Assert.assertNotNull(instructorNameAttribute);
        Assert.assertNotNull(((SimpleAttribute) instructorNameAttribute).getValue(), attributeValue);
    }
}
