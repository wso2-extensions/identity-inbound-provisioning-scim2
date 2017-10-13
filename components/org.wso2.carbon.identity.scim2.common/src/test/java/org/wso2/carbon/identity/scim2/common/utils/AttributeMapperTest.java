/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.charon3.core.encoder.JSONDecoder;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class AttributeMapperTest {

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);

    }

    @AfterMethod
    public void tearDown() throws Exception {

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

}
