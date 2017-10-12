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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.charon3.core.exceptions.CharonException;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class SCIMConfigProcessorTest {
    private SCIMConfigProcessor scimConfigProcessor;
    private AuthenticationSchema authenticationSchema;

    @DataProvider(name = "propertyProvider")
    public static Object[][] propertyProvider() {
        return new Object[][] { { "Name", "SCIM2" }, { "Address", null } };
    }

    @DataProvider(name="filePathProvider")
    public static Object[][] filePathProvider() {
        String errorFileNamePath = Paths.get(System.getProperty("user.dir"), "src", "test", "resources",
                "charon-config-tst.xml").toString();

        String noFilepath = Paths.get(System.getProperty("user.dir"), "src", "resources", "charon-config-test.xml")
                .toString();

        String errorFilePath = Paths.get(System.getProperty("user.dir"), "srcTest", "test", "resources",
                "charon-config-test.xml").toString();
        return new Object[][] { { noFilepath }, { errorFilePath }, { errorFileNamePath } };
    }

    @BeforeMethod
    public void setUp() throws Exception {
        scimConfigProcessor = new SCIMConfigProcessor();

        scimConfigProcessor.properties.put("Name", "SCIM2");
        scimConfigProcessor.properties.put("Age", "24");

        authenticationSchema = new AuthenticationSchema();
        authenticationSchema.setName("SCIM");
        authenticationSchema.setDescription("SCIM2");
        authenticationSchema.setSpecUri("https://localhost:9443/scim2");
        authenticationSchema.setDocumentationUri("https://localhost:9443/scim2/docs");
        authenticationSchema.setType("Authentication");
        authenticationSchema.setPrimary("true");
        scimConfigProcessor.authenticationSchemas = new ArrayList<>();
        scimConfigProcessor.authenticationSchemas.add(authenticationSchema);
    }

    @Test
    public void testGetProperties() throws Exception {
        Map<String, String> expected = new HashMap<String, String>();
        expected.put("Name", "SCIM2");
        expected.put("Age", "24");

        Map<String, String> map = scimConfigProcessor.getProperties();

        assertEquals(map.get("Name"), expected.get("Name"));
        assertEquals(map.get("Age"), expected.get("Age"));
    }

    @Test(dataProvider = "propertyProvider")
    public void testGetProperty(String property, String expectedResult) throws Exception {
        assertEquals(scimConfigProcessor.getProperty(property), expectedResult);
    }

    @Test
    public void testGetAuthenticationSchemas() throws Exception {
        List<AuthenticationSchema> authenticationSchemaList = scimConfigProcessor.getAuthenticationSchemas();
        for (AuthenticationSchema authenticationSchema1 : authenticationSchemaList) {
            assertEquals(authenticationSchema1.getName(), authenticationSchema.getName());
            assertEquals(authenticationSchema1.getDescription(), authenticationSchema.getDescription());
            assertEquals(authenticationSchema1.getSpecUri(), authenticationSchema.getSpecUri());
            assertEquals(authenticationSchema1.getDocumentationUri(), authenticationSchema.getDocumentationUri());
            assertEquals(authenticationSchema1.getType(), authenticationSchema.getType());
            assertEquals(authenticationSchema1.getPrimary(), authenticationSchema.getPrimary());
        }
    }

    @Test(dataProvider = "filePathProvider", expectedExceptions = CharonException.class)
    public void testBuildConfigFromFile(String filePath) throws Exception {
        scimConfigProcessor.buildConfigFromFile(filePath);
    }

    @Test
    public void testBuildConfigFromFileHappy() throws Exception {
        String filePath = Paths.get(System.getProperty("user.dir"), "src", "test", "resources",
                "charon-config-test.xml").toString();
        scimConfigProcessor.buildConfigFromFile(filePath);

    }

    @Test
    public void testGetInstance() throws Exception {
        SCIMConfigProcessor scimConfigProcessor1 = scimConfigProcessor.getInstance();
        assertNotNull(scimConfigProcessor1);
    }
}
