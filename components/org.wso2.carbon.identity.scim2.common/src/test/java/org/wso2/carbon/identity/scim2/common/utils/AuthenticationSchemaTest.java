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

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;

public class AuthenticationSchemaTest {

    private String dummyName = "dummyName";
    private String dummyDescription = "dummyDescription";
    private String dummySpecUri = "dummySpecUri";
    private String dummyDocumentationUri = "dummyDocumentationUri";
    private String dummyType = "dummyType";
    private String dummyPrimary = "dummyPrimary";
    private AuthenticationSchema authenticationSchema;

    @BeforeMethod
    public void setUp() throws Exception {
        authenticationSchema = new AuthenticationSchema();
        Map<String, String> properties = new HashMap<>();
        properties.put("name", dummyName);
        properties.put("description", dummyDescription);
        properties.put("specUri", dummySpecUri);
        properties.put("documentationUri", dummyDocumentationUri);
        properties.put("type", dummyType);
        properties.put("primary", dummyPrimary);
        authenticationSchema.setProperties(properties);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testGetName() throws Exception {
        assertEquals(authenticationSchema.getName(), dummyName);
    }

    @Test
    public void testSetName() throws Exception {
        dummyName = "dummyName2";
        authenticationSchema.setName(dummyName);
        assertEquals(authenticationSchema.getName(), dummyName);
    }

    @Test
    public void testGetDescription() throws Exception {
        assertEquals(authenticationSchema.getDescription(), dummyDescription);
    }

    @Test
    public void testSetDescription() throws Exception {
        dummyDescription = "dummyDescription2";
        authenticationSchema.setDescription(dummyDescription);
        assertEquals(authenticationSchema.getDescription(), dummyDescription);
    }

    @Test
    public void testGetSpecUri() throws Exception {
        assertEquals(authenticationSchema.getSpecUri(), dummySpecUri);
    }

    @Test
    public void testSetSpecUri() throws Exception {
        dummySpecUri = "dummySpecUri2";
        authenticationSchema.setSpecUri(dummySpecUri);
        assertEquals(authenticationSchema.getSpecUri(), dummySpecUri);
    }

    @Test
    public void testGetDocumentationUri() throws Exception {
        assertEquals(authenticationSchema.getDocumentationUri(), dummyDocumentationUri);
    }

    @Test
    public void testSetDocumentationUri() throws Exception {
        dummyDocumentationUri = "dummyDocumentationUri2";
        authenticationSchema.setDocumentationUri(dummyDocumentationUri);
        assertEquals(authenticationSchema.getDocumentationUri(), dummyDocumentationUri);
    }

    @Test
    public void testGetType() throws Exception {
        assertEquals(authenticationSchema.getType(), dummyType);
    }

    @Test
    public void testSetType() throws Exception {
        dummyType = "dummyType2";
        authenticationSchema.setType(dummyType);
        assertEquals(authenticationSchema.getType(), dummyType);
    }

    @Test
    public void testGetPrimary() throws Exception {
        assertEquals(authenticationSchema.getPrimary(), dummyPrimary);
    }

    @Test
    public void testSetPrimary() throws Exception {
        dummyPrimary = "dummyPrimary2";
        authenticationSchema.setPrimary(dummyPrimary);
        assertEquals(authenticationSchema.getPrimary(), dummyPrimary);
    }

}
