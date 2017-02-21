/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.inbound.provisioning.scim2.test.module;


import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.apache.commons.io.Charsets;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerSuite;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.inbound.provisioning.scim2.test.module.commons.utills.SCIMOSGiTestUtils;
import org.wso2.carbon.identity.inbound.provisioning.scim2.test.module.commons.utills.SCIMTestUtil;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.net.HttpURLConnection;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.Response;

import static org.ops4j.pax.exam.CoreOptions.systemProperty;

@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class UserResourceTestCase {

    private static final Gson GSON = new Gson();
    private static String scimId = null;

    private static Logger log = LoggerFactory.getLogger(UserResourceTestCase.class);


    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;


    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = SCIMOSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(systemProperty("java.security.auth.login.config")
                .value(Paths.get(SCIMOSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config")
                        .toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    @Test(groups = "addUsers", description = "Add User via SCIM")
    public void testAddUser() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createUser("Devid", "Silva",
                new ArrayList<String>() { { add("devid@gmail.com"); add("devid@yahoo.com"); } });
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the user.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject userObj = GSON.fromJson(content, JsonObject.class);
        scimId = userObj.get(SCIMConstants.CommonSchemaConstants.ID).toString().replace("\"", "");
        Assert.assertNotNull(scimId, "Invalid scim user id.");
    }

    @Test(groups = "addUsers", description = "Add User via SCIM without Mandatory Attributes")
    public void testAddUserWithoutMandatoryAttributes() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.createUser(null, "Silva",
                new ArrayList<String>() { { add("silva@gmail.com"); add("silva@yahoo.com"); } });
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the user without mandatory attributes.");
    }

    /*@Test (groups = "addUsers", dependsOnMethods = {"testAddUser"}, description = "Add Existing User via SCIM")
    public void testAddExistingUser() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.createUser("Devid", "Silva",
                new ArrayList<String>() { { add("devid@gmail.com"); add("devid@yahoo.com"); } });
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added an exisiting user.");
    }*/

    /*@Test (groups = "addUsers", description = "Add User via SCIM with Invalid Admin Credentials")
    public void testAddUserWithInvalidCredentials() throws Exception {
        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Phelps");

        JsonArray mailJsonArray = new JsonArray();
        JsonObject workJsonObj = new JsonObject();
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.WORK);
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@yahoo.com");
        mailJsonArray.add(workJsonObj);

        JsonObject homeJsonObj = new JsonObject();
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.HOME);
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@gmail.com");
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.PRIMARY, "true");
        mailJsonArray.add(homeJsonObj);

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.UserSchemaConstants.EMAILS, mailJsonArray);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());
        userJsonObj.addProperty(SCIMConstants.UserSchemaConstants.USER_NAME, "Michael");

        HttpURLConnection urlConn = SCIMTestUtil.connectionWithInvalidAdminCredentials(SCIMConstants.USER_ENDPOINT,
                HttpMethod.POST);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the user with invalid admin credentials.");
    }*/

    @Test(groups = "addUsers", description = "Add User via SCIM without Authorization Header")
    public void testAddUserWithoutAuthorizationHeader() throws Exception {
        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Phelps");

        JsonArray mailJsonArray = new JsonArray();
        JsonObject workJsonObj = new JsonObject();
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.WORK);
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@yahoo.com");
        mailJsonArray.add(workJsonObj);

        JsonObject homeJsonObj = new JsonObject();
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.HOME);
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@gmail.com");
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.PRIMARY, "true");
        mailJsonArray.add(homeJsonObj);

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.UserSchemaConstants.EMAILS, mailJsonArray);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());
        userJsonObj.addProperty(SCIMConstants.UserSchemaConstants.USER_NAME, "Michael");

        HttpURLConnection urlConn = SCIMTestUtil.connectionWithoutAuthorizationHeader(SCIMConstants.USER_ENDPOINT,
                HttpMethod.POST);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the user without authorization header.");
    }

    @Test(groups = "addUsers", description = "Add User via SCIM with invalid Syntax in Json Payload.")
    public void testAddUserWithInvalidSyntaxInJsonPayload() throws Exception {
        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Phelps");

        JsonArray mailJsonArray = new JsonArray();
        JsonObject workJsonObj = new JsonObject();
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.WORK);
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@yahoo.com");
        mailJsonArray.add(workJsonObj);

        JsonObject homeJsonObj = new JsonObject();
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.HOME);
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@gmail.com");
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.PRIMARY, "true");
        mailJsonArray.add(homeJsonObj);

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.UserSchemaConstants.EMAILS, mailJsonArray);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());
        userJsonObj.addProperty(SCIMConstants.UserSchemaConstants.USER_NAME, "Michael");

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT, HttpMethod.POST);
        urlConn.getOutputStream().write(userJsonObj.toString().substring(0, userJsonObj.toString().length() - 1)
                .getBytes(Charsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the user with invalid syntax in json payload.");
    }

    @Test(groups = "addUsers", description = "Add User via SCIM with invalid Semantic in Json Payload.")
    public void testAddUserWithInvalidSemanticInJsonPayload() throws Exception {
        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Phelps");
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.USER_NAME, "Michael");

        JsonArray mailJsonArray = new JsonArray();
        JsonObject workJsonObj = new JsonObject();
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.WORK);
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@yahoo.com");
        mailJsonArray.add(workJsonObj);

        JsonObject homeJsonObj = new JsonObject();
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.HOME);
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@gmail.com");
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.PRIMARY, "true");
        mailJsonArray.add(homeJsonObj);

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.UserSchemaConstants.EMAILS, mailJsonArray);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT, HttpMethod.POST);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the user with invalid semantic in json payload.");
    }

    @Test(groups = "addUsers", description = "Add User via SCIM without specifying 'Content-Type' header.")
    public void testAddUserWithoutContentTypeHeader() throws Exception {
        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Phelps");
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.USER_NAME, "Michael");

        JsonArray mailJsonArray = new JsonArray();
        JsonObject workJsonObj = new JsonObject();
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.WORK);
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@yahoo.com");
        mailJsonArray.add(workJsonObj);

        JsonObject homeJsonObj = new JsonObject();
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.HOME);
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "michael@gmail.com");
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.PRIMARY, "true");
        mailJsonArray.add(homeJsonObj);

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.UserSchemaConstants.EMAILS, mailJsonArray);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());

        HttpURLConnection urlConn = SCIMTestUtil.connectionWithoutContentTypeHeader
                (SCIMConstants.USER_ENDPOINT, HttpMethod.POST);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the user without content type header.");
    }

    @Test(groups = "addUsers", description = "Add User via SCIM specifying a attribute which is not in the schema.")
    public void testAddUserWithInvalidAttribute() throws Exception {
        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Abraham");

        JsonArray mailJsonArray = new JsonArray();
        JsonObject workJsonObj = new JsonObject();
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.WORK);
        workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "john@yahoo.com");
        mailJsonArray.add(workJsonObj);

        JsonObject homeJsonObj = new JsonObject();
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.HOME);
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, "john@gmail.com");
        homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.PRIMARY, "true");
        mailJsonArray.add(homeJsonObj);

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.UserSchemaConstants.EMAILS, mailJsonArray);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());
        userJsonObj.addProperty(SCIMConstants.UserSchemaConstants.USER_NAME, "John");
        userJsonObj.addProperty("attribute", "test");

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT,
                HttpMethod.POST);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failure in adding the user with invalid attribute.");
    }

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"}, description = "Get User via SCIM")
    public void testGetUser() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.getUser(scimId);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failure in retrieving the user.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject userObj = GSON.fromJson(content, JsonObject.class);
        String userName = userObj.get(SCIMConstants.UserSchemaConstants.USER_NAME).toString().replace("\"", "");
        String familyName = ((JsonObject) userObj.get(SCIMConstants.UserSchemaConstants.NAME)).
                get(SCIMConstants.UserSchemaConstants.FAMILY_NAME).toString().replace("\"", "");

        Assert.assertEquals(userName, "Devid", "Failure in retrieving the actual user attributes.");
        Assert.assertEquals(familyName, "Silva", "Failure in retrieving the actual user attributes.");

    }

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"}, description = "Get User via SCIM with invalid User ID")
    public void testGetUserWithInvalidUserId() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.getUser(scimId.substring(0, scimId.length() - 1));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully retrieving a user for an invalid user ID.");
    }

    /*@Test(groups = "getUsers", dependsOnGroups = {"addUsers"},
            description = "Get User via SCIM with invalid Admin Credentials")
    public void testGetUserWithInvalidCredentials() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.connectionWithInvalidAdminCredentials
                (SCIMConstants.USER_ENDPOINT + "/" + scimId, HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully retrieving a user with an invlaid admin credentials.");
    }*/

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"},
            description = "Get User via SCIM without Authorization Header")
    public void testGetUserWithoutAuthorizationHeader() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.connectionWithoutAuthorizationHeader
                (SCIMConstants.USER_ENDPOINT + "/" + scimId, HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully retrieving a user without an authorization header.");
    }

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"},
            description = "Get a User with given exact attribute name")
    public void testGetUserWithValidAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId + "?" +
                SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + SCIMConstants.UserSchemaConstants.
                USER_NAME, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in retrieving the user with a valid attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertNotNull(result.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                "Failed in retrieving the user with a valid attribute.");
        Assert.assertNull(result.get(SCIMConstants.UserSchemaConstants.NAME),
                "Failed in retrieving the user with a valid attribute.");
    }

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"}, description = "Get a User with given invalid attribute")
    public void testGetUserWithInvalidAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId + "?" +
                SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + "description", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in retrieving the user with an invalid attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertNotNull(result.get(SCIMConstants.CommonSchemaConstants.ID),
                "Successfully retrieving the user with an invalid attribute.");
        Assert.assertNull(result.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                "Successfully retrieving the user with an invalid attribute.");
    }

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"}, description = "Get a User with given invalid attribute")
    public void testGetUserWithComplexAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId + "?" +
                SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + SCIMConstants.UserSchemaConstants.NAME + "." +
                SCIMConstants.UserSchemaConstants.FAMILY_NAME, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in retrieving the user with a complex attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertNotNull(result.get(SCIMConstants.UserSchemaConstants.NAME).getAsJsonObject()
                .get(SCIMConstants.UserSchemaConstants.FAMILY_NAME),
                "Failed in retrieving the user with a complex attribute.");
        Assert.assertNull(result.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                "Failed in retrieving the user with a complex attribute.");
    }

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"},
            description = "Get a user with given multi valued attribute")
    public void testGetUserWithMultiValuedAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId + "?" +
                        SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + SCIMConstants.UserSchemaConstants.EMAILS,
                HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in retrieving the user with a multi valued attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray emails = ((JsonArray) result.get(SCIMConstants.UserSchemaConstants.EMAILS));
        for (JsonElement email : emails) {
            JsonObject emailObj = ((JsonObject) email);
            Assert.assertEquals(emailObj.get(SCIMConstants.CommonSchemaConstants.TYPE).getAsString(),
                    SCIMConstants.UserSchemaConstants.HOME,
                    "Failed in retrieving the user with a multi valued attribute.");
            Assert.assertNull(emailObj.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                    "Failed in retrieving the user with a multi valued attribute.");
        }
    }

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"},
            description = "Get a User with given exact attribute type")
    public void testGetUserWithFilterExactAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId + "?filter="
                + SCIMConstants.UserSchemaConstants.USER_NAME + "+EQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering the user with a exact attribute type.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertEquals(result.get(SCIMConstants.UserSchemaConstants.USER_NAME).getAsString(), "Devid",
                "Failed in retrieving the correct user attributes.");
    }

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"},
            description = "Get a User with attribute value in uppercase")
    public void testGetUserWithFilterUpperCaseAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId + "?filter="
                + SCIMConstants.UserSchemaConstants.USER_NAME.toUpperCase() + "+EQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering the user with an attribute type in upper case.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertEquals(result.get(SCIMConstants.UserSchemaConstants.USER_NAME).getAsString(), "Devid",
                "Failed in retrieving the correct user attributes.");
    }

    @Test(groups = "getUsers", dependsOnGroups = {"addUsers"},
            description = "Get a User with given exact attribute value")
    public void testGetUserWithFilterLowerCaseAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId + "?filter="
                + SCIMConstants.UserSchemaConstants.USER_NAME.toLowerCase() + "+EQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering the user with an attribute type in lower case.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertEquals(result.get(SCIMConstants.UserSchemaConstants.USER_NAME).getAsString(), "Devid",
                "Failed in retrieving the correct user attributes.");
    }

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"}, description = "List users for given indexes")
    public void testListAllUsers() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the users.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0, "Failed in listing all the users.");
    }

    /*@Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List User via SCIM with invalid Admin Credentials")
    public void testListAllUsersWithInvalidCredentials() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.connectionWithInvalidAdminCredentials
                (SCIMConstants.USER_ENDPOINT, HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully listing all the users with invalid admin credentials.");
    }*/

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List User via SCIM without Authorization Header")
    public void testListAllUsersWithoutAuthorizationHeader() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.connectionWithoutAuthorizationHeader
                (SCIMConstants.USER_ENDPOINT, HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully listing all the users without authorization header.");
    }

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"}, description = "List users for given indexes")
    public void testListAllUsersWithPagination() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createUser("Smiths", "Hunt",
                new ArrayList<String>() { { add("smith@gmail.com"); add("smith@yahoo.com"); } });
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed in creating the user.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.createUser("Rajive", "Kumar",
                new ArrayList<String>() { { add("rajive@gmail.com"); add("rajive@yahoo.com"); } });
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed in creating the user.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.ListedResourceSchemaConstants.START_INDEX + "=" + 1 + "&count=" + 3, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the users with pagination.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0, "Failed in listing all the users with pagination.");
    }

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List users for given filter for a Single Valued Attribute")
    public void testListAllUsersWithFilterForSingleValuedAttribute() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?filter=" +
                SCIMConstants.UserSchemaConstants.USER_NAME + "+EQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the users with a single valued attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get("Resources")).size() > 0,
                "Failed in filtering all the users with a single valued attribute.");
    }

    /*@Test(groups = "listUsers", dependsOnGroups = {"getUsers"}, description = "List users for given symantically " +
            "invalid filter for a Single Valued Attribute")
    public void testListAllUsersWithSemanticallyInvalidFilterForSingleValuedAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?filter=" +
                SCIMConstants.UserSchemaConstants.USER_NAME + "+EQ+\"Devid\"", HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully filtering all the users with a semantically invalid request for " +
                        "single valued attribute.");
    }*/

    /*@Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List users for given filter for a Multi Valued Attribute")
    public void testListAllUsersWithFilterForMultiValuedAttribute() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?filter=" +
                SCIMConstants.UserSchemaConstants.EMAILS + "[" + SCIMConstants.CommonSchemaConstants.TYPE + " eq \""+
                SCIMConstants.UserSchemaConstants.WORK +"\"]", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the users with a multi valued attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get("Resources")).size() > 0,
                "Failed in filtering all the users with a multi valued attribute.");
    }*/

    /*@Test(groups = "listUsers", dependsOnGroups = {"getUsers"}, description = "List users for given symantically " +
            "invalid filter for a Multi Valued Attribute")
    public void testListAllUsersWithSemanticallyInvalidFilterForMultiValuedAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?filter=" +
                SCIMConstants.UserSchemaConstants.EMAILS + "." + SCIMConstants.UserSchemaConstants.WORK +
                "+EQ+\"devid@gmail.com\"", HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully filtering all the users with a semantically invalid request for multi valued attribute.");
    }*/

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List users with given exact attribute name")
    public void testListAllUsersWithExactAttribute() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + SCIMConstants.UserSchemaConstants.
                USER_NAME, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the users with an exact attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                    "Failed in retrieving actual attributes of the user.");
            Assert.assertNull(resourceObj.get(SCIMConstants.UserSchemaConstants.FAMILY_NAME),
                    "Failed in retrieving actual attributes of the user.");
        }
    }

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"}, description = "List users with given invalid attribute")
    public void testListAllUsersWithInvalidAttribute() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + "description", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the users with an invalid attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.ResourceTypeSchemaConstants.ID),
                    "Failed in retrieving actual attributes of the user.");
            Assert.assertNull(resourceObj.get(SCIMConstants.UserSchemaConstants.FAMILY_NAME),
                    "Failed in retrieving actual attributes of the user.");
        }
    }

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"}, description = "List Users with given invalid attribute")
    public void testListAllUsersWithOptionalAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + SCIMConstants.UserSchemaConstants.NAME + "." +
                SCIMConstants.UserSchemaConstants.FAMILY_NAME, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the users with an optional attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.UserSchemaConstants.NAME).getAsJsonObject()
                    .get(SCIMConstants.UserSchemaConstants.FAMILY_NAME),
                    "Failed in retrieving actual attributes of the user.");
            Assert.assertNull(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                    "Failed in retrieving actual attributes of the user.");
        }
    }

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List Users with given multi valued attribute")
    public void testListAllUsersWithMultiValuedAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                        SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + SCIMConstants.UserSchemaConstants.EMAILS,
                HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the users with a multi valued attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            if (((JsonObject) resource).entrySet().size() != 1 &&
                    ((JsonObject) resource).get(SCIMConstants.CommonSchemaConstants.ID) != null) {
                JsonObject resourceObj = ((JsonObject) resource);
                JsonArray emails = ((JsonArray) resourceObj.get(SCIMConstants.UserSchemaConstants.EMAILS));
                for (JsonElement email : emails) {
                    JsonObject emailObj = ((JsonObject) email);
                    Assert.assertEquals(emailObj.get(SCIMConstants.CommonSchemaConstants.TYPE).getAsString(),
                            SCIMConstants.UserSchemaConstants.HOME,
                            "Failed in retrieving actual attributes of the user.");
                    Assert.assertNull(emailObj.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                            "Failed in retrieving actual attributes of the user.");
                }
            }
        }
    }


    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"}, description = "List users with exclude attribute")
    public void testListAllUsersWithExcludeAttributes() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?excludedAttributes=" +
                SCIMConstants.UserSchemaConstants.FAMILY_NAME, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the users with an excluded attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                    "Failed in retrieving actual attributes of the user.");
            Assert.assertNull(resourceObj.get(SCIMConstants.UserSchemaConstants.FAMILY_NAME),
                    "Failed in retrieving actual attributes of the user.");
        }
    }


    /*@Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List Users based on user resource type")
    public void testFilterAllUsersBasedOnUserResourceType() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection("?" +
                        SCIMConstants.OperationalConstants.FILTER + "=(meta.resourceType eq User)", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the users based on user resource type.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                "Failed in retrieving actual attributes of the user.");
            Assert.assertNull(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME)
                "Failed in retrieving actual attributes of the user.");
        }
    }*/

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List users with given exact attribute value")
    public void testFilterAllUsersWithExactAttributeName() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.UserSchemaConstants.USER_NAME
                + "+EQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the users with an exact attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME).getAsString(), "Devid",
                    "Failed in retrieving actual attributes of the user.");
        }
    }

   /*@Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List users with given exact attribute value")
    public void testFilterAllUsersWithLowerCaseAttributeName() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "="
                + SCIMConstants.UserSchemaConstants.USER_NAME.toLowerCase()
                + "+EQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the users with an lower case attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME).getAsString(), "Devid",
                "Failed in retrieving actual attributes of the user.");
        }
    }

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List users with attribute value in uppercase")
    public void testFilterAllUsersWithUpperCaseAttributeName() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.UserSchemaConstants.USER_NAME
                .toUpperCase()+ "+EQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the users with an upper case attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME).getAsString(), "Devid",
                "Failed in retrieving actual attributes of the user.");
        }
    }*/

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List users with given exact attribute value")
    public void testFilterAllUsersWithLowerCaseAttributeOperator() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.UserSchemaConstants.USER_NAME
                + "+eq+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the users with an lower case attribute operator.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME).getAsString(), "Devid",
                    "Failed in retrieving actual attributes of the user.");
        }
    }

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List users with attribute value in uppercase")
    public void testFilterAllUsersWithUpperCaseAttributeOperator() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.UserSchemaConstants.USER_NAME
                + "+EQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the users with an upper case attribute operator.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME).getAsString(), "Devid",
                    "Failed in retrieving actual attributes of the user.");
        }
    }

    @Test(groups = "listUsers", dependsOnGroups = {"getUsers"},
            description = "List users with attribute value in uppercase")
    public void testFilterAllUsersWithMultiCaseAttributeOperator() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.UserSchemaConstants.USER_NAME
                + "+eQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the users with an multi case attribute operator.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME).getAsString(), "Devid",
                    "Failed in retrieving actual attributes of the user.");
        }
    }

    /*@Test(groups = "searchUsers", dependsOnGroups = {"listUsers"}, description = "Search users with http POST")
    public void searchUsersWithPostWithCount() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, 1);
        searchFilter.addProperty(SCIMConstants.OperationalConstants.COUNT, 2);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(Charsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in searching users with POST request including count and start index.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() == 2, "Failed in searching users with POST request including count and start index.");
    }*/

    @Test(groups = "searchUsers", dependsOnGroups = {"listUsers"}, description = "Search users with http POST " +
            "with attributes")
    public void searchUsersWithPostWithAttributes() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, 1);
        searchFilter.addProperty(SCIMConstants.OperationalConstants.COUNT, 2);
        JsonArray attributesArray = new JsonArray();
        attributesArray.add(new JsonPrimitive(SCIMConstants.UserSchemaConstants.USER_NAME));
        searchFilter.add(SCIMConstants.OperationalConstants.ATTRIBUTES, attributesArray);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(Charsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in searching users with POST request including attributes.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                    "Failed in retrieving actual attributes of the user.");
            Assert.assertNull(resourceObj.get(SCIMConstants.UserSchemaConstants.EMAILS),
                    "Failed in retrieving actual attributes of the user.");
        }
    }

    @Test(groups = "searchUsers", dependsOnGroups = {"listUsers"}, description = "Search users with http POST " +
            "with excluding attributes")
    public void searchUsersWithPostWithExcludingAttributes() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, 1);
        searchFilter.addProperty(SCIMConstants.OperationalConstants.COUNT, 2);
        JsonArray attributesArray = new JsonArray();
        attributesArray.add(new JsonPrimitive(SCIMConstants.UserSchemaConstants.USER_NAME));
        searchFilter.add(SCIMConstants.OperationalConstants.EXCLUDED_ATTRIBUTES, attributesArray);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(Charsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in searching users with POST request including excluding attributes.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNull(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                    "Failed in retrieving actual attributes of the user.");
            Assert.assertNotNull(resourceObj.get(SCIMConstants.UserSchemaConstants.NAME),
                    "Failed in retrieving actual attributes of the user.");
        }
    }

    @Test(groups = "updateUsers", dependsOnGroups = {"searchUsers"}, description = "Update User via SCIM")
    public void testUpdateUser() throws Exception {

        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Jayawardana");

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId,
                HttpMethod.PUT);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in updating the user.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.getUser(scimId);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in retrieving the user.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject userObj = GSON.fromJson(content, JsonObject.class);
        String familyName = ((JsonObject) userObj.get(SCIMConstants.UserSchemaConstants.NAME)).
                get(SCIMConstants.UserSchemaConstants.FAMILY_NAME).toString().replace("\"", "");
        Assert.assertEquals(familyName, "Jayawardana", "Failed in retrieving actual attributes of the user.");

    }

    @Test(dependsOnGroups = {"updateUsers"}, description = "Delete User via SCIM")
    public void testDeleteUser() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.deleteUser(scimId);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NO_CONTENT.getStatusCode(),
                "Failed in deleting the user.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.getUser(scimId);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NOT_FOUND.getStatusCode(),
                "Successfully retrieving a deleted user.");
        urlConn.disconnect();

    }
}
