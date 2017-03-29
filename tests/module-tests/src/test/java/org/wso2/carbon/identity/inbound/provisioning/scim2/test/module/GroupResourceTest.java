/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.inbound.provisioning.scim2.test.module;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerSuite;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.inbound.provisioning.scim2.test.module.commons.utills.SCIMOSGiTestUtils;
import org.wso2.carbon.identity.inbound.provisioning.scim2.test.module.commons.utills.SCIMTestUtil;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.Response;

import static org.ops4j.pax.exam.CoreOptions.systemProperty;

@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class GroupResourceTest {

    private static final Gson GSON = new Gson();
    private static String userSCIMID1 = null;
    private static String userSCIMID2 = null;
    private static String groupSCIMID = null;

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

    @Test(groups = "addGroups", description = "Add a Group via SCIM")
    public void testAddGroup() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createGroup("Marketing");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject groupObj = GSON.fromJson(content, JsonObject.class);
        groupSCIMID = groupObj.get(SCIMConstants.CommonSchemaConstants.ID).toString().replace("\"", "");
        Assert.assertNotNull(groupSCIMID, "Invalid scim group id.");
    }

    @Test(groups = "addGroups", description = "Add Group via SCIM without Mandatory Attributes")
    public void testAddUserWithoutMandatoryAttributes() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.createGroup(null);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the group without mandatory attributes.");
    }

    @Test (groups = "addGroups", dependsOnMethods = {"testAddGroup"}, description = "Add Existing Group via SCIM")
    public void testAddExistingGroup() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.createGroup("Marketing");
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added an existing group.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CONFLICT.getStatusCode(),
                "Failed in retrieving \"Conflict\" as the response.");
    }

    /*@Test(groups = "addGroups", description = "Add Group via SCIM with Invalid Admin Credentials")
    public void testAddGroupWithInvalidCredentials() throws Exception {
        JsonObject groupJsonObj = new JsonObject();

        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);

        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "Finance");

        HttpURLConnection urlConn = SCIMTestUtil.connectionWithInvalidAdminCredentials(SCIMConstants.GROUP_ENDPOINT,
                HttpMethod.POST);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the group with invalid admin credentials.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNAUTHORIZED.getStatusCode(),
                "Failed in retrieving \"Unauthorized\" as the response.");
    }*/

    @Test(groups = "addGroups", description = "Add Group via SCIM without Authorization Header")
    public void testAddGroupWithoutAuthorizationHeader() throws Exception {
        JsonObject groupJsonObj = new JsonObject();

        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);

        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "HR");

        HttpURLConnection urlConn = SCIMTestUtil.connectionWithoutAuthorizationHeader(SCIMConstants.GROUP_ENDPOINT,
                HttpMethod.POST);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the group without authorization header.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNAUTHORIZED.getStatusCode(),
                "Failed in retrieving \"Unauthorized\" as the response.");
    }

    @Test(groups = "addGroups", description = "Add Group via SCIM with invalid Syntax in Json Payload.")
    public void testAddGroupWithInvalidSyntaxInJsonPayload() throws Exception {
        JsonObject groupJsonObj = new JsonObject();

        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);

        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "Engineering-Tech");

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT,
                HttpMethod.POST);
        urlConn.getOutputStream().write(groupJsonObj.toString().substring(0, groupJsonObj.toString().length() - 1)
                .getBytes(StandardCharsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the group with invalid syntax in json payload.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.BAD_REQUEST.getStatusCode(),
                "Failed in retrieving \"Bad Request\" as the response.");
    }

    @Test(groups = "addGroups", description = "Add Group via SCIM with invalid Semantic in Json Payload.")
    public void testAddGroupWithInvalidSemanticInJsonPayload() throws Exception {
        JsonObject groupJsonObj = new JsonObject();

        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.DISPLAY_NAME, "Engineering-1");

        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);

        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT,
                HttpMethod.POST);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the group with invalid semantic in json payload.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.BAD_REQUEST.getStatusCode(),
                "Failed in retrieving \"Bad Request\" as the response.");
    }

    @Test(groups = "addGroups", description = "Add Group via SCIM without specifying 'Content-Type' header.")
    public void testAddGroupWithoutContentTypeHeader() throws Exception {
        JsonObject groupJsonObj = new JsonObject();

        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);

        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "Engineering-2");

        HttpURLConnection urlConn = SCIMTestUtil.connectionWithoutContentTypeHeader(SCIMConstants.GROUP_ENDPOINT,
                HttpMethod.POST);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Successfully added the group without content type header.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNSUPPORTED_MEDIA_TYPE.getStatusCode(),
                "Failed in retrieving \"Unsupported Media Type\" as the response.");
    }

    @Test(groups = "addGroups", description = "Add Group via SCIM specifying a attribute which is not in the schema.")
    public void testAddGroupWithInvalidAttribute() throws Exception {
        JsonObject groupJsonObj = new JsonObject();

        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);

        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "Engineering-3");
        groupJsonObj.addProperty("attribute", "test");

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT,
                HttpMethod.POST);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed in adding the group with invalid attribute.");
    }

    @Test(groups = "addGroups", description = "Add a group with a user via SCIM")
    public void testAddGroupWithMembers() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createUser("Tom", null, "Luvis",
                new ArrayList<String>() { { add("tom@gmail.com"); add("tom@yahoo.com"); } });
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject userObj = GSON.fromJson(content, JsonObject.class);
        userSCIMID1 = userObj.get(SCIMConstants.CommonSchemaConstants.ID).toString().replace("\"", "");

        JsonObject groupJsonObj = new JsonObject();
        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);

        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "Tourist");

        JsonArray members = new JsonArray();
        JsonObject member = new JsonObject();
        member.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, userSCIMID1);
        members.add(member);

        groupJsonObj.add(SCIMConstants.GroupSchemaConstants.MEMBERS, members);
        urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT, HttpMethod.POST);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode());
        content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        groupJsonObj = GSON.fromJson(content, JsonObject.class);
        String groupSCIMIDWithMembers = groupJsonObj.get(SCIMConstants.CommonSchemaConstants.ID).toString()
                .replace("\"", "");

        //Get group object again to check members

        urlConn = SCIMTestUtil.getGroup(groupSCIMIDWithMembers);
        content = SCIMTestUtil.getContent(urlConn);
        groupJsonObj = GSON.fromJson(content, JsonObject.class);

        Assert.assertTrue((((JsonArray) groupJsonObj.get(SCIMConstants.GroupSchemaConstants.MEMBERS)).
                size()) > 0);
    }

    @Test(groups = "getGroups", dependsOnGroups = {"addGroups"}, description = "Get a Group via SCIM")
    public void testGetGroup() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.getGroup(groupSCIMID);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject groupJsonObj = GSON.fromJson(content, JsonObject.class);
        String displayName = groupJsonObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).toString()
                .replace("\"", "");
        Assert.assertEquals(displayName, "Marketing");
    }

    /*@Test(groups = "getGroups", dependsOnGroups = {"addGroups"},
            description = "Get Group via SCIM with invalid Group ID")
    public void testGetGroupWithInvalidUserId() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.getUser(groupSCIMID.substring(0, groupSCIMID.length() - 1));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully retrieving a group for an invalid group ID.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NOT_FOUND.getStatusCode(),
                "Failed in retrieving \"Not Found\" as the response.");
    }*/

    /*@Test(groups = "getGroups", dependsOnGroups = {"addGroups"},
            description = "Get Group via SCIM with invalid Admin Credentials")
    public void testGetGroupWithInvalidCredentials() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.connectionWithInvalidAdminCredentials
                (SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID, HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully retrieving a group with an invalid admin credentials.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNAUTHORIZED.getStatusCode(),
                "Failed in retrieving \"Unauthorized\" as the response.");
    }*/

    @Test(groups = "getGroups", dependsOnGroups = {"addGroups"},
            description = "Get Group via SCIM without Authorization Header")
    public void testGetGroupWithoutAuthorizationHeader() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.connectionWithoutAuthorizationHeader
                (SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID, HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully retrieving a group without an authorization header.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNAUTHORIZED.getStatusCode(),
                "Failed in retrieving \"Unauthorized\" as the response.");
    }

    @Test(groups = "getGroups", dependsOnGroups = {"addGroups"},
            description = "Get a Group with given exact attribute name")
    public void testGetGroupWithValidAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID + "?"
                        + SCIMConstants.OperationalConstants.ATTRIBUTES + "="
                        + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME,
                HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in retrieving the group with a valid attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertNotNull(result.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME),
                "Failed in retrieving the group with a valid attribute.");
        Assert.assertNull(result.get(SCIMConstants.GroupSchemaConstants.DISPLAY),
                "Failed in retrieving the group with a valid attribute.");
    }

    @Test(groups = "getGroups", dependsOnGroups = {"addGroups"},
            description = "Get a Group with given invalid attribute")
    public void testGetGroupWithInvalidAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID + "?"
                + SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + "description", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in retrieving the group with an invalid attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertNotNull(result.get(SCIMConstants.CommonSchemaConstants.ID),
                "Successfully retrieving the group with an invalid attribute.");
        Assert.assertNull(result.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME),
                "Failed in retrieving the group with an invalid attribute.");
    }

    @Test(groups = "getGroups", dependsOnGroups = {"addGroups"},
            description = "Get a Group with given exact attribute type")
    public void testGetGroupWithFilterExactAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID +
                "?filter=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME + "+EQ+Marketing", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering the group with a exact attribute type.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertEquals(result.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).getAsString(), "Marketing",
                "Failed in retrieving the correct group attributes.");
    }

    @Test(groups = "getGroups", dependsOnGroups = {"addGroups"},
            description = "Get a Group with attribute value in uppercase")
    public void testGetGroupWithFilterUpperCaseAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID +
                "?filter=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME.toUpperCase() + "+EQ+Marketing",
                HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering the group with an attribute type in upper case.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertEquals(result.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).getAsString(), "Marketing",
                "Failed in retrieving the correct group attributes.");
    }

    @Test(groups = "getGroups", dependsOnGroups = {"addGroups"},
            description = "Get a Group with given exact attribute value")
    public void testGetGroupWithFilterLowerCaseAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID +
                        "?filter=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME.toLowerCase() + "+EQ+Marketing",
                HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering the group with an attribute type in lower case.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertEquals(result.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).getAsString(), "Marketing",
                "Failed in retrieving the correct group attributes.");
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"}, description = "List groups for given indexes")
    public void testListGroups() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the groups.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0, "Failed in listing all the groups.");
    }

    /*@Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List Groups via SCIM with invalid Admin Credentials")
    public void testListGroupsWithInvalidCredentials() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.connectionWithInvalidAdminCredentials
                (SCIMConstants.GROUP_ENDPOINT, HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully listing all the groups with invalid admin credentials.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNAUTHORIZED.getStatusCode(),
                "Failed in retrieving \"Unauthorized\" as the response.");
    }*/

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List Groups via SCIM without Authorization Header")
    public void testListGroupsWithoutAuthorizationHeader() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.connectionWithoutAuthorizationHeader
                (SCIMConstants.GROUP_ENDPOINT, HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully listing all the groups without authorization header.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNAUTHORIZED.getStatusCode(),
                "Failed in retrieving \"Unauthorized\" as the response.");
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"}, description = "List Groups for given indexes")
    public void testListGroupsWithPagination() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createGroup("EngineeringQuality");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.createGroup("EngineeringQualityAssurance");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.ListedResourceSchemaConstants.START_INDEX + "=" + 1 + "&count=" + 3, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the groups with pagination.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0, "Failed in listing all the groups with pagination.");
        Assert.assertEquals(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).size(),
                3, "Failed in listing the correct number of groups with pagination.");
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"}, description = "List Groups with invalid count")
    public void testListGroupsWithPaginationInvalidCount() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createGroup("EngQuality");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.createGroup("EngQualityAssurance");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.ListedResourceSchemaConstants.START_INDEX + "=" + 1 + "&count=" + "abc", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.BAD_REQUEST.getStatusCode(),
                "Failed in listing all the groups with pagination.");
        urlConn.disconnect();
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"}, description = "List Groups with invalid startIndex")
    public void testListGroupsWithPaginationInvalidStartIndex() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createGroup("EngineeringQualityGroup");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.createGroup("EngineeringQualityAssuranceGroup");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.ListedResourceSchemaConstants.START_INDEX + "=" + "abc" + "&count=" + 3, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.BAD_REQUEST.getStatusCode(),
                "Failed in listing all the groups with pagination.");
        urlConn.disconnect();

    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List Groups for given negative indexes")
    public void testListGroupsWithPaginationInNegativeStartIndex() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createGroup("Engineering-5");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.createGroup("Engineering-6");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.ListedResourceSchemaConstants.START_INDEX + "=" + -1 + "&count=" + 3, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the groups with pagination.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        // As per the spec,value which is less than one for startIndex interpreted as "1" and count interpreted as "0"
        // A value of "0" indicates that no resource results are to be returned except for "totalResults"
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0, "Failed in listing all the groups with pagination.");
        Assert.assertEquals(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).size(),
                3, "Failed in listing the correct number of groups with pagination when startIndex parameter is a " +
                        "negative value.");
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups for given negative count index")
    public void testListGroupsWithPaginationInNegativeCount() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createGroup("Engineering-7");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.createGroup("Engineering-8");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.ListedResourceSchemaConstants.START_INDEX + "=" + 1 + "&count=" + -3, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the groups with pagination.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        // As per the spec,value which is less than one for startIndex interpreted as "1" and count interpreted as "0"
        // A value of "0" indicates that no resource results are to be returned except for "totalResults"
        Assert.assertEquals((result.get("totalResults")).getAsInt(),
                0, "Failed in retrieving the correct result with pagination when count parameter is a " +
                        "negative values.");
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups for given exceeded count index")
    public void testListGroupsWithPaginationInExceededCount() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.ListedResourceSchemaConstants.START_INDEX + "=" + 1 + "&count=" + 300, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the groups with pagination.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0, "Failed in listing all the groups with pagination.");
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups for given filter for a Single Valued Attribute")
    public void testListUsersWithFilterForSingleValuedAttribute() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?filter=" +
                SCIMConstants.GroupSchemaConstants.DISPLAY_NAME + "+EQ+Marketing", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the groups with a single valued attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get("Resources")).size() > 0,
                "Failed in filtering all the groups with a single valued attribute.");
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"}, description = "List users for given semantically " +
            "invalid filter for a Single Valued Attribute")
    public void testListGroupsWithSemanticallyInvalidFilterForSingleValuedAttribute() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?filter=" +
                SCIMConstants.GroupSchemaConstants.DISPLAY_NAME + "+EQMarketing", HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully filtering all the groups with a semantically invalid request for " +
                        "single valued attribute.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.BAD_REQUEST.getStatusCode(),
                "Failed in retrieving \"Bad Request\" as the response.");
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups for given unsupported filter")
    public void testListGroupsWithUnsupportedFilter() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?filter=" +
                SCIMConstants.GroupSchemaConstants.DISPLAY_NAME + "+E+Silva", HttpMethod.GET);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully filtering all the groups with an unsupported filter.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.BAD_REQUEST.getStatusCode(),
                "Failed in retrieving \"Bad Request\" as the response.");
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups with given exact attribute name")
    public void testListGroupsWithExactAttribute() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME,
                HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the groups with an exact attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME),
                    "Failed in retrieving actual attributes of the group.");
            Assert.assertNull(resourceObj.get(SCIMConstants.GroupSchemaConstants.MEMBERS),
                    "Failed in retrieving actual attributes of the group.");
        }
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups with given invalid attribute")
    public void testListGroupsWithInvalidAttribute() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + "description", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the groups with an invalid attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.ResourceTypeSchemaConstants.ID),
                    "Failed in retrieving actual attributes of the group.");
            Assert.assertNull(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME),
                    "Failed in retrieving actual attributes of the group.");
        }
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"}, description = "List groups with exclude attribute")
    public void testListGroupsWithExcludeAttributes() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?excludedAttributes=" +
                SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in listing all the groups with an excluded attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.CommonSchemaConstants.ID),
                    "Failed in retrieving actual attributes of the group.");
            Assert.assertNull(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME),
                    "Failed in retrieving actual attributes of the group.");
        }
    }

    /*@Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List Groups based on user resource type")
    public void testFilterGroupsBasedOnUserResourceType() throws Exception {
        HttpURLConnection urlConn = SCIMTestUtil.validConnection("?" +
                        SCIMConstants.OperationalConstants.FILTER + "=(meta.resourceType eq Group)", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the groups based on user resource type.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME),
                "Failed in retrieving actual attributes of the group.");
            Assert.assertNull(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME),
                    "Failed in retrieving actual attributes of the group.");
        }
    }*/

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups with given exact attribute value")
    public void testFilterGroupsWithExactAttributeName() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME
                + "+EQ+Marketing", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the groups with an exact attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).getAsString(),
                    "Marketing", "Failed in retrieving actual attributes of the group.");
        }
    }

    /*@Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups with given exact attribute value")
    public void testFilterGroupsWithLowerCaseAttributeName() throws Exception {

       HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
               SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME
               .toLowerCase() + "+EQ+Marketing", HttpMethod.GET);
       Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
               "Failed in filtering all the groups with an exact attribute.");
       String content = SCIMTestUtil.getContent(urlConn);
       JsonObject result = GSON.fromJson(content, JsonObject.class);
       JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
       for (JsonElement resource : resources) {
           JsonObject resourceObj = ((JsonObject) resource);
           Assert.assertEquals(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).getAsString(),
                   "Marketing", "Failed in retrieving actual attributes of the group.");
       }
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups with attribute value in uppercase")
    public void testFilterGroupsWithUpperCaseAttributeName() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME
                .toUpperCase() + "+EQ+Marketing", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the groups with an exact attribute.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).getAsString(),
                    "Marketing", "Failed in retrieving actual attributes of the group.");
        }
    }*/

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups with given exact attribute value")
    public void testFilterGroupsWithLowerCaseAttributeOperator() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME
                + "+eq+Marketing", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the groups with an lower case attribute operator.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).getAsString(),
                    "Marketing", "Failed in retrieving actual attributes of the group.");
        }
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups with attribute value in uppercase")
    public void testFilterGroupsWithUpperCaseAttributeOperator() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME
                + "+EQ+Marketing", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the groups with an upper case attribute operator.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).getAsString(),
                    "Marketing", "Failed in retrieving actual attributes of the group.");
        }
    }

    @Test(groups = "listGroups", dependsOnGroups = {"getGroups"},
            description = "List groups with attribute value in multicase")
    public void testFilterGroupsWithMultiCaseAttributeOperator() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.OperationalConstants.FILTER + "=" + SCIMConstants.GroupSchemaConstants.DISPLAY_NAME
                + "+eQ+Marketing", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in filtering all the groups with an multi case attribute operator.");
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertEquals(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).getAsString(),
                    "Marketing", "Failed in retrieving actual attributes of the group.");
        }
    }

    @Test(groups = "searchGroups", dependsOnGroups = {"listGroups"},
            description = "Search groups with http POST via SCIM")
    public void searchGroupsWithPostWithCount() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, 1);
        searchFilter.addProperty("count", 2);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(StandardCharsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() == 2, "Failed in retrieving correct number of groups when searching users with POST request " +
                "including count and start index.");
    }

    @Test(groups = "searchGroups", dependsOnGroups = {"listGroups"},
            description = "Search groups with http POST via SCIM in negative start index")
    public void searchGroupsWithPostWithNegativeStartIndex() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, -1);
        searchFilter.addProperty("count", 2);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(StandardCharsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() == 2, "Failed in retrieving correct number of groups when searching users with POST request " +
                "including count and start index.");
    }

    @Test(groups = "searchGroups", dependsOnGroups = {"listGroups"},
            description = "Search groups with http POST via SCIM in negative count")
    public void searchGroupsWithPostWithNegativeCount() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, 1);
        searchFilter.addProperty("count", -2);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(StandardCharsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertEquals((result.get("totalResults")).getAsInt(),
                0, "Failed in retrieving the correct result when searching users with POST request " +
                        "including negative count and start index.");
    }

    @Test(groups = "searchGroups", dependsOnGroups = {"listGroups"}, description = "Search groups with http POST " +
            "with attributes")
    public void searchGroupsWithPostWithAttributes() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, 1);
        searchFilter.addProperty(SCIMConstants.OperationalConstants.COUNT, 3);

        JsonArray attributesArray = new JsonArray();
        attributesArray.add(new JsonPrimitive(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME));
        searchFilter.add(SCIMConstants.OperationalConstants.ATTRIBUTES, attributesArray);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(StandardCharsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in searching users with POST request including attributes.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME),
                    "Failed in retrieving actual attributes of the group.");
            Assert.assertNull(resourceObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY),
                    "Failed in retrieving actual attributes of the group.");
        }
    }

    @Test(groups = "searchGroups", dependsOnGroups = {"listGroups"}, description = "Search groups with http POST " +
            "with excluding attributes")
    public void searchGroupsWithPostWithExcludingAttributes() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, 1);
        searchFilter.addProperty(SCIMConstants.OperationalConstants.COUNT, 3);

        JsonArray attributesArray = new JsonArray();
        attributesArray.add(new JsonPrimitive(SCIMConstants.GroupSchemaConstants.MEMBERS));
        searchFilter.add(SCIMConstants.OperationalConstants.EXCLUDED_ATTRIBUTES, attributesArray);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(StandardCharsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in searching users with POST request including attributes.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.CommonSchemaConstants.ID),
                    "Failed in retrieving actual attributes of the group.");
            Assert.assertNull(resourceObj.get(SCIMConstants.GroupSchemaConstants.MEMBERS),
                    "Failed in retrieving actual attributes of the group.");
        }
    }

    @Test(groups = "updateGroups", dependsOnGroups = {"searchGroups"}, description = "Update a group via SCIM")
    public void testUpdateGroup() throws Exception {

        //Create a new User
        HttpURLConnection urlConn = SCIMTestUtil.createUser("Matt", null, "Damon",
                new ArrayList<String>() { { add("matt@gmail.com"); add("matt@yahoo.com"); } });
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject userObj = GSON.fromJson(content, JsonObject.class);
        userSCIMID2 = userObj.get(SCIMConstants.CommonSchemaConstants.ID).toString().replace("\"", "");

        //Build Group payload
        JsonObject groupJsonObj = new JsonObject();
        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);
        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "Marketing");
        JsonArray members = new JsonArray();
        JsonObject member = new JsonObject();
        member.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, userSCIMID2);
        members.add(member);
        groupJsonObj.add(SCIMConstants.GroupSchemaConstants.MEMBERS, members);

        //Send update request
        urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID, HttpMethod.PUT);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        urlConn.disconnect();

        //Get Group again to check update
        urlConn = SCIMTestUtil.getGroup(groupSCIMID);
        content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        groupJsonObj = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue((((JsonArray) groupJsonObj.get(SCIMConstants.GroupSchemaConstants.MEMBERS)).
                size()) > 0);
    }

    @Test(groups = "updateGroups", dependsOnGroups = {"searchGroups"},
            description = "Update Group with incorrect attributes via SCIM")
    public void testUpdateGroupWithInvalidAttribute() throws Exception {

        JsonObject groupJsonObj = new JsonObject();
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "Engineering_9");
        groupJsonObj.addProperty("attribute", "attribute_value");
        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID,
                HttpMethod.PUT);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in updating the group with an incorrect attribute.");
    }

    @Test(groups = "updateGroups", dependsOnGroups = {"searchGroups"},
            description = "Update Group with incorrect scim ID via SCIM")
    public void testUpdateGroupWithIncorrectScimID() throws Exception {

        JsonObject groupJsonObj = new JsonObject();
        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);
        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "HRGroup2");

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" +
                groupSCIMID.substring(0, groupSCIMID.length() - 2), HttpMethod.PUT);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully updating the group with an incorrect SCIM ID.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NOT_FOUND.getStatusCode(),
                "Failed in retrieving \"Not Found\" as the response.");
        urlConn.disconnect();
    }

    /*@Test(groups = "updateGroups", dependsOnGroups = {"searchGroups"},
            description = "Update Group with invalid admin credentials via SCIM")
    public void testUpdateGroupWithInvalidCredentials() throws Exception {

        JsonObject groupJsonObj = new JsonObject();
        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);
        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "HR-3");

        HttpURLConnection urlConn = SCIMTestUtil.connectionWithInvalidAdminCredentials(SCIMConstants.GROUP_ENDPOINT +
                "/" + groupSCIMID, HttpMethod.PUT);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully updating the group with an invalid admin credentials.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNAUTHORIZED.getStatusCode(),
                "Failed in retrieving \"Unauthorized\" as the response.");
        urlConn.disconnect();
    }*/

    @Test(groups = "updateGroups", dependsOnGroups = {"searchGroups"},
            description = "Update Group with incorrect content type via SCIM")
    public void testUpdateGroupWithIncorrectContentType() throws Exception {

        JsonObject groupJsonObj = new JsonObject();
        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);
        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "HRGroup");

        HttpURLConnection urlConn = SCIMTestUtil.connectionWithIncorrectContentTypeHeader(SCIMConstants.GROUP_ENDPOINT +
                "/" + groupSCIMID, HttpMethod.PUT);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(StandardCharsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully updating the group with an incorrect Content Type.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNSUPPORTED_MEDIA_TYPE.getStatusCode(),
                "Failed in retrieving \"Unsupported Media Type\" as the response.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.getGroup(groupSCIMID);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Failed in retrieving the group.");
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject userObj = GSON.fromJson(content, JsonObject.class);
        String familyName = userObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).toString();
        Assert.assertNotEquals(familyName, "HRGroup", "Failed in retrieving actual attributes of the group.");
    }

    @Test(groups = "updateGroups", dependsOnGroups = {"searchGroups"},
            description = "Update Group with incorrect method via SCIM")
    public void testUpdateGroupWithIncorrectMethod() throws Exception {

        JsonObject groupJsonObj = new JsonObject();
        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);
        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "HR-5");

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID,
                HttpMethod.OPTIONS);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully updating the group with an incorrect method.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.METHOD_NOT_ALLOWED.getStatusCode(),
                "Failed in retrieving \"Method Not Found\" as the response.");
        urlConn.disconnect();
    }

    @Test(groups = "updateGroups", dependsOnGroups = {"searchGroups"},
            description = "Update Group with incorrect data content via SCIM")
    public void testUpdateGroupWithIncorrectDataContent() throws Exception {

        JsonObject groupJsonObj = new JsonObject();
        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);
        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, "HR-6");

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID,
                HttpMethod.PUT);
        urlConn.getOutputStream().write(groupJsonObj.toString().substring(0, groupJsonObj.toString().length() - 1)
                .getBytes(StandardCharsets.UTF_8));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode(),
                "Successfully updating the group with an incorrect data content.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.BAD_REQUEST.getStatusCode(),
                "Failed in retrieving \"Bad Request\" as the response.");
        urlConn.disconnect();
    }

    /*@Test(dependsOnGroups = {"updateGroups"}, description = "Delete group via SCIM")
    public void testDeleteGroup() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.deleteGroup(groupSCIMID);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NO_CONTENT.getStatusCode(),
                "Failed in deleting the group.");
        urlConn.disconnect();

        urlConn = SCIMTestUtil.getUser(groupSCIMID);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NOT_FOUND.getStatusCode(),
                "Failed in retrieving \"Not Found\" as the response when trying to retrieve a deleted group.");
        urlConn.disconnect();
    }*/

    /*@Test(dependsOnGroups = {"updateGroups"}, description = "Delete Group with incorrect identifier via SCIM")
    public void testDeleteGroupWithIncorrectIdentifier() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.deleteUser(groupSCIMID.substring(0, groupSCIMID.length() - 1));
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.NO_CONTENT.getStatusCode(),
                "Successfully deleting a group with incorrect Identifier.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NOT_FOUND.getStatusCode(),
                "Failed in retrieving \"Not Found\" as the response.");
        urlConn.disconnect();
    }*/

    /*@Test(dependsOnGroups = {"updateGroups"}, description = "Delete User with invalid credentials via SCIM")
    public void testDeleteGroupWithInvalidCredentials() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.connectionWithInvalidAdminCredentials(SCIMConstants.GROUP_ENDPOINT +
                "/" + groupSCIMID, HttpMethod.DELETE);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.NO_CONTENT.getStatusCode(),
                "Successfully deleting a group with invalid admin credentials.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.UNAUTHORIZED.getStatusCode(),
                "Failed in retrieving \"Unauthorized\" as the response.");
        urlConn.disconnect();
    }*/

    @Test(dependsOnGroups = {"updateGroups"}, description = "Delete User with wrong method via SCIM")
    public void testDeleteGroupWithWrongMethod() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/"
                + groupSCIMID, HttpMethod.POST);
        Assert.assertNotEquals(urlConn.getResponseCode(), Response.Status.NO_CONTENT.getStatusCode(),
                "Successfully deleting a group with wrong method.");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.METHOD_NOT_ALLOWED.getStatusCode(),
                "Failed in retrieving \"Method Not Allowed\" as the response.");
        urlConn.disconnect();
    }

}
