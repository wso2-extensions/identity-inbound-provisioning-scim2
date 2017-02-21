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
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.apache.commons.io.Charsets;
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

    @Test(description = "Add a Group via SCIM")
    public void testAddGroup() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createGroup("Marketing");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject groupObj = GSON.fromJson(content, JsonObject.class);
        groupSCIMID = groupObj.get(SCIMConstants.CommonSchemaConstants.ID).toString().replace("\"", "");

    }

    @Test(dependsOnMethods = "testAddGroup", description = "Get a Group via SCIM")
    public void testGetGroup() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.getGroup(groupSCIMID);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject groupObj = GSON.fromJson(content, JsonObject.class);
        String displayName = groupObj.get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME).toString().replace("\"", "");
        Assert.assertEquals(displayName, "Marketing");

    }

    @Test(dependsOnMethods = "testGetGroup", description = "Add a group with a user via SCIM")
    public void testAddGroupWithMembers() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createUser("Tom", "Luvis",
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
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode());
        content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        groupJsonObj = GSON.fromJson(content, JsonObject.class);
        String id = groupJsonObj.get(SCIMConstants.CommonSchemaConstants.ID).toString().replace("\"", "");

        //Get group object again to check members

        urlConn = SCIMTestUtil.getGroup(id);
        content = SCIMTestUtil.getContent(urlConn);
        groupJsonObj = GSON.fromJson(content, JsonObject.class);

        Assert.assertTrue((((JsonArray) groupJsonObj.get(SCIMConstants.GroupSchemaConstants.MEMBERS)).
                size()) > 0);

    }


    @Test(dependsOnMethods = {"testAddGroupWithMembers"}, description = "Update a group via SCIM")
    public void testUpdateGroup() throws Exception {

        //Create a new User
        HttpURLConnection urlConn = SCIMTestUtil.createUser("Matt", "Damon",
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

        //Send update validConnection
        urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + groupSCIMID, HttpMethod.PUT);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(Charsets.UTF_8));
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

    @Test(dependsOnMethods = {"testUpdateGroup"}, description = "List groups with pagination via SCIM")
    public void testListAllGroupsWithPagination() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "?" +
                SCIMConstants.ListedResourceSchemaConstants.START_INDEX + "=" + 1 + "&count=" + 3, HttpMethod.GET);
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0);
    }

    @Test(dependsOnMethods = {"testListAllGroupsWithPagination"}, description = "List all groups via SCIM")
    public void testGetAllGroups() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT, "GET");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0);
    }

    @Test(dependsOnMethods = {"testGetAllGroups"}, description = "Filter groups with HTTP POST via SCIM")
    public void getAllGroupsWithPost() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, 1);
        searchFilter.addProperty("count", 10);

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMConstants.GROUP_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(Charsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0);
    }

    @Test(dependsOnMethods = {"testGetAllGroups"}, description = "Delete group via SCIM")
    public void testDeleteGroup() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.deleteGroup(groupSCIMID);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NO_CONTENT.getStatusCode());
        urlConn.disconnect();
    }

}
