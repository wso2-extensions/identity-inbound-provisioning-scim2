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
import org.wso2.charon.core.v2.schema.SCIMConstants;

import java.net.HttpURLConnection;
import java.nio.file.Paths;
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

    @Test (description = "Add User via SCIM")
    public void testAddUser() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createUser("Devid", "Silva");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject userObj = GSON.fromJson(content, JsonObject.class);
        scimId = userObj.get(SCIMConstants.CommonSchemaConstants.ID).toString().replace("\"", "");
    }

    @Test (dependsOnMethods = "testAddUser", description = "Get User via SCIM")
    public void testGetUser () throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.getUser(scimId);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject userObj = GSON.fromJson(content, JsonObject.class);
        String userName = userObj.get(SCIMConstants.UserSchemaConstants.USER_NAME).toString().replace("\"", "");
        String familyName = ((JsonObject) userObj.get(SCIMConstants.UserSchemaConstants.NAME)).
                get(SCIMConstants.UserSchemaConstants.FAMILY_NAME).toString().replace("\"", "");

        Assert.assertEquals(userName, "Devid");
        Assert.assertEquals(familyName, "Silva");

    }

    @Test(dependsOnMethods = {"testGetUser"}, description = "Update User via SCIM")
    public void testUpdateUser() throws Exception {

        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Jayawardana");

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());

        HttpURLConnection urlConn = SCIMTestUtil.request(SCIMConstants.USER_ENDPOINT + "/" + scimId,
                HttpMethod.PUT);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        urlConn.disconnect();

        urlConn = SCIMTestUtil.getUser(scimId);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        JsonObject userObj = GSON.fromJson(content, JsonObject.class);
        String familyName = ((JsonObject) userObj.get(SCIMConstants.UserSchemaConstants.NAME)).
                get(SCIMConstants.UserSchemaConstants.FAMILY_NAME).toString().replace("\"", "");
        Assert.assertEquals(familyName, "Jayawardana");

    }

    @Test(dependsOnMethods = {"testUpdateUser"}, description = "List users for given indexes")
    public void testListAllUsersWithPagination() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createUser("Smith", "Hunt");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode());
        urlConn.disconnect();

        urlConn = SCIMTestUtil.createUser("Rajive", "Kumar");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode());
        urlConn.disconnect();

        urlConn = SCIMTestUtil.request(SCIMConstants.USER_ENDPOINT + "?" +
                SCIMConstants.ListedResourceSchemaConstants.START_INDEX + "=" + 1 + "&count=" + 3, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0);

    }

    @Test(dependsOnMethods = {"testListAllUsersWithPagination"}, description = "List users for given filter")
    public void testListAllUsersWithFilter() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.request(SCIMConstants.USER_ENDPOINT + "?filter=" +
                SCIMConstants.UserSchemaConstants.USER_NAME + "+EQ+Devid", HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get("Resources")).size() > 0);
    }

    @Test(dependsOnMethods = {"testListAllUsersWithFilter"}, description = "List users with given attribute")
    public void testListAllUsersWithAttributes() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.request(SCIMConstants.USER_ENDPOINT + "?" +
                        SCIMConstants.OperationalConstants.ATTRIBUTES + "=" + SCIMConstants.UserSchemaConstants.
                        USER_NAME, HttpMethod.GET);
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME));
            Assert.assertNull(resourceObj.get(SCIMConstants.UserSchemaConstants.FAMILY_NAME));
        }

    }

    @Test(dependsOnMethods = {"testListAllUsersWithAttributes"}, description = "List users with exclude attribute")
    public void testListAllUsersWithExcludeAttributes() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.request(SCIMConstants.USER_ENDPOINT + "?excludedAttributes=" +
                SCIMConstants.UserSchemaConstants.FAMILY_NAME, HttpMethod.GET);
        String content = SCIMTestUtil.getContent(urlConn);
        JsonObject result = GSON.fromJson(content, JsonObject.class);
        JsonArray resources = ((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES));
        for (JsonElement resource : resources) {
            JsonObject resourceObj = ((JsonObject) resource);
            Assert.assertNotNull(resourceObj.get(SCIMConstants.UserSchemaConstants.USER_NAME));
            Assert.assertNull(resourceObj.get(SCIMConstants.UserSchemaConstants.FAMILY_NAME));
        }

    }

    @Test(dependsOnMethods = {"testListAllUsersWithExcludeAttributes"}, description = "List all users")
    public void getAllUsers() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.request(SCIMConstants.USER_ENDPOINT, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0);
    }

    @Test(dependsOnMethods = {"getAllUsers"}, description = "Search users with http POST")
    public void searchUsersWithPost() throws Exception {

        JsonObject searchFilter = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(new JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:SearchRequest"));
        searchFilter.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        searchFilter.addProperty(SCIMConstants.ListedResourceSchemaConstants.START_INDEX, 1);
        searchFilter.addProperty("count", 10);

        HttpURLConnection urlConn = SCIMTestUtil.request(SCIMConstants.USER_ENDPOINT + "/.search",
                HttpMethod.POST);
        urlConn.getOutputStream().write(searchFilter.toString().getBytes(Charsets.UTF_8));

        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content = SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

        JsonObject result = GSON.fromJson(content, JsonObject.class);
        Assert.assertTrue(((JsonArray) result.get(SCIMConstants.ListedResourceSchemaConstants.RESOURCES)).
                size() > 0);
    }

    @Test (dependsOnMethods = {"searchUsersWithPost"}, description = "Delete User via SCIM")
    public void testDeleteUser() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.deleteUser(scimId);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NO_CONTENT.getStatusCode());
        urlConn.disconnect();

        urlConn = SCIMTestUtil.getUser(scimId);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NOT_FOUND.getStatusCode());
        urlConn.disconnect();

    }
}
