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
import org.wso2.carbon.identity.inbound.provisioning.scim2.test.module.commons.utills.SCIMTestConstant;
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
public class MeResourceTest {

    private static final Gson GSON = new Gson();

    private static Logger log = LoggerFactory.getLogger(MeResourceTest.class);


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

    @Test(description = "Add my identity via SCIM")
    public void testAddMe() throws Exception {

        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Gunasinghe");

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());
        userJsonObj.addProperty(SCIMConstants.UserSchemaConstants.USER_NAME, "hasini");


        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMTestConstant.ME_ENDPOINT, HttpMethod.POST);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode());
        String content =  SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();

    }

   @Test(dependsOnMethods = { "testAddMe" }, description = "Update my identity via SCIM")
    public void testUpdateMe() throws Exception {

        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Jayawardana");

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMTestConstant.ME_ENDPOINT, HttpMethod.PUT);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());

        JsonObject jsonObject = getUser();
        Assert.assertEquals(((JsonObject) jsonObject.get(SCIMConstants.UserSchemaConstants.NAME)).
                get(SCIMConstants.UserSchemaConstants.FAMILY_NAME).toString().replace("\"", ""),
                "Jayawardana");
        urlConn.disconnect();
    }

    @Test(dependsOnMethods = { "testUpdateMe" }, description = "Delete my identity via SCIM")
    public void testDeleteMe() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.createUser("admin2", "password", "admin2",
                new ArrayList<String>() { { add("admin@gmail.com"); add("admin@yahoo.com"); } });
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.CREATED.getStatusCode(),
                "Failed to add the user.");

        urlConn = SCIMTestUtil.validConnection(SCIMTestConstant.ME_ENDPOINT, HttpMethod.DELETE, "admin2", "password");
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.NO_CONTENT.getStatusCode());
        urlConn.disconnect();
    }

    private JsonObject getUser() throws Exception {

        HttpURLConnection urlConn = SCIMTestUtil.validConnection(SCIMTestConstant.ME_ENDPOINT, HttpMethod.GET);
        Assert.assertEquals(urlConn.getResponseCode(), Response.Status.OK.getStatusCode());
        String content =  SCIMTestUtil.getContent(urlConn);
        urlConn.disconnect();
        return GSON.fromJson(content, JsonObject.class);

    }
}
