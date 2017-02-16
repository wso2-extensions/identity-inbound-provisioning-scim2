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

package org.wso2.carbon.identity.inbound.provisioning.scim2.test.module.commons.utills;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Base64;
import javax.net.ssl.HttpsURLConnection;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;

/**
 * Utility functions for SCIM test cases
 */
public class SCIMTestUtil {

    private static Logger log = LoggerFactory.getLogger(SCIMTestUtil.class);
    private static final String USER_NAME = "admin";
    private static final String PASSWORD = "admin";

    /**
     * Create a user with sample attributes
     *
     * @param userName
     * @param familyName
     * @return
     * @throws IOException
     */
    public static HttpURLConnection createUser(String userName, String familyName) throws IOException {

        JsonObject nameJsonObj = new JsonObject();
        nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, familyName);

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());
        userJsonObj.addProperty(SCIMConstants.UserSchemaConstants.USER_NAME, userName);

        HttpURLConnection urlConn = request(SCIMConstants.USER_ENDPOINT, HttpMethod.POST);
        urlConn.getOutputStream().write(userJsonObj.toString().getBytes(Charsets.UTF_8));
        return urlConn;
    }

    /**
     * Create a group
     *
     * @param groupName
     * @return
     * @throws IOException
     */
    public static HttpURLConnection createGroup(String groupName) throws IOException {

        JsonObject groupJsonObj = new JsonObject();

        JsonPrimitive schema = new JsonPrimitive("urn:ietf:params:scim:schemas:core:2.0:Group");
        JsonArray schemas = new JsonArray();
        schemas.add(schema);

        groupJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, schemas);
        groupJsonObj.addProperty(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME, groupName);

        HttpURLConnection urlConn = request(SCIMConstants.GROUP_ENDPOINT, HttpMethod.POST);
        urlConn.getOutputStream().write(groupJsonObj.toString().getBytes(Charsets.UTF_8));
        return urlConn;

    }

    /**
     * Get a user for given SCIM ID
     *
     * @param scimId
     * @return
     * @throws IOException
     */
    public static HttpURLConnection getUser(String scimId) throws IOException {

        return request(SCIMConstants.USER_ENDPOINT + "/" + scimId, HttpMethod.GET);
    }

    /**
     * Get a group for given SCIM ID
     *
     * @param scimId
     * @return
     * @throws IOException
     */
    public static HttpURLConnection getGroup(String scimId) throws IOException {

        return request(SCIMConstants.GROUP_ENDPOINT + "/" + scimId, HttpMethod.GET);
    }

    public static HttpURLConnection deleteUser(String scimId) throws IOException {

        return request(SCIMConstants.USER_ENDPOINT + "/" + scimId, HttpMethod.DELETE);

    }

    public static HttpURLConnection deleteGroup(String scimId) throws IOException {

        return request(SCIMConstants.GROUP_ENDPOINT + "/" + scimId, HttpMethod.DELETE);

    }

    public static HttpURLConnection request(String path, String method) throws IOException {
        return request(path, method, false);
    }

    private static HttpURLConnection request(String path, String method, boolean keepAlive) throws IOException {

        URL url = new URL(SCIMTestConstant.BASE_URL + path);

        HttpURLConnection httpURLConnection = null;

        if (SCIMTestConstant.BASE_URL.contains("https")) {
            httpURLConnection = (HttpsURLConnection) url.openConnection();
        } else {
            httpURLConnection = (HttpURLConnection) url.openConnection();
        }

        if (method.equals(HttpMethod.POST) || method.equals(HttpMethod.PUT)) {
            httpURLConnection.setDoOutput(true);
        }
        httpURLConnection.setRequestMethod(method);
        if (!keepAlive) {
            httpURLConnection.setRequestProperty("CONNECTION", "CLOSE");
        }

        String authorization = USER_NAME + ":" + PASSWORD;


        String temp = new String(Base64.getEncoder().encode(authorization.getBytes(Charset.forName("UTF-8"))),
                Charset.forName("UTF-8"));

        authorization = "Basic " + temp;
        httpURLConnection.setRequestProperty(HttpHeaders.AUTHORIZATION, authorization);
        httpURLConnection.setRequestProperty(HttpHeaders.CONTENT_TYPE, "application/scim+json");

        return httpURLConnection;

    }

    public static String getContent(HttpURLConnection urlConn) throws IOException {
        return new String(IOUtils.toByteArray(urlConn.getInputStream()), Charsets.UTF_8);
    }
}
