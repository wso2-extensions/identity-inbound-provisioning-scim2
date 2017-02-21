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
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;

/**
 * Utility functions for SCIM test cases
 */
public class SCIMTestUtil {

    private static Logger log = LoggerFactory.getLogger(SCIMTestUtil.class);
    private static final String USER_NAME = "username";
    private static final String PASSWORD = "password";

    private static Map<String, String> validAdminCredentials = new HashMap<String, String>() {
        {
            put("username", "admin");
            put("password", "admin");
        }
    };
    private static Map<String, String> invalidAdminCredentials = new HashMap<String, String>() {
        {
            put("username", "admin");
            put("password", "invalidPassword");
        }
    };
    private static String contentTypeHeader = "application/scim+json";

    /**
     * Create a user with sample attributes
     *
     * @param userName
     * @param familyName
     * @return
     * @throws IOException
     */
    public static HttpURLConnection createUser(String userName, String familyName, List<String> emails)
            throws IOException {

        JsonObject nameJsonObj = new JsonObject();
        if (StringUtils.isNotEmpty(familyName)) {
            nameJsonObj.addProperty(SCIMConstants.UserSchemaConstants.FAMILY_NAME, familyName);
        }

        JsonArray mailJsonArray = new JsonArray();
        if (emails != null && emails.size() != 0) {
            JsonObject workJsonObj = new JsonObject();
            workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.WORK);
            workJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, emails.get(0));
            mailJsonArray.add(workJsonObj);

            JsonObject homeJsonObj = new JsonObject();
            homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.TYPE, SCIMConstants.UserSchemaConstants.HOME);
            homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.VALUE, emails.get(1));
            homeJsonObj.addProperty(SCIMConstants.CommonSchemaConstants.PRIMARY, "true");
            mailJsonArray.add(homeJsonObj);
        }

        JsonObject userJsonObj = new JsonObject();
        userJsonObj.add(SCIMConstants.UserSchemaConstants.NAME, nameJsonObj);
        userJsonObj.add(SCIMConstants.UserSchemaConstants.EMAILS, mailJsonArray);
        userJsonObj.add(SCIMConstants.CommonSchemaConstants.SCHEMAS, new JsonArray());
        if (StringUtils.isNotEmpty(userName)) {
            userJsonObj.addProperty(SCIMConstants.UserSchemaConstants.USER_NAME, userName);
        }

        HttpURLConnection urlConn = validConnection(SCIMConstants.USER_ENDPOINT, HttpMethod.POST);
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

        HttpURLConnection urlConn = validConnection(SCIMConstants.GROUP_ENDPOINT, HttpMethod.POST);
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

        return validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId, HttpMethod.GET);
    }

    /**
     * Get a group for given SCIM ID
     *
     * @param scimId
     * @return
     * @throws IOException
     */
    public static HttpURLConnection getGroup(String scimId) throws IOException {

        return validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + scimId, HttpMethod.GET);
    }

    public static HttpURLConnection deleteUser(String scimId) throws IOException {

        return validConnection(SCIMConstants.USER_ENDPOINT + "/" + scimId, HttpMethod.DELETE);

    }

    public static HttpURLConnection deleteGroup(String scimId) throws IOException {

        return validConnection(SCIMConstants.GROUP_ENDPOINT + "/" + scimId, HttpMethod.DELETE);

    }

    public static HttpURLConnection validConnection(String path, String method) throws IOException {
        String authorizationHeader = validAdminCredentials.get(USER_NAME) + ":" + validAdminCredentials.get(PASSWORD);
        return connection(path, method, false, authorizationHeader, contentTypeHeader);
    }

    public static HttpURLConnection connectionWithInvalidAdminCredentials(String path, String method)
            throws IOException {
        String authorizationHeader = invalidAdminCredentials.get(USER_NAME) + ":" + validAdminCredentials.get(PASSWORD);
        return connection(path, method, false, authorizationHeader, contentTypeHeader);
    }

    public static HttpURLConnection connectionWithoutAuthorizationHeader(String path, String method)
            throws IOException {
        return connection(path, method, false, null, contentTypeHeader);
    }

    public static HttpURLConnection connectionWithoutContentTypeHeader(String path, String method)
            throws IOException {
        return connection(path, method, false, null, null);
    }

    private static HttpURLConnection connection(String path, String method, boolean keepAlive,
                                                String authorizationHeader, String contentTypeHeader)
            throws IOException {

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

        if (authorizationHeader != null) {
            String temp = new String(Base64.getEncoder().encode(authorizationHeader.getBytes(Charset.forName("UTF-8"))),
                    Charset.forName("UTF-8"));

            authorizationHeader = "Basic " + temp;
            httpURLConnection.setRequestProperty(HttpHeaders.AUTHORIZATION, authorizationHeader);
        }
        if (contentTypeHeader != null) {
            httpURLConnection.setRequestProperty(HttpHeaders.CONTENT_TYPE, contentTypeHeader);
        }

        return httpURLConnection;

    }

    public static String getContent(HttpURLConnection urlConn) throws IOException {
        return new String(IOUtils.toByteArray(urlConn.getInputStream()), Charsets.UTF_8);
    }
}
