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

package org.wso2.carbon.identity.scim2.provider.util;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.scim2.common.cache.SCIMCustomAttributeSchemaCache;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCustomSchemaProcessor;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.charon3.core.attributes.SCIMCustomAttribute;
import org.wso2.charon3.core.config.SCIMCustomSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.InternalErrorException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.schema.AttributeSchema;

import javax.ws.rs.core.Response;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.getCustomSchemaURI;

/**
 * This class contains the common utils used at HTTP level
 */
public class SupportUtils {

    private static final Log log = LogFactory.getLog(SupportUtils.class);

    private SupportUtils() {}

    /**
     * build the jaxrs response
     * @param scimResponse
     * @return
     */
    public static Response buildResponse(SCIMResponse scimResponse) {
        //create a response builder with the status code of the response to be returned.
        Response.ResponseBuilder responseBuilder = Response.status(scimResponse.getResponseStatus());
        //set the headers on the response
        Map<String, String> httpHeaders = scimResponse.getHeaderParamMap();
        if (MapUtils.isNotEmpty(httpHeaders)) {
            for (Map.Entry<String, String> entry : httpHeaders.entrySet()) {

                responseBuilder.header(entry.getKey(), entry.getValue());
            }
        }
        //set the payload of the response, if available.
        if (scimResponse.getResponseMessage() != null) {
            responseBuilder.entity(scimResponse.getResponseMessage());
        }
        return responseBuilder.build();
    }

    /**
     * decode the base64 encoded string
     * @param encodedString
     * @return
     */
    public static String getUserNameFromBase64EncodedString(String encodedString) {
        // decode it and extract username and password
        byte[] decodedAuthHeader = Base64.decode(encodedString.split(" ")[1]);
        String authHeader = new String(decodedAuthHeader, StandardCharsets.UTF_8);
        String userName = authHeader.split(":")[0];
        return userName;
    }

    /**
     * Get the fully qualified username of the user authenticated at the SCIM Endpoint. The username will be set by
     * the REST API Authentication valve (configured in identity.xml)
     *
     * @return tenant and userstore domain appended
     */
    public static String getAuthenticatedUsername() {
        // Get authenticated username from the thread local.
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
    }

    /**
     * This builds the custom schema for tenants.
     * @param userManager
     * @param tenantId
     * @throws CharonException
     */
    public static void buildCustomSchema(UserManager userManager, int tenantId) throws CharonException {

        if (log.isDebugEnabled()) {
            log.debug("Building scim2 custom attribute schema for tenant with Id: " + tenantId);
        }

        if (!SCIMCommonUtils.isCustomSchemaEnabled()) {
            return;
        }
        try {
            if (userManager.getCustomUserSchemaExtension() != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Scim2 custom attribute schema is found in the UserManager for tenant with Id: " +
                            tenantId + ". Hence skip building the Extension Builder");
                }
                return;
            }

            try {
                SCIMCustomSchemaProcessor scimCustomSchemaProcessor = new SCIMCustomSchemaProcessor();
                List<SCIMCustomAttribute> attributes =
                        scimCustomSchemaProcessor.getCustomAttributes(IdentityTenantUtil.getTenantDomain(tenantId),
                                getCustomSchemaURI());
                AttributeSchema attributeSchema = SCIMCustomSchemaExtensionBuilder.getInstance()
                        .buildUserCustomSchemaExtension(attributes);
                SCIMCustomAttributeSchemaCache.getInstance().addSCIMCustomAttributeSchema(tenantId, attributeSchema);
            } catch (InternalErrorException e) {
                throw new CharonException("Error while building scim custom schema", e);
            }
        } catch (NotImplementedException | BadRequestException | IdentitySCIMException e) {
            throw new CharonException("Error while building scim custom schema", e);
        }
    }

    public static int getTenantId() {

        return IdentityTenantUtil.getTenantId(getTenantDomain());
    }

    public static String getTenantDomain() {

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            return IdentityTenantUtil.getTenantDomainFromContext();
        }
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }
}
