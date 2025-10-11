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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.authorization.common.AuthorizationUtil;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.encoder.JSONDecoder;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ForbiddenException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.exceptions.InternalErrorException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.RoleV2;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.getTenantDomainFromContext;
import static org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants.RoleV2Operations.UPDATE_ROLE_GROUPS;
import static org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants.RoleV2Operations.UPDATE_ROLE_MEMBERS;
import static org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants.RoleV2Operations.UPDATE_ROLE_PERMISSIONS;

/**
 * This class contains the common utils used at HTTP level
 */
public class SupportUtils {

    private static final Log log = LogFactory.getLog(SupportUtils.class);
    private static final String ASK_PASSWORD_CONFIRMATION_CODE_HEADER_NAME = "Ask-Password-Confirmation-Code";
    public static final String ASK_PASSWORD_KEY = "askPassword";
    private static final JSONDecoder DECODER = new JSONDecoder();

    private SupportUtils() {}

    /**
     * build the jaxrs response
     *
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
     * the REST API Authentication valve
     * @deprecated use {@link #getAuthenticatedUserId()} to use the authenticated user id instead of authenticated
     * user name.
     *
     * @return tenant and userstore domain appended
     */
    @Deprecated
    public static String getAuthenticatedUsername() {
        // Get authenticated username from the thread local.
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
    }

    /**
     * Get the user id of the user authenticated at the SCIM Endpoint. The user id will be set by
     * the REST API Authentication valve (configured in identity.xml)
     *
     * @return authenticated user id.
     */
    public static String getAuthenticatedUserId() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserId();
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

        try {
            if (userManager.getCustomUserSchemaExtension() != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Scim2 custom attribute schema is found in the UserManager for tenant with Id: " +
                            tenantId + ". Hence skip building the Extension Builder");
                }
                return;
            }

            SCIMCommonUtils.buildCustomSchema(tenantId);
        } catch (NotImplementedException | BadRequestException e) {
            throw new CharonException("Error while building scim custom schema", e);
        }
    }

    public static int getTenantId() {

        return IdentityTenantUtil.getTenantId(getTenantDomain());
    }

    public static String getTenantDomain() {

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            return getTenantDomainFromContext();
        }
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }

    /**
     * Check whether the resource include ask password.
     *
     * @param resourceString Resource body.
     * @return True if askPassword is true in resource string.
     */
    public static boolean isAskPasswordFlow(String resourceString) {

        try {
            JSONObject request = new JSONObject(resourceString);
            if (request.has(SCIMCommonConstants.SCIM_ENTERPRISE_USER_CLAIM_DIALECT) &&
                    request.getJSONObject(SCIMCommonConstants.SCIM_ENTERPRISE_USER_CLAIM_DIALECT)
                            .has(ASK_PASSWORD_KEY)) {
                return Boolean.parseBoolean(
                        request.getJSONObject(SCIMCommonConstants.SCIM_ENTERPRISE_USER_CLAIM_DIALECT)
                                .getString(ASK_PASSWORD_KEY));
            }

            String customSchemaURI = SCIMCommonUtils.getCustomSchemaURI();
            if (customSchemaURI != null && request.has(customSchemaURI) &&
                    request.getJSONObject(customSchemaURI).has(ASK_PASSWORD_KEY)) {
                return Boolean.parseBoolean(request.getJSONObject(customSchemaURI).getString(ASK_PASSWORD_KEY));
            }

        } catch (JSONException e) {
            return false;
        }

        return false;
    }

    /**
     * To get the ask password confirmation code from thread local.
     *
     * @return Confirmation code.
     */
    private static String getAskPasswordConfirmationCodeThreadLocal() {

        Object confirmationCode = IdentityUtil.threadLocalProperties.get()
                .get(IdentityRecoveryConstants.AP_CONFIRMATION_CODE_THREAD_LOCAL_PROPERTY);
        if (confirmationCode != null && !confirmationCode.toString()
                .equals(IdentityRecoveryConstants.AP_CONFIRMATION_CODE_THREAD_LOCAL_INITIAL_VALUE)) {
            return confirmationCode.toString();
        }
        return null;
    }

    /**
     * To build response after creating a user resource.
     *
     * @param scimResponse SCIM response.
     * @return Jaxrs response.
     */
    public static Response buildCreateUserResponse(SCIMResponse scimResponse) {

        if (!(scimResponse.getResponseStatus() == ResponseCodeConstants.CODE_CREATED) ||
                !IdentityUtil.threadLocalProperties.get()
                        .containsKey(IdentityRecoveryConstants.AP_CONFIRMATION_CODE_THREAD_LOCAL_PROPERTY)) {
            return buildResponse(scimResponse);
        }

        String confirmationCode = getAskPasswordConfirmationCodeThreadLocal();
        if (StringUtils.isNotEmpty(confirmationCode)) {
            scimResponse.getHeaderParamMap().put(ASK_PASSWORD_CONFIRMATION_CODE_HEADER_NAME, confirmationCode);
        }
        return buildResponse(scimResponse);
    }

    /**
     * This is used to set the flow and initiator in the identity context
     * for the admin or application initiated flows. This method cannot be
     * utilized for the user initiated flows.
     *
     * @param flowName The name of the flow to set in the identity context.
     */
    public static void enterFlow(Flow.Name flowName) {

        Flow.InitiatingPersona initiatingPersona = getFlowInitiatingPersona();
        if (initiatingPersona == null) {
            log.warn("Unable to resolve initiation persona. Hence, not entering the flow: " + flowName);
            return;
        }

        IdentityContext.getThreadLocalIdentityContext().enterFlow(new Flow.Builder()
                .name(flowName)
                .initiatingPersona(initiatingPersona)
                .build());
    }

    private static Flow.InitiatingPersona getFlowInitiatingPersona() {

        Flow existingFlow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        if (existingFlow != null) {
            return existingFlow.getInitiatingPersona();
        } else if (IdentityContext.getThreadLocalIdentityContext().isApplicationActor()) {
            return Flow.InitiatingPersona.APPLICATION;
        } else if (IdentityContext.getThreadLocalIdentityContext().isUserActor()) {
            return Flow.InitiatingPersona.ADMIN;
        }
        log.debug("Actor is not set in the identity context.");
        return null;
    }

    /**
     * This method formats the given scim payload for PUT requests.
     * It expects the input JSON to be an array of objects and the method wraps it in a map with a specified key.
     *
     * @param inputJson The input JSON string representing an array of objects.
     * @return A formatted JSON string suitable for PUT requests.
     * @throws FormatNotSupportedException If the input JSON is not a valid array or cannot be processed.
     */
    public static String formatJsonPayloadWithKey(String inputJson, String wrapperKey)
            throws FormatNotSupportedException {

        try {
            ObjectMapper mapper = new ObjectMapper();
            List<Map<String, String>> inputList = mapper.readValue(inputJson,
                    new TypeReference<List<Map<String, String>>>() {});
            Map<String, Object> outputMap = new HashMap<>();
            outputMap.put(wrapperKey, inputList);
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(outputMap);
        } catch (JsonProcessingException e) {
            throw new FormatNotSupportedException("Error while transforming groups payload for PUT request. " +
                    "Please ensure the input is a valid JSON array.");
        }
    }

    /**
     * Formalizes a SCIM PatchOp JSON request by ensuring all operations have a valid "path"
     * and wrap any object values in arrays, using the specified SCIM attribute name.
     *
     * @param inputJson     The raw SCIM PatchOp request body as a JSON string
     * @param scimAttribute The SCIM attribute name to use (e.g., "groups", "members")
     * @return A normalized JSON string with explicit paths and wrapped values
     * @throws FormatNotSupportedException FormatNotSupportedException
     */
    public static String formalizeScimPatchRequest(String inputJson, String scimAttribute)
            throws FormatNotSupportedException {

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(inputJson);
            ArrayNode operations = (ArrayNode) root.get(SCIMProviderConstants.OPERATIONS);

            for (JsonNode opNode : operations) {
                ObjectNode opObject = (ObjectNode) opNode;
                String op = opObject.get(SCIMProviderConstants.OP).asText();

                // Add default "path"
                if (!opObject.has(SCIMProviderConstants.PATH)) {
                    if (op.equalsIgnoreCase(SCIMProviderConstants.ADD) ||
                            op.equalsIgnoreCase(SCIMProviderConstants.REPLACE)) {
                        opObject.put(SCIMProviderConstants.PATH, scimAttribute);
                    }
                } else {
                    String path = opObject.get(SCIMProviderConstants.PATH).asText();
                    if (path.startsWith(SCIMProviderConstants.VALUE_EQ)) {
                        opObject.put(SCIMProviderConstants.PATH, scimAttribute + "[" + path + "]");
                    }
                }
            }
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (JsonProcessingException e ) {
            throw new FormatNotSupportedException("Error while processing SCIM PatchOp request. " +
                    "Please ensure the input is a valid JSON object with 'Operations' array.");
        }
    }

    /**
     * Validate the role v2 operation authorization for POST operation.
     *
     * @param roleV2EncodedString Role v2 encoded string.
     * @throws FormatNotSupportedException FormatNotSupportedException
     * @throws ForbiddenException ForbiddenException
     */
    public static void validateRoleV2AddAuthorization(String roleV2EncodedString)
            throws FormatNotSupportedException, ForbiddenException {

        if (isSkipEnforceRoleOperationPermissionEnabled()) {
            log.debug("Skipping enforcing role operation permission for add role operation.");
            return;
        }
        try {
            if (StringUtils.isBlank(roleV2EncodedString)) {
                return;
            }
            SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getRoleResourceV2Schema();
            RoleV2 roleV2 = DECODER.decodeResource(roleV2EncodedString, schema, new RoleV2());
            if (roleV2 == null) {
                return;
            }
            if (!roleV2.getPermissions().isEmpty()) {
                AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_PERMISSIONS);
            }
            if (!roleV2.getUsers().isEmpty()) {
                AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_MEMBERS);
            }
            if (!roleV2.getGroups().isEmpty()) {
                AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_GROUPS);
            }
        } catch (org.wso2.carbon.identity.authorization.common.exception.ForbiddenException e) {
            throw new ForbiddenException(e.getMessage());
        } catch (CharonException | BadRequestException | InternalErrorException e) {
            throw new FormatNotSupportedException("Error while decoding the role object from the encoded string.");
        }
    }

    /**
     * Validate the role v2 operation authorization for PATCH operation.
     *
     * @param patchOpEncodedString Patch operation encoded string.
     * @throws ForbiddenException ForbiddenException
     * @throws BadRequestException BadRequestException
     */
    public static void validateRoleV2PatchAuthorization(String patchOpEncodedString)
            throws ForbiddenException, BadRequestException {

        if (isSkipEnforceRoleOperationPermissionEnabled()) {
            log.debug("Skipping enforcing role operation permission for patch role operation.");
            return;
        }
        try {
            if (StringUtils.isBlank(patchOpEncodedString)) {
                return;
            }
            List<PatchOperation> patchOperations = DECODER.decodeRequest(patchOpEncodedString);
            if (patchOperations == null || patchOperations.isEmpty()) {
                return;
            }
            for (PatchOperation patchOp : patchOperations) {
                // Check if the operation is related to permissions, users, or groups, and validate operation scopes.
                if (patchOp.getAttributeName() != null) {
                    switch (patchOp.getAttributeName()) {
                        case SCIMConstants.RoleSchemaConstants.PERMISSIONS:
                            AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_PERMISSIONS);
                            break;
                        case SCIMConstants.RoleSchemaConstants.USERS:
                            AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_MEMBERS);
                            break;
                        case SCIMConstants.RoleSchemaConstants.GROUPS:
                            AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_GROUPS);
                            break;
                        default:
                            // No action needed for other attributes.
                            break;
                    }
                }
                if (patchOp.getPath() != null) {
                    if (patchOp.getPath().startsWith(SCIMConstants.RoleSchemaConstants.PERMISSIONS)) {
                        AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_PERMISSIONS);
                    }
                    if (patchOp.getPath().startsWith(SCIMConstants.RoleSchemaConstants.USERS)) {
                        AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_MEMBERS);
                    }
                    if (patchOp.getPath().startsWith(SCIMConstants.RoleSchemaConstants.GROUPS)) {
                        AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_GROUPS);
                    }
                }
                if (patchOp.getValues() != null && patchOp.getValues() instanceof JSONObject) {
                    JSONObject jsonObject = (JSONObject) patchOp.getValues();
                    if (jsonObject.has(SCIMConstants.RoleSchemaConstants.PERMISSIONS)) {
                        AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_PERMISSIONS);
                    }
                    if (jsonObject.has(SCIMConstants.RoleSchemaConstants.USERS)) {
                        AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_MEMBERS);
                    }
                    if (jsonObject.has(SCIMConstants.RoleSchemaConstants.GROUPS)) {
                        AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_GROUPS);
                    }
                }
            }
        } catch (org.wso2.carbon.identity.authorization.common.exception.ForbiddenException e) {
            throw new ForbiddenException(e.getMessage());
        }
    }

    /**
     * Validate the role v2 operation authorization for PUT operation.
     *
     * @param newRoleString New role string.
     * @throws ForbiddenException ForbiddenException
     * @throws BadRequestException BadRequestException
     */
    public static void validateRoleV2PutAuthorization(String newRoleString)
            throws ForbiddenException, BadRequestException {

        if (isSkipEnforceRoleOperationPermissionEnabled()) {
            log.debug("Skipping enforcing role operation permission for update role operation.");
            return;
        }
        try {
            if (StringUtils.isBlank(newRoleString)) {
                return;
            }
            SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getRoleResourceV2Schema();
            RoleV2 newRole = DECODER.decodeResource(newRoleString, schema, new RoleV2());
            if (newRole == null || newRole.getAttributeList() == null) {
                return;
            }
            if (newRole.getAttributeList().containsKey(SCIMConstants.RoleSchemaConstants.PERMISSIONS)) {
                AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_PERMISSIONS);
            }
            if (newRole.getAttributeList().containsKey(SCIMConstants.RoleSchemaConstants.USERS)) {
                AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_MEMBERS);
            }
            if (newRole.getAttributeList().containsKey(SCIMConstants.RoleSchemaConstants.GROUPS)) {
                AuthorizationUtil.validateOperationScopes(UPDATE_ROLE_GROUPS);
            }
        } catch (org.wso2.carbon.identity.authorization.common.exception.ForbiddenException e) {
            throw new ForbiddenException(e.getMessage());
        } catch (BadRequestException | CharonException | InternalErrorException e) {
            throw new BadRequestException("Error while decoding the role object from the encoded string.");
        }
    }

    private static boolean isSkipEnforceRoleOperationPermissionEnabled() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(
                SCIMProviderConstants.SKIP_ENFORCE_ROLE_OPERATION_PERMISSION));
    }
}
