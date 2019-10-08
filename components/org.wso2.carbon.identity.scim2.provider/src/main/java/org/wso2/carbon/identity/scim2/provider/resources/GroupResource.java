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

package org.wso2.carbon.identity.scim2.provider.resources;

import com.google.gson.Gson;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.jaxrs.designator.PATCH;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.common.impl.SCIMUserManager;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.mgt.RolePermissionException;
import org.wso2.charon3.core.encoder.JSONDecoder;
import org.wso2.charon3.core.encoder.JSONEncoder;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.GroupResourceManager;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class GroupResource extends AbstractResource {

    private static final Log logger = LogFactory.getLog(GroupResource.class);
    private static final String PERMISSIONS = "Permissions";

    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                             @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                             @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                             @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                             @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes) {

        String userName = SupportUtils.getAuthenticatedUsername();
        try {
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }

        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.ID, id);
        requestAttributes.put(SCIMProviderConstants.ACCEPT_HEADER, outputFormat);
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, GET.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, attribute);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @GET
    @Path("{id}/permissions")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getPermissionListOfGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                                             @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                                             @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                             @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat) {

        String userName = SupportUtils.getAuthenticatedUsername();
        if (!isValidOutputFormat(outputFormat)) {
            return handleFormatNotSupportedException(new FormatNotSupportedException("Output format: " + outputFormat + " is not supported."));
        }

        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.ID, id);
        requestAttributes.put(SCIMProviderConstants.ACCEPT_HEADER, outputFormat);
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, GET.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, PERMISSIONS);
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @PUT
    @Path("{id}/permissions")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response setPermissionForGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                                          @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                                          @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                          @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                          @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                                          @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                                          String resourceString) {

        String userName = SupportUtils.getAuthenticatedUsername();
        // content-type header is compulsory in post request.
        if (inputFormat == null) {
            return handleFormatNotSupportedException(new FormatNotSupportedException("Content type: " + SCIMProviderConstants.CONTENT_TYPE +
                    "  not present in the request header"));
        }

        if (!isValidInputFormat(inputFormat)) {
            return handleFormatNotSupportedException(new FormatNotSupportedException("Input format: " + inputFormat + " is not supported."));
        }

        if (!isValidOutputFormat(outputFormat)) {
            return handleFormatNotSupportedException(new FormatNotSupportedException("Output format: " + outputFormat + " is not supported."));
        }

        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.ID, id);
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, PUT.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.RESOURCE_STRING, resourceString);
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, PERMISSIONS);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        return processRequest(requestAttributes);

    }

    @PATCH
    @Path("{id}/permissions")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response patchPermissionForGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                                            @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                                            @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                                            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                                            String resourceString) {

        String userName = SupportUtils.getAuthenticatedUsername();
        // content-type header is compulsory in post request.
        if (inputFormat == null) {
            return handleFormatNotSupportedException(new FormatNotSupportedException("Content type: " + SCIMProviderConstants.CONTENT_TYPE +
                    "  not present in the request header"));
        }

        if (!isValidInputFormat(inputFormat)) {
            return handleFormatNotSupportedException(new FormatNotSupportedException("Input format: " + inputFormat + " is not supported."));
        }

        if (!isValidOutputFormat(outputFormat)) {
            return handleFormatNotSupportedException(new FormatNotSupportedException("Output format: " + outputFormat + " is not supported."));
        }

        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.ID, id);
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, PATCH.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.RESOURCE_STRING, resourceString);
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, PERMISSIONS);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        return processRequest(requestAttributes);

    }

    @POST
    @Path("/.search")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getGroupsByPOST(@HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                                    @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                    @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                    String resourceString) {

        String userName = SupportUtils.getAuthenticatedUsername();
        try {
            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if (!isValidInputFormat(inputFormat)) {
                String error = inputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }

            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }

            Map<String, String> requestAttributes = new HashMap<>();
            requestAttributes.put(SCIMProviderConstants.ACCEPT_HEADER, outputFormat);
            requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
            requestAttributes.put(SCIMProviderConstants.HTTP_VERB, POST.class.getSimpleName());
            requestAttributes.put(SCIMProviderConstants.RESOURCE_STRING, resourceString );
            requestAttributes.put(SCIMProviderConstants.SEARCH, "1");

            return processRequest(requestAttributes);

        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    public Response createGroup(@HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                                @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                                @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                                String resourceString) {

        String userName = SupportUtils.getAuthenticatedUsername();
        try {
            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if (!isValidInputFormat(inputFormat)) {
                String error = inputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }

            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }

        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, POST.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.RESOURCE_STRING, resourceString);
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, attribute);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @GET
    public Response getGroup(@HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                             @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                             @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                             @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                             @QueryParam(SCIMProviderConstants.FILTER) String filter,
                             @QueryParam(SCIMProviderConstants.START_INDEX) String startIndex,
                             @QueryParam(SCIMProviderConstants.COUNT) String count,
                             @QueryParam(SCIMProviderConstants.SORT_BY) String sortBy,
                             @QueryParam(SCIMProviderConstants.SORT_ORDER) String sortOrder,
                             @QueryParam(SCIMProviderConstants.DOMAIN) String domainName) {

        String userName = SupportUtils.getAuthenticatedUsername();
        try {
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }

        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, GET.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, attribute);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        requestAttributes.put(SCIMProviderConstants.FILTER, filter);
        requestAttributes.put(SCIMProviderConstants.START_INDEX, startIndex);
        requestAttributes.put(SCIMProviderConstants.COUNT, count);
        requestAttributes.put(SCIMProviderConstants.SORT_BY, sortBy);
        requestAttributes.put(SCIMProviderConstants.SORT_ORDER, sortOrder);
        requestAttributes.put(SCIMProviderConstants.DOMAIN, domainName);
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @DELETE
    @Path("{id}")
    public Response deleteGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                                @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                                @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat) {

        String userName = SupportUtils.getAuthenticatedUsername();
        try {
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }

        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.ID, id);
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, DELETE.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @PUT
    @Path("{id}")
    public Response updateGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                                @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                                @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
                                @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                                @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                                String resourceString) {

        String userName = SupportUtils.getAuthenticatedUsername();
        try {
            // content-type header is compulsory in put request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if (!isValidInputFormat(inputFormat)) {
                String error = inputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }

            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }


        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.ID, id);
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, PUT.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.RESOURCE_STRING, resourceString);
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, attribute);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @PATCH
    @Path("{id}")
    public Response patchGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                               @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                               @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                               String resourceString) {

        String userName = SupportUtils.getAuthenticatedUsername();
        try {
            // content-type header is compulsory in patch request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if (!isValidInputFormat(inputFormat)) {
                String error = inputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }

            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }


        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.ID, id);
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, userName);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, PATCH.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.RESOURCE_STRING, resourceString);
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, attribute);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    private Response processRequest(final Map<String, String> requestAttributes) {

        String id = requestAttributes.get(SCIMProviderConstants.ID);
        String httpVerb = requestAttributes.get(SCIMProviderConstants.HTTP_VERB);
        String resourceString = requestAttributes.get(SCIMProviderConstants.RESOURCE_STRING);
        String attributes = requestAttributes.get(SCIMProviderConstants.ATTRIBUTES);
        String excludedAttributes = requestAttributes.get(SCIMProviderConstants.EXCLUDE_ATTRIBUTES);
        String search = requestAttributes.get(SCIMProviderConstants.SEARCH);
        JSONEncoder encoder = null;
        JSONArray outputPermissions;
        Gson gson = new Gson();
        HashMap<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("Content-Type", SCIMProviderConstants.APPLICATION_SCIM_JSON);
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();
            // Obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // Obtain the user store manager
            SCIMUserManager userManager = (SCIMUserManager) IdentitySCIMManager.getInstance().getUserManager();

            // Create charon-SCIM group endpoint and hand-over the request.
            GroupResourceManager groupResourceManager = new GroupResourceManager();
            SCIMResponse scimResponse = null;
            String groupName;
            if (GET.class.getSimpleName().equals(httpVerb) && id == null) {
                String filter = requestAttributes.get(SCIMProviderConstants.FILTER);
                String sortBy = requestAttributes.get(SCIMProviderConstants.SORT_BY);
                String sortOrder = requestAttributes.get(SCIMProviderConstants.SORT_ORDER);
                String domainName = requestAttributes.get(SCIMProviderConstants.DOMAIN);

                // Processing count and startIndex in the request.
                Integer startIndex = convertStringPaginationParamsToInteger(
                        requestAttributes.get(SCIMProviderConstants.START_INDEX), SCIMProviderConstants.START_INDEX);
                Integer count = convertStringPaginationParamsToInteger(requestAttributes.get(SCIMProviderConstants
                        .COUNT), SCIMProviderConstants.COUNT);
                scimResponse = groupResourceManager
                        .listWithGET(userManager, filter, startIndex, count, sortBy, sortOrder, domainName, attributes,
                                excludedAttributes);
            } else if (GET.class.getSimpleName().equals(httpVerb) && isGroupPermissionsRequest(requestAttributes)) {
                try {
                    groupName = getGroupName(id, userManager, groupResourceManager, excludedAttributes);

                    outputPermissions = new JSONArray(Arrays.asList(userManager.getGroupPermissions(groupName)));
                    scimResponse = new SCIMResponse(ResponseCodeConstants.CODE_OK, outputPermissions
                            .toString(), responseHeaders);
                } catch (JSONException e) {
                    return SupportUtils.buildResponse(groupResourceManager.get(id, userManager, attributes,
                            excludedAttributes));
                }
            } else if (GET.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.get(id, userManager, attributes, excludedAttributes);
            } else if (POST.class.getSimpleName().equals(httpVerb) && search.equals("1")) {
                scimResponse = groupResourceManager.listWithPOST(resourceString, userManager);
            } else if (POST.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.create(resourceString, userManager, attributes, excludedAttributes);
            } else if (PUT.class.getSimpleName().equals(httpVerb) && isGroupPermissionsRequest(requestAttributes)) {
                try {
                    groupName = getGroupName(id, userManager, groupResourceManager, excludedAttributes);
                    String[] permissions = gson.fromJson(resourceString, String[].class);
                    // Replace the existing permission paths with given array.
                    userManager.setGroupPermissions(groupName, permissions);

                    outputPermissions = new JSONArray(Arrays.asList(userManager.getGroupPermissions(groupName)));
                    scimResponse = new SCIMResponse(ResponseCodeConstants.CODE_OK, outputPermissions
                            .toString(), responseHeaders);
                } catch (JSONException e) {
                    return SupportUtils.buildResponse(groupResourceManager.get(id, userManager, attributes,
                            excludedAttributes));
                }

            } else if (PUT.class.getSimpleName().equals(httpVerb)) {

                scimResponse = groupResourceManager
                        .updateWithPUT(id, resourceString, userManager, attributes, excludedAttributes);
            } else if (PATCH.class.getSimpleName().equals(httpVerb) && isGroupPermissionsRequest(requestAttributes)) {
                try {
                    groupName = getGroupName(id, userManager, groupResourceManager, excludedAttributes);

                    // Decode the resource string and get the permissions to add or remove.
                    HashMap<String, String[]> permissionMap = decodePatchOperation(resourceString);
                    userManager.updatePermissionListOfGroup(groupName, permissionMap.get(SCIMProviderConstants.ADD),
                            permissionMap.get(SCIMProviderConstants.REMOVE));
                    outputPermissions = new JSONArray(Arrays.asList(userManager.getGroupPermissions(groupName)));
                    scimResponse = new SCIMResponse(ResponseCodeConstants.CODE_OK, outputPermissions
                            .toString(), responseHeaders);
                } catch (JSONException e) {
                    return SupportUtils.buildResponse(groupResourceManager.get(id, userManager, attributes,
                            excludedAttributes));
                }
            } else if (PATCH.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager
                        .updateWithPATCH(id, resourceString, userManager, attributes, excludedAttributes);
            } else if (DELETE.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.delete(id, userManager);
            }
            return SupportUtils.buildResponse(Objects.requireNonNull(scimResponse));
        } catch (BadRequestException e) {
            logger.error("The Patch request is invalid. Unable to decode." + e);
            return SupportUtils.buildResponse(new SCIMResponse(ResponseCodeConstants.CODE_BAD_REQUEST,
                    "The Patch request is invalid.", responseHeaders));
        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (UserStoreException | RolePermissionException e) {
            return handleCharonException(new CharonException("Error occurred when getting the permissions from server",
                    e), encoder);
        }
    }

    /**
     * Get group display name from the groupId.
     *
     * @param groupId SCIM group id.
     * @return Display name of the group.
     * @throws JSONException thrown when an error occurred when getting displayName from JSON response.
     */
    private String getGroupName(String groupId, SCIMUserManager userManager, GroupResourceManager groupResourceManager,
                                String excludeAttributes) throws JSONException {

        String includeAttributes = SCIMConstants.GroupSchemaConstants.DISPLAY_NAME;
        SCIMResponse scimResponse = groupResourceManager.get(groupId, userManager, includeAttributes, excludeAttributes);
        JSONObject responseMessage = new JSONObject(scimResponse.getResponseMessage());
        return (String) (responseMessage).get(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME);
    }

    /**
     * Decode patch operation resource string and get the permissions.
     *
     * @param jsonResourceString string that should decode.
     * @return Map of permissions to add and remove.
     * @throws BadRequestException
     */
    private HashMap<String, String[]> decodePatchOperation(String jsonResourceString) throws BadRequestException {

        JSONDecoder decode = new JSONDecoder();
        ArrayList<PatchOperation> listOperations;
        List<String> permissionsToAdd;
        List<String> permissionsToRemove;
        HashMap<String, String[]> permissionMap = new HashMap<>();

        // Decode the JSON string and get the permissions based on operations.
        listOperations = decode.decodeRequest(jsonResourceString);
        if (!listOperations.isEmpty()) {
            for (PatchOperation op : listOperations) {
                if ((SCIMProviderConstants.ADD).equals(op.getOperation())) {
                    JSONArray permissions = new JSONArray(op.getValues().toString());
                    permissionsToAdd = IntStream.range(0, permissions.length()).mapToObj(permissions::getString)
                            .collect(Collectors.toList());
                    if (permissionsToAdd.isEmpty()) {
                        permissionMap.put(SCIMProviderConstants.ADD, null);
                    } else {
                        permissionMap.put(SCIMProviderConstants.ADD, permissionsToAdd.toArray(new String[0]));
                    }
                } else if (SCIMProviderConstants.REMOVE.equals(op.getOperation())) {
                    JSONArray permissions = new JSONArray(op.getValues().toString());
                    permissionsToRemove = IntStream.range(0, permissions.length()).mapToObj(permissions::getString)
                            .collect(Collectors.toList());
                    if (permissionsToRemove.isEmpty()) {
                        permissionMap.put(SCIMProviderConstants.REMOVE, null);
                    } else {
                        permissionMap.put(SCIMProviderConstants.REMOVE, permissionsToRemove.toArray(new String[0]));
                    }
                }
            }
        }
        return permissionMap;
    }

    /**
     * Method to convert string pagination values to Interger pagination values.
     *
     * @param valueInRequest       Value passed in the request.
     * @param scimProviderConstant The name of parameter.
     * @return Integer if the param is populated and returns null if the param is omitted from the request.
     * @throws CharonException If the passed param value is not an integer.
     */
    private Integer convertStringPaginationParamsToInteger(String valueInRequest, String scimProviderConstant)
            throws CharonException {

        try {
            if (StringUtils.isNotEmpty(valueInRequest)) {
                return Integer.valueOf(valueInRequest);
            } else {
                return null;
            }
        } catch (NumberFormatException e) {
            String errorMessage = String
                    .format("Invalid integer value: %s for %s parameter in the request.", valueInRequest,
                            scimProviderConstant);
            throw new CharonException(errorMessage, e);
        }
    }

    /**
     * Check whether the Group request is a permissions related request.
     *
     * @param requestAttributes requested attributes of the request.
     * @return true or false.
     */
    private boolean isGroupPermissionsRequest(Map<String, String> requestAttributes) {

        return PERMISSIONS.equals(requestAttributes.get(SCIMProviderConstants.ATTRIBUTES));
    }
}
