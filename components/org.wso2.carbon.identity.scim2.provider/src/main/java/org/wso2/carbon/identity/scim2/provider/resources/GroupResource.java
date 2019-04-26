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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.jaxrs.designator.PATCH;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.charon3.core.encoder.JSONEncoder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.GroupResourceManager;
import org.wso2.charon3.core.schema.SCIMConstants;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

public class GroupResource extends AbstractResource {

    private static Log logger = LogFactory.getLog(GroupResource.class);

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
        String userName = requestAttributes.get(SCIMProviderConstants.AUTHORIZATION);
        String httpVerb = requestAttributes.get(SCIMProviderConstants.HTTP_VERB);
        String resourceString = requestAttributes.get(SCIMProviderConstants.RESOURCE_STRING);
        String attributes = requestAttributes.get(SCIMProviderConstants.ATTRIBUTES);
        String excludedAttributes = requestAttributes.get(SCIMProviderConstants.EXCLUDE_ATTRIBUTES);
        String search = requestAttributes.get(SCIMProviderConstants.SEARCH);
        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();
            // Obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // Obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Create charon-SCIM group endpoint and hand-over the request.
            GroupResourceManager groupResourceManager = new GroupResourceManager();
            SCIMResponse scimResponse = null;
            if (GET.class.getSimpleName().equals(httpVerb) && id == null) {
                String filter = requestAttributes.get(SCIMProviderConstants.FILTER);
                String sortBy = requestAttributes.get(SCIMProviderConstants.SORT_BY);
                String sortOrder = requestAttributes.get(SCIMProviderConstants.SORT_ORDER);
                String domainName = requestAttributes.get(SCIMProviderConstants.DOMAIN);

                // Processing count and startIndex in the request.
                Integer startIndex = convertStringPaginationParamsToInteger(
                        requestAttributes.get(SCIMProviderConstants.START_INDEX), SCIMProviderConstants.START_INDEX);
                Integer count = convertStringPaginationParamsToInteger(requestAttributes.get(SCIMProviderConstants.COUNT),
                        SCIMProviderConstants.COUNT);
                scimResponse = groupResourceManager
                        .listWithGET(userManager, filter, startIndex, count, sortBy, sortOrder, domainName, attributes,
                                excludedAttributes);
            } else if (GET.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.get(id, userManager, attributes, excludedAttributes);
            } else if (POST.class.getSimpleName().equals(httpVerb) && search.equals("1")) {
                scimResponse = groupResourceManager.listWithPOST(resourceString, userManager);
            } else if (POST.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.create(resourceString, userManager, attributes, excludedAttributes);
            } else if (PUT.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager
                        .updateWithPUT(id, resourceString, userManager, attributes, excludedAttributes);
            } else if (PATCH.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager
                        .updateWithPATCH(id, resourceString, userManager, attributes, excludedAttributes);
            } else if (DELETE.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.delete(id, userManager);
            }
            return SupportUtils.buildResponse(scimResponse);
        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        }
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
                return new Integer(valueInRequest);
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

}
