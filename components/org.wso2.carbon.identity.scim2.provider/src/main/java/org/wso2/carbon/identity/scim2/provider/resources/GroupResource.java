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
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                             @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                             @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                             @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes) {

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
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, GET.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, attribute);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @POST
    @Path("/.search")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGroupsByPOST(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                    @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                    String resourceString) {

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
            requestAttributes.put(SCIMProviderConstants.HTTP_VERB, POST.class.getSimpleName());
            requestAttributes.put(SCIMProviderConstants.RESOURCE_STRING, resourceString );
            requestAttributes.put(SCIMProviderConstants.SEARCH, "1");

            return processRequest(requestAttributes);

        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    public Response createGroup(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                                @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                                String resourceString) {


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
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, POST.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.RESOURCE_STRING, resourceString);
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, attribute);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @GET
    public Response getGroup(@HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                             @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                             @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                             @QueryParam(SCIMProviderConstants.FILTER) String filter,
                             @QueryParam(SCIMProviderConstants.START_INDEX) String startIndex,
                             @QueryParam(SCIMProviderConstants.COUNT) String count,
                             @QueryParam(SCIMProviderConstants.SORT_BY) String sortBy,
                             @QueryParam(SCIMProviderConstants.SORT_ORDER) String sortOrder) {

        try {
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }

        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, GET.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.ATTRIBUTES, attribute);
        requestAttributes.put(SCIMProviderConstants.EXCLUDE_ATTRIBUTES, excludedAttributes);
        requestAttributes.put(SCIMProviderConstants.FILTER, filter);
        requestAttributes.put(SCIMProviderConstants.START_INDEX, startIndex);
        requestAttributes.put(SCIMProviderConstants.COUNT, count);
        requestAttributes.put(SCIMProviderConstants.SORT_BY, sortBy);
        requestAttributes.put(SCIMProviderConstants.SORT_ORDER, sortOrder);
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @DELETE
    @Path("{id}")
    public Response deleteGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                                @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat) {

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
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, DELETE.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.SEARCH, "0");
        return processRequest(requestAttributes);
    }

    @PUT
    @Path("{id}")
    public Response updateGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                                @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
                                @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                                @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                                String resourceString) {


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
                               @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                               String resourceString) {

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
        try {

            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();
            //obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            //create charon-SCIM group endpoint and hand-over the request.
            GroupResourceManager groupResourceManager = new GroupResourceManager();
            SCIMResponse scimResponse = null;
            int startIndex = 0;
            int count = 0;
            if (GET.class.getSimpleName().equals(httpVerb) && id == null) {
                String filter = requestAttributes.get(SCIMProviderConstants.FILTER);
                if(requestAttributes.get(SCIMProviderConstants.START_INDEX) != null){
                    startIndex = Integer.parseInt(requestAttributes.get(SCIMProviderConstants.START_INDEX));
                }
                if(requestAttributes.get(SCIMProviderConstants.COUNT) != null){
                    count = Integer.parseInt(requestAttributes.get(SCIMProviderConstants.COUNT));
                }

                String sortBy = requestAttributes.get(SCIMProviderConstants.SORT_BY);
                String sortOrder = requestAttributes.get(SCIMProviderConstants.SORT_ORDER);

                scimResponse = groupResourceManager.listWithGET(userManager, filter, startIndex,
                        count, sortBy, sortOrder, attributes, excludedAttributes);

            } else if (GET.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.get(id, userManager, attributes, excludedAttributes);
            } else if (POST.class.getSimpleName().equals(httpVerb) && search.equals("1")){
                scimResponse = groupResourceManager.listWithPOST(resourceString,userManager);
            } else if (POST.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.create(resourceString, userManager, attributes, excludedAttributes);
            } else if (PUT.class.getSimpleName().equals(httpVerb)) {
                scimResponse =
                        groupResourceManager.updateWithPUT(id, resourceString, userManager, attributes, excludedAttributes);
            } else if (PATCH.class.getSimpleName().equals(httpVerb)) {
                scimResponse =
                        groupResourceManager.updateWithPATCH(id, resourceString, userManager, attributes, excludedAttributes);
            } else if (DELETE.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.delete(id, userManager);
            }

            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        }
    }

}
