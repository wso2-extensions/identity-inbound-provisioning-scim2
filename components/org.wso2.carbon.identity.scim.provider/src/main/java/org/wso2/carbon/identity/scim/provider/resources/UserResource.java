/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.scim.provider.resources;

import io.swagger.annotations.*;

import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.scim.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim.provider.util.SupportUtils;
import org.wso2.charon.core.v2.encoder.JSONEncoder;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.exceptions.FormatNotSupportedException;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.protocol.SCIMResponse;
import org.wso2.charon.core.v2.protocol.endpoints.UserResourceManager;


import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


@Api(value = "scim/v2/Users")
@SwaggerDefinition(
        info = @Info(
                title = "/Users Endpoint Swagger Definition", version = "1.0",
                description = "SCIM 2.0 /Users endpoint",
                license = @License(name = "Apache 2.0", url = "http://www.apache.org/licenses/LICENSE-2.0"),
                contact = @Contact(
                        name = "WSO2 Identity Server Team",
                        email = "vindula@wso2.com",
                        url =  "http://wso2.com"
                ))
)
@Path("/scim/v2/Users")
public class UserResource extends AbstractResource {

    @GET
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)

    @ApiOperation(
            value = "Return the user with the given id",
            notes = "Returns HTTP 204 if the user is not found.")

    @ApiResponses(value = {
            @ApiResponse(code = 204, message = "Valid user is found"),
            @ApiResponse(code = 404, message = "Valid user is not found")})

    public Response getUser(@ApiParam(value = SCIMProviderConstants.ID_DESC, required = true)
                            @PathParam(SCIMProviderConstants.ID) String id,
                            @ApiParam(value = SCIMProviderConstants.ACCEPT_HEADER_DESC, required = true)
                            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                            @ApiParam(value = SCIMProviderConstants.ATTRIBUTES_DESC, required = false)
                            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @ApiParam(value = SCIMProviderConstants.EXCLUDED_ATTRIBUTES_DESC, required = false)
                            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String  excludedAttributes) {

        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            if(!isValidOutputFormat(outputFormat)){
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse = userResourceManager.get(id, userManager,attribute, excludedAttributes);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return new SupportUtils().buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e,encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }


    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiResponses(value = {
            @ApiResponse(code = 201, message = "Valid user is created"),
            @ApiResponse(code = 404, message = "User is not found")})

    public Response createUser(@ApiParam(value = SCIMProviderConstants.CONTENT_TYPE_HEADER_DESC, required = true)
                               @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @ApiParam(value = SCIMProviderConstants.ACCEPT_HEADER_DESC, required = true)
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @ApiParam(value = SCIMProviderConstants.ATTRIBUTES_DESC, required = false)
                               @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @ApiParam(value = SCIMProviderConstants.EXCLUDED_ATTRIBUTES_DESC, required = false)
                               @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String  excludedAttributes,
                               String resourceString) {


        JSONEncoder encoder = null;
        try {
            // obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if(!isValidInputFormat(inputFormat)){
                String error = inputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            if(!isValidOutputFormat(outputFormat)){
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse response = userResourceManager.create(resourceString, userManager,
                    attribute, excludedAttributes);

            return new SupportUtils().buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @DELETE
    @Path("/{id}")
    @ApiOperation(
            value = "Delete the user with the given id",
            notes = "Returns HTTP 204 if the user is successfully deleted.")

    @ApiResponses(value = {
            @ApiResponse(code = 204, message = "User is deleted"),
            @ApiResponse(code = 404, message = "Valid user is not found")})

    public Response deleteUser(@ApiParam(value = SCIMProviderConstants.ID_DESC, required = true)
                               @PathParam(SCIMProviderConstants.ID) String id,
                               @ApiParam(value = SCIMProviderConstants.ACCEPT_HEADER_DESC, required = true)
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format) {
        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // defaults to application/scim+json.
            if (format == null) {
                format = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if(!isValidOutputFormat(format)){
                String error = format + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM user resource manager and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse = userResourceManager.delete(id, userManager);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return new SupportUtils().buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Return users according to the filter, sort and pagination parameters",
            notes = "Returns HTTP 404 if the users are not found.")

    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Valid users are found"),
            @ApiResponse(code = 404, message = "Valid users are not found")})

    public Response getUser(@ApiParam(value = SCIMProviderConstants.ACCEPT_HEADER_DESC, required = true)
                            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format,
                            @ApiParam(value = SCIMProviderConstants.ATTRIBUTES_DESC, required = false)
                            @QueryParam (SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @ApiParam(value = SCIMProviderConstants.EXCLUDED_ATTRIBUTES_DESC, required = false)
                            @QueryParam (SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                            @ApiParam(value = SCIMProviderConstants.FILTER_DESC, required = false)
                            @QueryParam (SCIMProviderConstants.FILTER) String filter,
                            @ApiParam(value = SCIMProviderConstants.START_INDEX_DESC, required = false)
                            @QueryParam (SCIMProviderConstants.START_INDEX) int startIndex,
                            @ApiParam(value = SCIMProviderConstants.COUNT_DESC, required = false)
                            @QueryParam (SCIMProviderConstants.COUNT) int count,
                            @ApiParam(value = SCIMProviderConstants.SORT_BY_DESC, required = false)
                            @QueryParam (SCIMProviderConstants.SORT_BY) String sortBy,
                            @ApiParam(value = SCIMProviderConstants.SORT_ORDER_DESC, required = false)
                            @QueryParam (SCIMProviderConstants.SORT_ORDER) String sortOrder) {
        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // defaults to application/scim+json.
            if (format == null) {
                format = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if(!isValidOutputFormat(format)){
                String error = format + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM user resource manager and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse = null;

            scimResponse = userResourceManager.listWithGET(userManager, filter, startIndex, count,
                    sortBy, sortOrder, attribute, excludedAttributes);

            return new SupportUtils().buildResponse(scimResponse);
        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    @Path("/.search")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Return users according to the filter, sort and pagination parameters",
            notes = "Returns HTTP 404 if the users are not found.")

    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Valid users are found"),
            @ApiResponse(code = 404, message = "Valid users are not found")})

    public Response getUsersByPost(@ApiParam(value = SCIMProviderConstants.CONTENT_TYPE_HEADER_DESC, required = true)
                                   @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                   @ApiParam(value = SCIMProviderConstants.ACCEPT_HEADER_DESC, required = true)
                                   @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                   String resourceString) {
        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if(!isValidInputFormat(inputFormat)){
                String error = inputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            if(!isValidOutputFormat(outputFormat)){
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM user resource manager and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse = null;

            scimResponse = userResourceManager.listWithPOST(resourceString, userManager);

            return new SupportUtils().buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PUT
    @Path("{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Return the updated user",
            notes = "Returns HTTP 404 if the user is not found.")

    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "User is updated"),
            @ApiResponse(code = 404, message = "Valid user is not found")})

    public Response updateUser(@ApiParam(value = SCIMProviderConstants.ID_DESC, required = true)
                               @PathParam(SCIMProviderConstants.ID) String id,
                               @ApiParam(value = SCIMProviderConstants.CONTENT_TYPE_HEADER_DESC, required = true)
                               @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @ApiParam(value = SCIMProviderConstants.ACCEPT_HEADER_DESC, required = true)
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @ApiParam(value = SCIMProviderConstants.ATTRIBUTES_DESC, required = false)
                               @QueryParam (SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @ApiParam(value = SCIMProviderConstants.EXCLUDED_ATTRIBUTES_DESC, required = false)
                               @QueryParam (SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                               String resourceString) {
        JSONEncoder encoder = null;
        try {
            // obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if(!isValidInputFormat(inputFormat)){
                String error = inputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            if(!isValidOutputFormat(outputFormat)){
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceEndpoint = new UserResourceManager();

            SCIMResponse response = userResourceEndpoint.updateWithPUT(
                    id, resourceString, userManager, attribute, excludedAttributes);

            return new SupportUtils().buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

}