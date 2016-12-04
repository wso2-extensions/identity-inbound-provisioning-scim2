/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.inbound.provisioning.scim2.provider.resources;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Contact;
import io.swagger.annotations.Info;
import io.swagger.annotations.License;
import io.swagger.annotations.SwaggerDefinition;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.inbound.provisioning.scim2.provider.util.SCIMProviderConstants;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.exceptions.FormatNotSupportedException;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.protocol.SCIMResponse;
import org.wso2.charon.core.v2.protocol.endpoints.MeResourceManager;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
/*
@Component(
        name = "org.wso2.carbon.identity.inbound.provisioning.scim2.provider.resources.UserResource",
        service = Microservice.class,
        immediate = true
)

*/

/**
 * Endpoints of the MeResource in micro service. This will basically captures
 * the requests from the remote clients and hand over the request to respective operation performer.
 * clients can directly invoke operations through this endpoint without explicitly mentioning the resource id.
 *
 */

@Api(value = "scim/v2/Me")
@SwaggerDefinition(
        info = @Info(
                title = "/Me Endpoint Swagger Definition", version = "1.0",
                description = "SCIM 2.0 /Me endpoint",
                license = @License(name = "Apache 2.0", url = "http://www.apache.org/licenses/LICENSE-2.0"),
                contact = @Contact(
                        name = "WSO2 Identity Server Team",
                        email = "vindula@wso2.com",
                        url = "http://wso2.com"
                ))
)
@Path("/scim/v2/Me")
public class MeResource extends AbstractResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)

    @ApiOperation(
            value = "Return the authenticated user.",
            notes = "Returns HTTP 200 if the user is found.")

    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Valid user is found"),
            @ApiResponse(code = 404, message = "Valid user is not found")})

    public Response getUser(@ApiParam(value = SCIMProviderConstants.ACCEPT_HEADER_DESC, required = true)
                            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                            @ApiParam(value = SCIMProviderConstants.ATTRIBUTES_DESC, required = false)
                            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @ApiParam(value = SCIMProviderConstants.EXCLUDED_ATTRIBUTES_DESC, required = false)
                            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes)
            throws FormatNotSupportedException, CharonException {

        //Accept type validation checking.
        if (!isValidOutputFormat(outputFormat)) {
            String error = outputFormat + " is not supported.";
            throw new FormatNotSupportedException(error);
        }

        try {
            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM me endpoint and hand-over the request.
            MeResourceManager meResourceManager = new MeResourceManager();
            //TODO :Pass userID here
            SCIMResponse scimResponse = meResourceManager.get("", userManager, attribute, excludedAttributes);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return buildResponse(scimResponse);

        } catch (CharonException e) {
            throw new CharonException(e.getDetail(), e);
        }
    }


    @ApiOperation(
            value = "Return the user which was anonymously created",
            notes = "Returns HTTP 201 if the user is successfully created.")

    @POST
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
                               @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                               String resourceString) throws CharonException, FormatNotSupportedException {

        // content-type header is compulsory in post request.
        if (inputFormat == null) {
            String error = SCIMProviderConstants.CONTENT_TYPE
                    + " not present in the request header";
            throw new FormatNotSupportedException(error);
        }

        //Accept type validation checking.
        if (!isValidOutputFormat(outputFormat)) {
            String error = outputFormat + " is not supported.";
            throw new FormatNotSupportedException(error);
        }

        try {
            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM me endpoint and hand-over the request.
            MeResourceManager meResourceManager = new MeResourceManager();

            SCIMResponse response = meResourceManager.create(resourceString, userManager,
                    attribute, excludedAttributes);

            return buildResponse(response);

        } catch (CharonException e) {
            throw new CharonException(e.getDetail(), e);
        }

    }

    @DELETE
    @ApiOperation(
            value = "Delete the authenticated user.",
            notes = "Returns HTTP 204 if the user is successfully deleted.")

    @ApiResponses(value = {
            @ApiResponse(code = 204, message = "User is deleted"),
            @ApiResponse(code = 404, message = "Valid user is not found")})

    public Response deleteUser(@ApiParam(value = SCIMProviderConstants.ACCEPT_HEADER_DESC, required = true)
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format)
            throws FormatNotSupportedException, CharonException {

        // defaults to application/scim+json.
        if (format == null) {
            format = SCIMProviderConstants.APPLICATION_SCIM_JSON;
        }

        if (!isValidOutputFormat(format)) {
            String error = format + " is not supported.";
            throw new FormatNotSupportedException(error);
        }

        try {
            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM me endpoint and hand-over the request.
            MeResourceManager meResourceManager = new MeResourceManager();
            //TODO : pass the userId here
            SCIMResponse scimResponse = meResourceManager.delete("", userManager);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return buildResponse(scimResponse);

        } catch (CharonException e) {
            throw new CharonException(e.getDetail(), e);
        }
    }


    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Return the updated user",
            notes = "Returns HTTP 404 if the user is not found.")

    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "User is updated"),
            @ApiResponse(code = 404, message = "Valid user is not found")})

    public Response updateUser(@ApiParam(value = SCIMProviderConstants.CONTENT_TYPE_HEADER_DESC, required = true)
                               @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @ApiParam(value = SCIMProviderConstants.ACCEPT_HEADER_DESC, required = true)
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @ApiParam(value = SCIMProviderConstants.ATTRIBUTES_DESC, required = false)
                               @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @ApiParam(value = SCIMProviderConstants.EXCLUDED_ATTRIBUTES_DESC, required = false)
                               @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                               String resourceString) throws FormatNotSupportedException, CharonException {

        // content-type header is compulsory in post request.
        if (inputFormat == null) {
            String error = SCIMProviderConstants.CONTENT_TYPE
                    + " not present in the request header";
            throw new FormatNotSupportedException(error);
        }

        if (!isValidOutputFormat(outputFormat)) {
            String error = outputFormat + " is not supported.";
            throw new FormatNotSupportedException(error);
        }
        try {
            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM user endpoint and hand-over the request.
            MeResourceManager meResourceManager = new MeResourceManager();
            //TODO : Pass the userid here
            SCIMResponse response = meResourceManager.updateWithPUT(
                    "", resourceString, userManager, attribute, excludedAttributes);

            return buildResponse(response);

        } catch (CharonException e) {
            throw new CharonException(e.getDetail(), e);
        }
    }

}
