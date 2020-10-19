/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.charon3.core.extensions.RoleManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.RoleResourceManager;
import org.wso2.charon3.core.protocol.endpoints.UserResourceManager;
import org.wso2.charon3.core.schema.SCIMConstants;

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

@Path("/")
public class RoleResource extends AbstractResource {

    private static final Log logger = LogFactory.getLog(RoleResource.class);

    @GET
    @Path("{id}")
    @Produces({ MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON })
    public Response getRole(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes) {

        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
            // Obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // Obtain the role manager.
            RoleManager roleManager = IdentitySCIMManager.getInstance().getRoleManager();

            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceManager roleResourceManager = new RoleResourceManager();

            SCIMResponse scimResponse = roleResourceManager.getRole(id, roleManager, attribute, excludedAttributes);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    @Path("/.search")
    @Produces({ MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON })
    public Response getRolesByPOST(@HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
            @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat, String resourceString) {

        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE + " not present in the request header";
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
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // Obtain the role manager.
            RoleManager roleManager = IdentitySCIMManager.getInstance().getRoleManager();

            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceManager roleResourceManager = new RoleResourceManager();

            SCIMResponse scimResponse = roleResourceManager.listWithPOSTRole(resourceString, roleManager);

            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    public Response createRole(@HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
            @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat, String resourceString) {

        JSONEncoder encoder = null;
        try {
            // Obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE + " not present in the request header";
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
            // Obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // Obtain the role manager.
            RoleManager roleManager = IdentitySCIMManager.getInstance().getRoleManager();

            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceManager roleResourceManager = new RoleResourceManager();

            SCIMResponse response = roleResourceManager.createRole(resourceString, roleManager);

            return SupportUtils.buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @GET
    public Response getRoles(@HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
            @QueryParam(SCIMProviderConstants.FILTER) String filter,
            @QueryParam(SCIMProviderConstants.START_INDEX) Integer startIndex,
            @QueryParam(SCIMProviderConstants.COUNT) Integer count,
            @QueryParam(SCIMProviderConstants.SORT_BY) String sortBy,
            @QueryParam(SCIMProviderConstants.SORT_ORDER) String sortOrder) {

        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // Defaults to application/scim+json.
            if (outputFormat == null) {
                outputFormat = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // Obtain the role manager.
            RoleManager roleManager = IdentitySCIMManager.getInstance().getRoleManager();

            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceManager roleResourceManager = new RoleResourceManager();

            SCIMResponse scimResponse = roleResourceManager
                    .listWithGETRole(roleManager, filter, startIndex, count, sortBy, sortOrder);

            return SupportUtils.buildResponse(scimResponse);
        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @DELETE
    @Path("{id}")
    public Response deleteRole(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat) {

        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // defaults to application/scim+json.
            if (outputFormat == null) {
                outputFormat = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
            // Obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // Obtain the role manager.
            RoleManager roleManager = IdentitySCIMManager.getInstance().getRoleManager();

            // Create charon-SCIM role resource manager and hand-over the request.
            RoleResourceManager roleResourceManager = new RoleResourceManager();

            SCIMResponse scimResponse = roleResourceManager.deleteRole(id, roleManager);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PUT
    @Path("{id}")
    public Response updateRole(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
            @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat, String resourceString) {

        JSONEncoder encoder = null;
        try {
            // Obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE + " not present in the request header";
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
            // Obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // Obtain the role manager.
            RoleManager roleManager = IdentitySCIMManager.getInstance().getRoleManager();

            // Create charon-SCIM role resource manager and hand-over the request.
            RoleResourceManager roleResourceManager = new RoleResourceManager();

            SCIMResponse response = roleResourceManager.updateWithPUTRole(id, resourceString, roleManager);

            return SupportUtils.buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PATCH
    @Path("{id}")
    public Response patchRole(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
            @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat, String resourceString) {

        JSONEncoder encoder = null;
        try {
            // Obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE + " not present in the request header";
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
            // Obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // Obtain the role manager.
            RoleManager roleManager = IdentitySCIMManager.getInstance().getRoleManager();

            // Create charon-SCIM role resource manager and hand-over the request.
            RoleResourceManager roleResourceManager = new RoleResourceManager();

            SCIMResponse response = roleResourceManager.updateWithPATCHRole(id, resourceString, roleManager);

            return SupportUtils.buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }
}
