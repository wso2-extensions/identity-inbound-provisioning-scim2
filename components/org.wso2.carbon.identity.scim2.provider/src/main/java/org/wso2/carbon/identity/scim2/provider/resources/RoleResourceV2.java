/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.provider.resources;

import org.wso2.carbon.identity.jaxrs.designator.PATCH;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.extensions.RoleV2Manager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.RoleResourceV2Manager;
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

/**
 * This class is used to handle the SCIM V2 role resource requests.
 */
@Path("/")
public class RoleResourceV2 extends AbstractResource {

    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getRole(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes) {

        try {
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
            // Obtain the role manager.
            RoleV2Manager roleManager = IdentitySCIMManager.getInstance().getRoleV2Manager();
            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceV2Manager roleResourceManager = new RoleResourceV2Manager();
            SCIMResponse scimResponse = roleResourceManager.getRole(id, roleManager, attribute, excludedAttributes);
            // Needs to check the code of the response and return 200 0k or other error codes appropriately.
            return SupportUtils.buildResponse(scimResponse);
        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    @Path("/.search")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getRolesByPOST(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                   @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                   String resourceString) {

        try {
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
            // Obtain the role manager.
            RoleV2Manager roleManager = IdentitySCIMManager.getInstance().getRoleV2Manager();
            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceV2Manager roleResourceManager = new RoleResourceV2Manager();
            SCIMResponse scimResponse = roleResourceManager.listWithPOSTRole(resourceString, roleManager);
            return SupportUtils.buildResponse(scimResponse);
        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    public Response createRole(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               String resourceString) {

        try {
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
            // Obtain the role manager.
            RoleV2Manager roleManager = IdentitySCIMManager.getInstance().getRoleV2Manager();
            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceV2Manager roleResourceManager = new RoleResourceV2Manager();
            SCIMResponse response = roleResourceManager.createRole(resourceString, roleManager);
            return SupportUtils.buildResponse(response);
        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @GET
    public Response getRoles(@HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                             @QueryParam(SCIMProviderConstants.FILTER) String filter,
                             @QueryParam(SCIMProviderConstants.START_INDEX) Integer startIndex,
                             @QueryParam(SCIMProviderConstants.COUNT) Integer count,
                             @QueryParam(SCIMProviderConstants.SORT_BY) String sortBy,
                             @QueryParam(SCIMProviderConstants.SORT_ORDER) String sortOrder,
                             @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                             @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes) {

        try {
            // Defaults to application/scim+json.
            if (outputFormat == null) {
                outputFormat = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
            // Obtain the role manager.
            RoleV2Manager roleManager = IdentitySCIMManager.getInstance().getRoleV2Manager();
            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceV2Manager roleResourceManager = new RoleResourceV2Manager();
            SCIMResponse scimResponse = roleResourceManager
                    .listWithGETRole(roleManager, filter, startIndex, count, sortBy, sortOrder, attribute,
                            excludedAttributes);
            return SupportUtils.buildResponse(scimResponse);
        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @DELETE
    @Path("{id}")
    public Response deleteRole(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat) {

        try {
            // defaults to application/scim+json.
            if (outputFormat == null) {
                outputFormat = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw new FormatNotSupportedException(error);
            }
            // Obtain the role manager.
            RoleV2Manager roleManager = IdentitySCIMManager.getInstance().getRoleV2Manager();
            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceV2Manager roleResourceManager = new RoleResourceV2Manager();
            SCIMResponse scimResponse = roleResourceManager.deleteRole(id, roleManager);
            // Needs to check the code of the response and return 200 0k or other error codes appropriately.
            return SupportUtils.buildResponse(scimResponse);
        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PUT
    @Path("{id}")
    public Response updateRole(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                               @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               String resourceString) {

        try {
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
            // Obtain the role manager.
            RoleV2Manager roleManager = IdentitySCIMManager.getInstance().getRoleV2Manager();
            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceV2Manager roleResourceManager = new RoleResourceV2Manager();
            SCIMResponse response = roleResourceManager.updateWithPUTRole(id, resourceString, roleManager);
            return SupportUtils.buildResponse(response);
        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PATCH
    @Path("{id}")
    public Response patchRole(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                              @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
                              @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                              String resourceString) {

        try {
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
            // Obtain the role manager.
            RoleV2Manager roleManager = IdentitySCIMManager.getInstance().getRoleV2Manager();
            // Create charon-SCIM role endpoint and hand-over the request.
            RoleResourceV2Manager roleResourceManager = new RoleResourceV2Manager();
            SCIMResponse response = roleResourceManager.updateWithPATCHRole(id, resourceString, roleManager);
            return SupportUtils.buildResponse(response);
        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }
}
