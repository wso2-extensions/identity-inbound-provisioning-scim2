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


import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.jaxrs.designator.PATCH;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.MeResourceManager;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.scim2.provider.util.SupportUtils.buildCustomSchema;
import static org.wso2.carbon.identity.scim2.provider.util.SupportUtils.getTenantId;

public class MeResource extends AbstractResource {
    @GET
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getUser(@HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String  excludedAttributes) {

        String userId = SupportUtils.getAuthenticatedUserId();
        try {
            if(!isValidOutputFormat(outputFormat)){
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());
            // create charon-SCIM me endpoint and hand-over the request.
            MeResourceManager meResourceManager = new MeResourceManager();

            SCIMResponse scimResponse = meResourceManager.get(userId, userManager, attribute, excludedAttributes);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    public Response createUser(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String  excludedAttributes,
                               String resourceString) {

        try {
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

            // create charon-SCIM user endpoint and hand-over the request.
            MeResourceManager meResourceManager = new MeResourceManager();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());

            SCIMResponse response = meResourceManager.create(resourceString, userManager,
                    attribute, excludedAttributes);

            return SupportUtils.buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }


    @DELETE
    public Response deleteUser(@HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format) {

        String userId = SupportUtils.getAuthenticatedUserId();
        try {
            // defaults to application/scim+json.
            if (format == null) {
                format = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if(!isValidOutputFormat(format)){
                String error = format + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM me resource manager and hand-over the request.
            MeResourceManager meResourceManager = new MeResourceManager();

            SCIMResponse scimResponse = meResourceManager.delete(userId, userManager);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PUT
    public Response updateUser(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @QueryParam (SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @QueryParam (SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                               String resourceString) {

        updateIdentityContext();
        String userId = SupportUtils.getAuthenticatedUserId();
        try {
            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE + " not present in the request header";
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

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());

            // create charon-SCIM me resource manager and hand-over the request.
            MeResourceManager meResourceManager = new MeResourceManager();

            SCIMResponse response = meResourceManager.updateWithPUT(
                    userId, resourceString, userManager, attribute, excludedAttributes);

            return SupportUtils.buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PATCH
    public Response patchUser(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                              @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                              @QueryParam (SCIMProviderConstants.ATTRIBUTES) String attribute,
                              @QueryParam (SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                              String resourceString) {

        updateIdentityContext();
        String userId = SupportUtils.getAuthenticatedUserId();
        try {
            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE + " not present in the request header";
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

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());

            // create charon-SCIM me resource manager and hand-over the request.
            MeResourceManager meResourceManager = new MeResourceManager();

            SCIMResponse response = meResourceManager.updateWithPATCH(
                    userId, resourceString, userManager, attribute, excludedAttributes);

            return SupportUtils.buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    /**
     * This is used to set the flow and initiator in the identity context.
     * These values will be used in the pre update password action.
     */
    private void updateIdentityContext() {

        Flow flow = new Flow.Builder()
                .name(Flow.Name.PROFILE_UPDATE)
                .initiatingPersona(Flow.InitiatingPersona.USER)
                .build();
        IdentityContext.getThreadLocalIdentityContext().setFlow(flow);
    }
}
