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
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.jaxrs.designator.PATCH;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.common.utils.AdminAttributeUtil;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.scim2.common.utils.SCIMConfigProcessor;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.charon3.core.config.SCIMConfigConstants;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.UserResourceManager;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.ResourceManagerUtil;

import java.util.Objects;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.scim2.provider.util.SupportUtils.buildCustomSchema;
import static org.wso2.carbon.identity.scim2.provider.util.SupportUtils.getTenantDomain;
import static org.wso2.carbon.identity.scim2.provider.util.SupportUtils.getTenantId;

@Path("/")
public class UserResource extends AbstractResource {

    private static final Log LOG = LogFactory.getLog(UserResource.class);

    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String  excludedAttributes) {

        try {
            if(!isValidOutputFormat(outputFormat)){
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());

            SCIMResponse scimResponse = userResourceManager.get(id, userManager,attribute, excludedAttributes);
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

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            // To initialize a thread local to get confirmation code of the user for ask password flow if notification
            // mange by client application.
            initializeAskPasswordConfirmationCodeThreadLocal(resourceString);

            SCIMResponse response = userResourceManager.create(resourceString, userManager,
                    attribute, excludedAttributes);

            return SupportUtils.buildCreateUserResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        } finally {
            removeAskPasswordConfirmationCodeThreadLocal();
        }
    }

    @DELETE
    @Path("{id}")
    public Response deleteUser(@PathParam(SCIMProviderConstants.ID) String id,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format) {

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

            // Skipping this validation if the request comes from a sub organization.
            if (!SCIMCommonUtils.isOrganization(getTenantDomain())) {
                String superAdminID = AdminAttributeUtil.getSuperAdminID();
                String loggedInUser = SCIMCommonUtils.getLoggedInUserID();
                if (superAdminID.equals(id) && !loggedInUser.equals(id)) {
                    LOG.debug("Do not have permission to delete SuperAdmin user.");
                    return Response.status(Response.Status.FORBIDDEN).build();
                }
            }

            // create charon-SCIM user resource manager and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse = userResourceManager.delete(id, userManager);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @GET
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getUser(@HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format,
                            @QueryParam (SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @QueryParam (SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                            @QueryParam (SCIMProviderConstants.FILTER) String filter,
                            @QueryParam (SCIMProviderConstants.START_INDEX) Integer startIndex,
                            @QueryParam (SCIMProviderConstants.COUNT) Integer count,
                            @QueryParam (SCIMProviderConstants.SORT_BY) String sortBy,
                            @QueryParam (SCIMProviderConstants.SORT_ORDER) String sortOrder,
                            @QueryParam (SCIMProviderConstants.DOMAIN) String domainName,
                            @QueryParam (SCIMProviderConstants.CURSOR) String cursor) {

        try {
            // defaults to application/scim+json.
            if (format == null) {
                format = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if(!isValidOutputFormat(format)){
                String error = format + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            // Validates the count parameter if exists.
            if (count != null && IdentityUtil.isSCIM2UserMaxItemsPerPageEnabled()) {
                count = validateCountParameter(count);
            }

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());

            // create charon-SCIM user resource manager and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse;

            //Check pagination type.
            String paginationType = ResourceManagerUtil.processPagination(startIndex, cursor);

            if (SCIMProviderConstants.CURSOR.equals(paginationType)) {
                //If the count is null when using a cursor pagination, set count to the value of
                //pagination_default_count specified in the server config (charon-config.xml)
                if (count == null) {
                    count = Integer.parseInt(SCIMConfigProcessor.getInstance().
                            getProperty(SCIMConfigConstants.PAGINATION_DEFAULT_COUNT));
                }
                scimResponse = userResourceManager.listWithGET(userManager, filter, cursor, count,
                        sortBy, sortOrder, domainName, attribute, excludedAttributes);
                return SupportUtils.buildResponse(scimResponse);
            }
            scimResponse = userResourceManager.listWithGET(userManager, filter, startIndex, count,
                    sortBy, sortOrder, domainName, attribute, excludedAttributes);
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
    public Response getUsersByPost(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                   @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
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

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());

            // create charon-SCIM user resource manager and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse = null;

            scimResponse = userResourceManager.listWithPOST(resourceString, userManager);

            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PUT
    @Path("{id}")
    public Response updateUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                               @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @QueryParam (SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @QueryParam (SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
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

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceEndpoint = new UserResourceManager();

            SCIMResponse response = userResourceEndpoint.updateWithPUT(
                    id, resourceString, userManager, attribute, excludedAttributes);

            return SupportUtils.buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PATCH
    @Path("{id}")
    public Response patchUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                              @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                              @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                              @QueryParam (SCIMProviderConstants.ATTRIBUTES) String attribute,
                              @QueryParam (SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
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
            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // Skipping this validation if the request comes from a sub organization.
            if (!SCIMCommonUtils.isOrganization(getTenantDomain())) {
                String superAdminID = AdminAttributeUtil.getSuperAdminID();
                String loggedInUser = SCIMCommonUtils.getLoggedInUserID();
                if (superAdminID.equals(id) && !loggedInUser.equals(id)) {
                    LOG.debug("Do not have permission to patch SuperAdmin user.");
                    return Response.status(Response.Status.FORBIDDEN).build();
                }
            }

            // Build Custom schema
            buildCustomSchema(userManager, getTenantId());

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceEndpoint = new UserResourceManager();

            SCIMResponse response = userResourceEndpoint.updateWithPATCH(
                    id, resourceString, userManager, attribute, excludedAttributes);

            return SupportUtils.buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    /**
     * To initialize the Ask password confirmation code thread local if the ask password is true.
     *
     * @param resourceString Resource body.
     */
    private void initializeAskPasswordConfirmationCodeThreadLocal(String resourceString) {

        if (SupportUtils.isAskPasswordFlow(resourceString)) {
            IdentityUtil.threadLocalProperties.get()
                    .put(IdentityRecoveryConstants.AP_CONFIRMATION_CODE_THREAD_LOCAL_PROPERTY,
                            IdentityRecoveryConstants.AP_CONFIRMATION_CODE_THREAD_LOCAL_INITIAL_VALUE);
        }
    }

    /**
     * Remove the ask password confirmation code thread local.
     */
    private void removeAskPasswordConfirmationCodeThreadLocal() {

        IdentityUtil.threadLocalProperties.get()
                .remove(IdentityRecoveryConstants.AP_CONFIRMATION_CODE_THREAD_LOCAL_PROPERTY);
    }

    /**
     * Validate the count query parameter.
     *
     * @param count Requested item count.
     * @return Validated count parameter.
     */
    private int validateCountParameter(Integer count) {

        int maximumItemsPerPage = IdentityUtil.getMaximumItemPerPage();
        if (count > maximumItemsPerPage) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Given limit exceeds the maximum limit. Therefore the limit is set to %s.",
                        maximumItemsPerPage));
            }
            return maximumItemsPerPage;
        }

        return count;
    }
}
