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

import org.wso2.carbon.identity.authorization.common.AuthorizationUtil;
import org.wso2.carbon.identity.authorization.common.exception.ForbiddenException;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.charon3.core.encoder.JSONDecoder;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.exceptions.InternalErrorException;
import org.wso2.charon3.core.exceptions.PayloadTooLargeException;
import org.wso2.charon3.core.extensions.RoleManager;
import org.wso2.charon3.core.extensions.RoleV2Manager;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.bulk.BulkRequestContent;
import org.wso2.charon3.core.objects.bulk.BulkRequestData;
import org.wso2.charon3.core.objects.bulk.BulkResponseContent;
import org.wso2.charon3.core.objects.bulk.BulkResponseData;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.AbstractResourceManager;
import org.wso2.charon3.core.protocol.endpoints.BulkResourceManager;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants.BULK_CREATE_ROLE_OPERATION_NAME;
import static org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants.BULK_DELETE_ROLE_OPERATION_NAME;
import static org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants.BULK_UPDATE_ROLE_OPERATION_NAME;

@Path("/")
public class BulkResource extends AbstractResource {

    @POST
    public Response createUser(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               String resourceString) {
        try {
            SupportUtils.enterFlow(Flow.Name.BULK_RESOURCE_UPDATE);
            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if (!isValidInputFormat(inputFormat)) {
                String error = inputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            // Obtain the user store manager.
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();
            // Obtain the role manager.
            RoleManager roleManager = IdentitySCIMManager.getInstance().getRoleManager();
            // Obtain the role v2 manager.
            RoleV2Manager roleV2Manager = IdentitySCIMManager.getInstance().getRoleV2Manager();

            List<BulkRequestContent> authorizedRoleV2BulkOperations = new ArrayList<>();
            List<BulkRequestContent> unauthorizedRoleV2BulkOperations = new ArrayList<>();

            // create charon-SCIM bulk endpoint and hand-over the request.
            BulkResourceManager bulkResourceManager = new BulkResourceManager();
            BulkRequestData bulkRequestData;
            try {
                bulkRequestData = validateOperationScopes(resourceString, bulkResourceManager,
                        unauthorizedRoleV2BulkOperations, authorizedRoleV2BulkOperations);

                // Call for process bulk data.
                BulkResponseData bulkResponseData =
                        bulkResourceManager.processBulkData(bulkRequestData, userManager, roleManager, roleV2Manager);
                addUnauthorizedOperationsToResponse(bulkResponseData, unauthorizedRoleV2BulkOperations);
                SCIMResponse scimResponse = bulkResourceManager.getEncodeSCIMResponse(bulkResponseData);
                // needs to check the code of the response and return 200 0k or other error codes
                // appropriately.
                return SupportUtils.buildResponse(scimResponse);
            } catch (CharonException | BadRequestException | PayloadTooLargeException | InternalErrorException e) {
                return SupportUtils.buildResponse(AbstractResourceManager.encodeSCIMException(e));
            }

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        } finally {
            IdentityContext.getThreadLocalIdentityContext().exitFlow();
        }
    }

    private BulkRequestData validateOperationScopes(String resourceString, BulkResourceManager bulkResourceManager,
                                         List<BulkRequestContent> unAuthorizedBulkOperations,
                                         List<BulkRequestContent> authorizedBulkOperations)
            throws BadRequestException, CharonException {

        BulkRequestData bulkRequestData = bulkResourceManager.getDecodeBulkRequest(resourceString);
        if (!bulkRequestData.getRoleV2OperationRequests().isEmpty()) {
            for (BulkRequestContent bulkRequestContent : bulkRequestData.getRoleV2OperationRequests()) {
                String operationName = getOperationNameForMethod(bulkRequestContent.getMethod());
                if (operationName != null) {
                    try {
                        AuthorizationUtil.validateOperationScopes(operationName);
                        authorizedBulkOperations.add(bulkRequestContent);
                    } catch (ForbiddenException e) {
                        unAuthorizedBulkOperations.add(bulkRequestContent);
                    }
                }
            }
            bulkRequestData.setRoleV2OperationRequests(authorizedBulkOperations);
        }
        return bulkRequestData;
    }

    private String getOperationNameForMethod(String method) {

        switch (method.toUpperCase()) {
            case HttpMethod.POST:
                return BULK_CREATE_ROLE_OPERATION_NAME;
            case HttpMethod.PUT:
            case HttpMethod.PATCH:
                return BULK_UPDATE_ROLE_OPERATION_NAME;
            case HttpMethod.DELETE:
                return BULK_DELETE_ROLE_OPERATION_NAME;
            default:
                return null;
        }
    }

    private void addUnauthorizedOperationsToResponse(BulkResponseData bulkResponseData,
                                                 List<BulkRequestContent> unauthorizedBulkOperations) {

        if (!unauthorizedBulkOperations.isEmpty()) {
            for (BulkRequestContent bulkRequestContent : unauthorizedBulkOperations) {
                bulkResponseData.addRoleOperation(buildForbiddenBulkResponseContent(bulkRequestContent));
            }
        }
    }

    private BulkResponseContent buildForbiddenBulkResponseContent(BulkRequestContent bulkRequestContent) {

        BulkResponseContent bulkResponseContent = new BulkResponseContent();
        bulkResponseContent.setBulkID(bulkRequestContent.getBulkID());
        bulkResponseContent.setMethod(bulkRequestContent.getMethod());
        bulkResponseContent.setScimResponse(
                AbstractResourceManager.encodeSCIMException(
                        new org.wso2.charon3.core.exceptions.ForbiddenException("Operation is not permitted. You do not have permissions to make " +
                                "this request.", "You do not have permission to perform this operation.")));
        return bulkResponseContent;
    }
}

