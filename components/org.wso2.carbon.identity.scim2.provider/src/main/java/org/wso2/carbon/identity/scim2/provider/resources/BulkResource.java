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

import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.charon3.core.encoder.JSONEncoder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.BulkResourceManager;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;


@Path("/")
public class BulkResource extends AbstractResource {

    @POST
    public Response createUser(@HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorizationHeader,
                               @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               String resourceString) {

        JSONEncoder encoder = null;
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
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM bulk endpoint and hand-over the request.
            BulkResourceManager bulkResourceManager = new BulkResourceManager();
            //call for process bulk data
            SCIMResponse scimResponse = bulkResourceManager.processBulkData(resourceString, userManager);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e,encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }
}

