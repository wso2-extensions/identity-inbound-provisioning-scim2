/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.SchemaResourceManager;
import org.wso2.charon3.core.schema.SCIMConstants;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.getTenantDomainFromContext;

public class SchemaResource extends AbstractResource {

    private static final Log logger = LogFactory.getLog(SchemaResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSchemas() {

        try {
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            // create charon-SCIM schemas endpoint and hand-over the request.
            SchemaResourceManager schemaResourceManager = new SchemaResourceManager();
            SCIMResponse scimResponse = schemaResourceManager.get(null, userManager, null, null);

            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e);
        }
    }

    @GET
    @Path("/{id}")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getSchemasById(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id) {

        try {
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();

            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                String tenantDomain = getTenantDomainFromContext();
            }

            // create charon-SCIM schemas endpoint and hand-over the request.
            SchemaResourceManager schemaResourceManager = new SchemaResourceManager();
            SCIMResponse scimResponse = schemaResourceManager.get(id, userManager, null, null);

            return SupportUtils.buildResponse(scimResponse);
        } catch (CharonException e) {
            return handleCharonException(e);
        }
    }
}
