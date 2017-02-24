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
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Contact;
import io.swagger.annotations.Info;
import io.swagger.annotations.License;
import io.swagger.annotations.SwaggerDefinition;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.exception.SCIMClientException;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.ServiceProviderConfigResourceManager;
import org.wso2.msf4j.Microservice;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

/**
 * Endpoints of the ServiceProviderConfig in micro service. This will basically captures
 * the requests from the remote clients and hand over the request to respective operation performer.
 * Clients can view service providers configurations through this endpoint.
 */
@Component(
        name = "org.wso2.carbon.identity.inbound.provisioning.scim2.provider.resources.ServiceProviderConfigResource",
        service = Microservice.class,
        immediate = true
)

@Api(value = "scim/v2/ServiceProviderConfig")
@SwaggerDefinition(
        info = @Info(
                title = "/ServiceProviderConfig Endpoint Swagger Definition", version = "1.0",
                description = "SCIM 2.0 /ServiceProviderConfig endpoint",
                license = @License(name = "Apache 2.0", url = "http://www.apache.org/licenses/LICENSE-2.0"),
                contact = @Contact(
                        name = "WSO2 Identity Server Team",
                        email = "vindula@wso2.com",
                        url = "http://wso2.com"
                ))
)
@Path("/scim/v2/ServiceProviderConfig")
public class ServiceProviderConfigResource extends AbstractResource {

    @GET
    @Produces({"application/scim+json"})
    @ApiOperation(
            value = "Return the ServiceProviderConfig schema.",
            notes = "Returns HTTP 200 if the schema is found.")

    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Schema is found"),
            @ApiResponse(code = 404, message = "Schema is not found")})

    public Response getUser() throws SCIMClientException {

        // create charon-SCIM resourceType endpoint and hand-over the request.
        ServiceProviderConfigResourceManager serviceProviderConfigResourceManager =
                new ServiceProviderConfigResourceManager();

        SCIMResponse scimResponse = serviceProviderConfigResourceManager.get(null, null, null, null);
        // needs to check the code of the response and return 200 0k or other error codes
        // appropriately.
        return buildResponse(scimResponse);
    }
}
