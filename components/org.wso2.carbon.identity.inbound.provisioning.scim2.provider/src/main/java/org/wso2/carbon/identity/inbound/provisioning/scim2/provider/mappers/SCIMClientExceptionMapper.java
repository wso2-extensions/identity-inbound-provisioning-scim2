/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.inbound.provisioning.scim2.provider.mappers;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.exception.SCIMClientException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Exception mapper for SCIM2 Client Exception.
 */

@Component(
        name = "org.wso2.carbon.identity.inbound.provisioning.scim2.provider.SCIMClientMapper",
        service = ExceptionMapper.class,
        immediate = true
)
public class SCIMClientExceptionMapper implements ExceptionMapper<SCIMClientException> {

    @Override
    public Response toResponse(SCIMClientException e) {
        return Response.status(e.getErrorCode()).entity(e.getMessage()).type("text/plain").build();
    }
}
