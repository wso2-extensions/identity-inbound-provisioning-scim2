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
public class SCIMClientMapper implements ExceptionMapper<SCIMClientException> {

    @Override
    public Response toResponse(SCIMClientException e) {
        return Response.status(e.getErrorCode()).entity(e.getMessage()).type("text/plain").build();
    }
}
