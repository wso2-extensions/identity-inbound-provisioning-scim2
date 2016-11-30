package org.wso2.carbon.identity.inbound.provisioning.scim2.provider.mappers;

import org.osgi.service.component.annotations.Component;
import org.wso2.charon.core.v2.exceptions.FormatNotSupportedException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Exception mapper for Charon Exception.
 */

@Component(
        name = "org.wso2.carbon.identity.inbound.provisioning.scim2.provider.FormatNotSupportedException",
        service = ExceptionMapper.class,
        immediate = true
)
public class FormatNotSupportedMapper implements ExceptionMapper<FormatNotSupportedException> {

    @Override
    public Response toResponse(FormatNotSupportedException e) {
        return Response.status(e.getStatus()).
                entity(e.getDetail()).
                type("text/plain").
                build();
    }
}
