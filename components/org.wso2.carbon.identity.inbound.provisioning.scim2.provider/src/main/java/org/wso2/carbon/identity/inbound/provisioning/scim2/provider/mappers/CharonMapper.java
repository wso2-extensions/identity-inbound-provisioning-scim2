package org.wso2.carbon.identity.inbound.provisioning.scim2.provider.mappers;

import org.osgi.service.component.annotations.Component;
import org.wso2.charon.core.v2.exceptions.CharonException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Exception mapper for Charon Exception.
 */

@Component(
        name = "org.wso2.carbon.identity.inbound.provisioning.scim2.common.mappers.CharonMapper;",
        service = ExceptionMapper.class,
        immediate = true
)
public class CharonMapper implements ExceptionMapper<CharonException> {


    @Override
    public Response toResponse(CharonException e) {
        return Response.status(e.getStatus()).
                entity(e.getDetail() + "." + e.getMessage()).
                type("text/plain").
                build();
    }
}
