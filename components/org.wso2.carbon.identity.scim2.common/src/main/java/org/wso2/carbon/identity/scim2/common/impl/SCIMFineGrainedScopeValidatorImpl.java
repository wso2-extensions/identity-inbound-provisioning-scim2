package org.wso2.carbon.identity.scim2.common.impl;

import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.scim2.common.FineGrainedScopeValidator;
import org.wso2.charon3.core.exceptions.BadRequestException;

import java.util.List;

public class SCIMFineGrainedScopeValidatorImpl
        implements FineGrainedScopeValidator {

    private static final String FORBIDDEN_ERROR_MSG = "Operation is not permitted. You do not have permissions to " +
            "make this request.";

    @Override
    public void validate(String operation) throws BadRequestException {

        SCIMScopeProviderImpl scopeProvider = new SCIMScopeProviderImpl();
        String RequiredScope = scopeProvider.resolve(operation);
        List<String> authorizedScopes = (List<String>) IdentityUtil.threadLocalProperties.get().get(
                OAuth2Constants.AUTHORIZED_SCOPES);
        if (authorizedScopes != null && !authorizedScopes.contains(RequiredScope)) {
             throw new BadRequestException(
                     FORBIDDEN_ERROR_MSG);
        }
    }
}
