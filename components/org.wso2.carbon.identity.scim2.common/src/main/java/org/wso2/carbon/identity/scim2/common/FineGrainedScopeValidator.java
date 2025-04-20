package org.wso2.carbon.identity.scim2.common;

import org.wso2.charon3.core.exceptions.BadRequestException;

public interface FineGrainedScopeValidator {

    void validate(String operation) throws BadRequestException;
}
