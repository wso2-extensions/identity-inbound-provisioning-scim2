package org.wso2.carbon.identity.scim2.common;

public interface ScopeProvider {

    String resolve(String operation);
}
