package org.wso2.carbon.identity.scim2.common.impl;

import org.wso2.carbon.identity.scim2.common.ScopeProvider;

import java.util.HashMap;
import java.util.Map;

public class
SCIMScopeProviderImpl implements ScopeProvider {

    private static final Map<String, String> OPERATION_SCOPE_MAP = new HashMap<>();

    static {
        OPERATION_SCOPE_MAP.put("group_mgt_metadata_update", "internal_group_mgt_metadata_update");
        OPERATION_SCOPE_MAP.put("user_assignment_group", "internal_user_mgt_update");
        OPERATION_SCOPE_MAP.put("user_assignment_role", "internal_user_mgt_update");
    }

    @Override
    public String resolve(String operation) {

        return OPERATION_SCOPE_MAP.get(operation);
    }
}
