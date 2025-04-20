package org.wso2.carbon.identity.scim2.common.impl;

import org.wso2.carbon.identity.scim2.common.ScopeProvider;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.GROUP_METADATA_UPDATE;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.USER_ASSIGNMENT_INTO_GROUP;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.USER_ASSIGNMENT_INTO_ROLE;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.GROUP_ASSIGNMENT_INTO_ROLE;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.ROLE_UPDATE_PERMISSIONS;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.ROLE_UPDATE_NAME;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.USER_CREATION;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.USER_DELETION;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.FILTER_USERS;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.SEARCH_USERS;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.GET_USER_BY_ID;

public class SCIMScopeProviderImpl implements ScopeProvider {

    private static final Map<String, String> SCIM_OPERATION_SCOPE_MAP = new HashMap<>();

    static {
        SCIM_OPERATION_SCOPE_MAP.put(GROUP_METADATA_UPDATE, "internal_group_entitlement");
        SCIM_OPERATION_SCOPE_MAP.put(USER_ASSIGNMENT_INTO_GROUP, "internal_group_entitlement");
        SCIM_OPERATION_SCOPE_MAP.put(USER_ASSIGNMENT_INTO_ROLE, "internal_role_entitlement");
        SCIM_OPERATION_SCOPE_MAP.put(GROUP_ASSIGNMENT_INTO_ROLE, "internal_role_entitlement");
        SCIM_OPERATION_SCOPE_MAP.put(ROLE_UPDATE_PERMISSIONS, "internal_role_mgt_update");
        SCIM_OPERATION_SCOPE_MAP.put(ROLE_UPDATE_NAME, "internal_role_mgt_update");
        SCIM_OPERATION_SCOPE_MAP.put(FILTER_USERS, "internal_user_mgt_list");
        SCIM_OPERATION_SCOPE_MAP.put(USER_CREATION, "internal_user_mgt_create");
        SCIM_OPERATION_SCOPE_MAP.put(USER_DELETION, "internal_user_mgt_delete");
        SCIM_OPERATION_SCOPE_MAP.put(SEARCH_USERS, "internal_user_mgt_list");
        SCIM_OPERATION_SCOPE_MAP.put(GET_USER_BY_ID, "internal_user_mgt_view");
    }

    @Override
    public String resolve(String operation) {

        return SCIM_OPERATION_SCOPE_MAP.get(operation);
    }
}
