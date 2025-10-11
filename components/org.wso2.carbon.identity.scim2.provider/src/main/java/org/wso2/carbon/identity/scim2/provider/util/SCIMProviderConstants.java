/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.provider.util;

public class SCIMProviderConstants {

    public static final String AUTHORIZATION = "Authorization";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String ATTRIBUTES = "attributes";
    public static final String EXCLUDE_ATTRIBUTES = "excludedAttributes";
    public static final String FILTER = "filter";
    public static final String START_INDEX = "startIndex";
    public static final String COUNT = "count";
    public static final String SORT_BY = "sortBy";
    public static final String SORT_ORDER = "sortOder";
    public static final String SCIM_VERSION = "scimVersion";
    public static final String SCIM_VERSION_V3 = "v3";
    public static final String APPLICATION_SCIM_JSON = "application/scim+json";
    public static final String APPLICATION__JSON = "application/json";
    public static final String APPLICATION_ALL = "application/*";
    public static final String CHARSET_UTF8= "charset=utf-8";
    public static final String SEMI_COLON = ";";
    public static final String CHARSET= "charset";
    public static final String ACCEPT_HEADER = "Accept";
    public static final String ID = "id";
    public static final String DOMAIN = "domain";
    public static final String GROUPS = "groups";
    public static final String USERS = "users";

    public static final String RESOURCE_STRING = "RESOURCE_STRING";
    public static final String HTTP_VERB = "HTTP_VERB";
    public static final String SEARCH = ".search";
    public static final String DEFAULT_USERNAME = "admin";
    public static final String ADD = "add";
    public static final String OPERATIONS = "Operations";
    public static final String OP = "op";
    public static final String PATH = "path";
    public static final String REMOVE = "remove";
    public static final String REPLACE = "replace";
    public static final String VALUE_EQ = "value eq";

    public static final String BULK_CREATE_ROLE_OPERATION_NAME = "createRole";
    public static final String BULK_UPDATE_ROLE_OPERATION_NAME = "updateRole";
    public static final String BULK_DELETE_ROLE_OPERATION_NAME = "deleteRole";

    public static final String SKIP_ENFORCE_ROLE_OPERATION_PERMISSION = "RoleMgt.SkipEnforceRoleOperationPermission";

    /*
     * This class contains constants related to SCIM Role operations.
     */
    public static class RoleV2Operations {

        public static final String UPDATE_ROLE_PERMISSIONS = "updateRolePermissions";
        public static final String UPDATE_ROLE_MEMBERS = "updateRoleMembers";
        public static final String UPDATE_ROLE_GROUPS = "updateRoleGroups";
    }
}
