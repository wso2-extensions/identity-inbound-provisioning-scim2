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

package org.wso2.carbon.identity.scim2.common.utils;

/**
 * Class to hold Identity SCIM Constants.
 */
public class SCIMCommonConstants {

    public static final String SCIM2_ENDPOINT = "/scim2";

    public static final String USERS = "/Users";
    public static final String GROUPS = "/Groups";
    public static final String SERVICE_PROVIDER_CONFIG = "/ServiceProviderConfig";
    public static final String RESOURCE_TYPE = "/ResourceTypes";
    public static final String DEFAULT = "default";

    public static final int USER = 1;
    public static final int GROUP = 2;

    public static final String SCIM_CORE_CLAIM_DIALECT = "urn:ietf:params:scim:schemas:core:2.0";
    public static final String SCIM_USER_CLAIM_DIALECT = "urn:ietf:params:scim:schemas:core:2.0:User";

    public static final String EQ = "eq";
    public static final String CO = "co";
    public static final String SW = "sw";
    public static final String EW = "ew";

    public static final String APPLICATION_DOMAIN = "Application";
    public static final String INTERNAL_DOMAIN = "Internal";

    public static final String ANY = "*";

    //config constants
    public static final String CHARON_CONFIG_NAME = "charon-config.xml";
    public static final String ELEMENT_NAME_AUTHENTICATION_SCHEMES = "authenticationSchemes";;
    public static final String ELEMENT_NAME_PROPERTY = "Property";
    public static final String ELEMENT_NAME_SCHEMA = "schema";
    public static final String ATTRIBUTE_NAME_NAME = "name";

    public static final String BULK_SUPPORTED = "bulk-supported";
    public static final String SORT_SUPPORTED = "sort-supported";
    public static final String PATCH_SUPPORTED = "patch-supported";
    public static final String ETAG_SUPPORTED = "etag-supported";
    public static final String FILTER_SUPPORTED = "filter-supported";
    public static final String CHNAGE_PASSWORD_SUPPORTED = "changePassword-supported";
    public static final String DOCUMENTATION_URL = "documentationUri";
    public static final String BULK_MAX_OPERATIONS = "bulk-maxOperations";
    public static final String BULK_MAX_PAYLOAD_SIZE = "bulk-maxPayloadSize";
    public static final String FILTER_MAX_RESULTS = "filter-maxResults";

    public static final java.lang.String ASK_PASSWORD_URI = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:askPassword";
    public static final java.lang.String VERIFY_EMAIL_URI = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:verifyEmail";

    // Identity recovery claims
    public static final String ASK_PASSWORD_CLAIM = "http://wso2.org/claims/identity/askPassword";
    public static final String VERIFY_EMAIL_CLIAM = "http://wso2.org/claims/identity/verifyEmail";
    public static final String SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED = "SCIM2" +
            ".ComplexMultiValuedAttributeSupportEnabled";
    public static final String SCIM_ENABLE_FILTERING_ENHANCEMENTS = "SCIM2.EnableFilteringEnhancements";
    public static final String SCIM_ENABLE_FILTER_USERS_AND_GROUPS_ONLY_FROM_PRIMARY_DOMAIN =
            "SCIM2.FilterUsersAndGroupsOnlyFromPrimaryDomain";
    public static final String SCIM_ENABLE_MANDATE_DOMAIN_FOR_GROUPNAMES_IN_GROUPS_RESPONSE =
            "SCIM2.MandateDomainForGroupNamesInGroupsResponse";
    public static final String SCIM_ENABLE_MANDATE_DOMAIN_FOR_USERNAMES_AND_GROUPNAMES_IN_RESPONSE =
            "SCIM2.MandateDomainForUsernamesAndGroupNamesInResponse";

    public static final String URL_SEPERATOR = "/";
    public static final String TENANT_URL_SEPERATOR = "/t/";
}

