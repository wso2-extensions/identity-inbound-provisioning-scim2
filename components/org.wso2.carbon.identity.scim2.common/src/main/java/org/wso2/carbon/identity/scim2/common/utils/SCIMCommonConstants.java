/*
 * Copyright (c) 2017-2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.utils;

import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.util.HashMap;
import java.util.Map;


/**
 * Class to hold Identity SCIM Constants.
 */
public class SCIMCommonConstants {

    public static final String SCIM2_ENDPOINT = "/scim2";

    public static final String USERS = "/Users";
    public static final String GROUPS = "/Groups";
    public static final String ROLES = "/Roles";
    public static final String ROLES_V2 = "/v2/Roles";
    public static final String SERVICE_PROVIDER_CONFIG = "/ServiceProviderConfig";
    public static final String RESOURCE_TYPE = "/ResourceTypes";
    public static final String DEFAULT = "default";

    public static final int USER = 1;
    public static final int GROUP = 2;

    public static final String SCIM_CORE_CLAIM_DIALECT = "urn:ietf:params:scim:schemas:core:2.0";
    public static final String SCIM_USER_CLAIM_DIALECT = "urn:ietf:params:scim:schemas:core:2.0:User";
    public static final String SCIM_ENTERPRISE_USER_CLAIM_DIALECT =
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

    public static final String EQ = "eq";
    public static final String NE = "ne";
    public static final String CO = "co";
    public static final String SW = "sw";
    public static final String EW = "ew";
    public static final String GE = "ge";
    public static final String LE = "le";

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
    public static final String ENTERPRISE_USER_EXTENSION_ENABLED = "user-schema-extension-enabled";
    public static final String PAGINATION_DEFAULT_COUNT = "pagination-default-count";
    public static final String CUSTOM_USER_SCHEMA_ENABLED = "custom-user-schema-enabled";
    public static final String CUSTOM_USER_SCHEMA_URI = "custom-user-schema-uri";
    public static final String ENABLE_REGEX_VALIDATION_FOR_USER_CLAIM_INPUTS = "UserClaimUpdate.EnableUserClaimInputRegexValidation";
    public static final String CURSOR_PAGINATION_SUPPORTED = "cursor-pagination-supported";
    public static final java.lang.String ASK_PASSWORD_URI = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:askPassword";
    public static final java.lang.String VERIFY_EMAIL_URI = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:verifyEmail";

    // Identity recovery claims
    public static final String ASK_PASSWORD_CLAIM = "http://wso2.org/claims/identity/askPassword";
    public static final String VERIFY_EMAIL_CLIAM = "http://wso2.org/claims/identity/verifyEmail";

    public static final String READ_ONLY_USER_CLAIM = "http://wso2.org/claims/identity/isReadOnlyUser";

    public static final String SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED = "SCIM2" +
            ".ComplexMultiValuedAttributeSupportEnabled";
    public static final String SCIM_ENABLE_FILTERING_ENHANCEMENTS = "SCIM2.EnableFilteringEnhancements";
    public static final String SCIM_ENABLE_FILTER_USERS_AND_GROUPS_ONLY_FROM_PRIMARY_DOMAIN =
            "SCIM2.FilterUsersAndGroupsOnlyFromPrimaryDomain";
    public static final String SCIM_ENABLE_CONSIDER_MAX_LIMIT_FOR_TOTAL_RESULT =
            "SCIM2.ConsiderMaxLimitForTotalResult";
    public static final String SCIM_ENABLE_CONSIDER_TOTAL_RECORDS_FOR_TOTAL_RESULT_OF_LDAP =
            "SCIM2.ConsiderTotalRecordsForTotalResultOfLDAP";
    public static final String SCIM_ENABLE_GROUP_BASED_USER_FILTERING_IMPROVEMENTS =
            "SCIM2.EnableGroupBasedUserFilteringImprovements";
    public static final String SCIM_ENABLE_MANDATE_DOMAIN_FOR_GROUPNAMES_IN_GROUPS_RESPONSE =
            "SCIM2.MandateDomainForGroupNamesInGroupsResponse";
    public static final String SCIM_ENABLE_MANDATE_DOMAIN_FOR_USERNAMES_AND_GROUPNAMES_IN_RESPONSE =
            "SCIM2.MandateDomainForUsernamesAndGroupNamesInResponse";
    public static final String SCIM_RETURN_UPDATED_GROUP_IN_PATCH_RESPONSE = "SCIM2.ReturnUpdatedGroupInPatchResponse";
    public static final String SCIM_NOTIFY_USERSTORE_STATUS = "SCIM2.NotifyUserstoreStatus";
    public static final String SCIM_2_REMOVE_DUPLICATE_USERS_IN_USERS_RESPONSE =
            "SCIM2.RemoveDuplicateUsersInUsersResponse";
    public static final String SCIM2_COMPLEX_MULTI_ATTRIBUTE_FILTERING_ENABLED =
            "SCIM2MultiAttributeFiltering.UsePagination";

    public static final String URL_SEPERATOR = "/";
    public static final String TENANT_URL_SEPERATOR = "/t/";
    public static final String ORGANIZATION_PATH_PARAM = "/o/";

    //Configuration for primary login identifiers
    public static final String ENABLE_LOGIN_IDENTIFIERS = "LoginIdentifiers.Enable";
    public static final String PRIMARY_LOGIN_IDENTIFIER_CLAIM = "LoginIdentifiers.PrimaryLoginIdentifier";
    public static final boolean DEFAULT_ENABLE_LOGIN_IDENTIFIERS = false;

    public static final String DATE_OF_BIRTH_LOCAL_CLAIM = "http://wso2.org/claims/dob";
    public static final String MOBILE_LOCAL_CLAIM = "http://wso2.org/claims/mobile";
    public static final String GROUPS_LOCAL_CLAIM = "http://wso2.org/claims/groups";
    public static final String PROP_REG_EX = "RegEx";
    public static final String PROP_REG_EX_VALIDATION_ERROR = "RegExValidationError";
    public static final String PROP_DISPLAYNAME = "DisplayName";
    public static final String DOB_REG_EX_VALIDATION_DEFAULT_ERROR =
            "Date of Birth is not in the correct format of YYYY-MM-DD";
    public static final String MOBILE_REGEX_VALIDATION_DEFAULT_ERROR =
            "Mobile number is not in the correct format. Valid format is [+][country code][area code][local phone number]";
    public static final String COMMON_REGEX_VALIDATION_ERROR = "%s is not in the correct format.";
    public static final String NOT_EXISTING_GROUPS_ERROR = "The provided group/groups does not exist. Please " +
            "provide valid group/groups.";
    public static final String DATE_OF_BIRTH_REGEX = "^\\d{4}-\\d{2}-\\d{2}$";
    public static final String MOBILE_REGEX =
            "^\\s*(?:\\+?(\\d{1,3}))?[-. (]*(\\d{3})?[-. )]*(\\d{3})?[-. ]*(\\d{4,6})(?: *x(\\d+))?\\s*$";
    public static final String ERROR_CODE_RESOURCE_LIMIT_REACHED = "ATS-10001";
    public static final String DEFAULT_REGEX = "[^<>`\"]+";
    public static final String MIN_LENGTH = "minLength";
    public static final String MAX_LENGTH = "maxLength";
    public static final String REQUIRED = "required";


    private static final Map<String, String> groupAttributeSchemaMap = new HashMap<>();

    static {
        groupAttributeSchemaMap.put(SCIMConstants.CommonSchemaConstants.ID_URI,
                UserStoreConfigConstants.GROUP_ID_ATTRIBUTE);
        groupAttributeSchemaMap.put(SCIMConstants.CommonSchemaConstants.CREATED_URI,
                UserStoreConfigConstants.GROUP_CREATED_DATE_ATTRIBUTE);
        groupAttributeSchemaMap.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI,
                UserStoreConfigConstants.GROUP_LAST_MODIFIED_DATE_ATTRIBUTE);
        groupAttributeSchemaMap.put(SCIMConstants.CommonSchemaConstants.LOCATION_URI, "GroupLocation");
    }

    /**
     * Get the group mapped attributes.
     *
     * @return Group mapped attributes.
     */
    public static Map<String, String> getGroupAttributeSchemaMap() {

        return groupAttributeSchemaMap;
    }

    /**
     * Enum which contains the error codes and corresponding error messages.
     */
    public enum ErrorMessages {

        // SUO - SCIM User Operations.
        ERROR_CODE_INVALID_ATTRIBUTE_UPDATE("SUO-10000", "User attribute update is not allowed",
                "The user: %s has been JIT provisioned from federated IDP: %s. " +
                        "Hence provisioned user attributes are not allowed to update"),
        ERROR_CODE_REGEX_VIOLATION("SUO-10001", "Regex validation error",
                "%s attribute value doesn't match with %s regex pattern"),
        ERROR_CODE_LENGTH_VIOLATION("SUO-10002", "Length validation error",
                "%s attribute should be between %s and %s characters");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessages(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return this.description;
        }

        @Override
        public String toString() {

            return code + " : " + message;
        }
    }
}

