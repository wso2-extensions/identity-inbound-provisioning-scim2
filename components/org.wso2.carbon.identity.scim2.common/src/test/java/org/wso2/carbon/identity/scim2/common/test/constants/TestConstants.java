/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.scim2.common.test.constants;

import java.util.Arrays;
import java.util.List;

/**
 * Constants used in the test classes.
 */
public class TestConstants {

    public static final String TEST_USER_ID = "testUserId";
    public static final String TEST_USER_USERNAME = "testUser";

    public enum Claims {
        NEW_SINGLEVALUE_CLAIM1("http://wso2.org/claims/claim1", false, "value11", "value11", null),
        UPDATING_SINGLEVALUE_CLAIM2("http://wso2.org/claims/claim2", false, "value21", "value21", "value20"),
        UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3("http://wso2.org/claims/claim3", false,
                "value31,value32,value33", "value31,value32,value33", "value30,value31"),
        DELETING_SINGLEVALUE_CLAIM4("http://wso2.org/claims/claim4", false, "value41", "", "value41"),
        DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5("http://wso2.org/claims/claim5", false,
                "value51,value52", "", "value51,value52"),
        NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6("http://wso2.org/claims/claim6", true,
                Arrays.asList("value61", "value62", "value63"),
                new String[]{"value61", "value62", "value63"}, null),
        NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM6("http://wso2.org/claims/claim6", true, "value61,value62,value63",
                new String[]{"value61", "value62", "value63"}, null),
        UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7("http://wso2.org/claims/claim7", true,
                Arrays.asList("value71", "value72"),
                new String[]{"value70", "value73", "value71", "value72"}, "value70,value73"),
        UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM7("http://wso2.org/claims/claim7", true, "value71,value72",
                new String[]{"value71", "value72"}, "value70,value73"),
        DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8("http://wso2.org/claims/claim8", true,
                Arrays.asList("value81", "value82"),
                new String[]{"value80"}, "value81,value80,value82"),
        DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8("http://wso2.org/claims/claim8", true,
                "value81,value80",
                new String[]{}, "value81,value80,value82"),
        FLOW_INITIATOR_SINGLEVALUE_IDENTITY_CLAIM1("http://wso2.org/claims/identity/adminForcedPasswordReset", false, "true", "false", null);

        private String claimURI;
        private boolean isMultiValued;
        private Object inputValue;
        private Object expectedValueInDTO;
        private String existingValueInUser;

        Claims(String claimURI, boolean isMultiValued, Object inputValue, Object expectedValueInDTO,
               String existingValueInUser) {

            this.claimURI = claimURI;
            this.isMultiValued = isMultiValued;
            this.inputValue = inputValue;
            this.expectedValueInDTO = expectedValueInDTO;
            this.existingValueInUser = existingValueInUser;
        }

        public String getClaimURI() {

            return claimURI;
        }

        public boolean isMultiValued() {

            return isMultiValued;
        }

        public String getInputValueAsString() {

            return String.valueOf(inputValue);
        }

        public List<String> getInputValueAsStringList() {

            return (List<String>) inputValue;
        }

        public String getExpectedValueInDTOAsString() {

            return String.valueOf(expectedValueInDTO);
        }

        public String[] getExpectedValueInDTOAsStringArray() {

            return (String[]) expectedValueInDTO;
        }

        public String getExistingValueInUser() {

            return existingValueInUser;
        }
    }

    private TestConstants() {

    }
}
