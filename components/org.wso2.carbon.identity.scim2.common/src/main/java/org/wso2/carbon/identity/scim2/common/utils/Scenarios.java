/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;

/**
 * Enum which contains the scenarios.
 */
public enum Scenarios {

    CREDENTIAL_UPDATE_BY_ADMIN_VIA_CONSOLE,
    CREDENTIAL_UPDATE_BY_USER_VIA_MY_ACCOUNT;

    /**
     * Get scenario which matches the given scenario name.
     *
     * @param scenarioName Name of the scenario
     * @return Scenarios
     * @throws IdentitySCIMException Invalid scenario
     */
    public static Scenarios getScenario(String scenarioName) throws IdentitySCIMException {

        Scenarios[] scenarios = {
                CREDENTIAL_UPDATE_BY_ADMIN_VIA_CONSOLE, CREDENTIAL_UPDATE_BY_USER_VIA_MY_ACCOUNT
        };
        if (StringUtils.isNotEmpty(scenarioName)) {
            for (Scenarios scenario : scenarios) {
                if (scenarioName.equals(scenario.name())) {
                    return scenario;
                }
            }
        }
        throw new IdentitySCIMException("Invalid scenario: " + scenarioName);
    }

}
