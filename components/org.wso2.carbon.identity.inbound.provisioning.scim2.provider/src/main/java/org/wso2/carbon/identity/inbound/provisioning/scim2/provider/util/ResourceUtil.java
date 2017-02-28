/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.inbound.provisioning.scim2.provider.util;

import org.wso2.charon3.core.config.CharonConfiguration;
import org.wso2.charon3.core.exceptions.BadRequestException;

/*import static org.wso2.carbon.kernel.utils.StringUtils.isNullOrEmpty;*/

/**
 * Provide utility to process startIndex and count
 */
public class ResourceUtil {

    /**
     * Assign startIndex to default value, if user haven't sent startIndex
     * @param startIndexStr
     * @return
     * @throws BadRequestException
     */
    public static int processStartIndex(String startIndexStr) throws BadRequestException {

        int startIndex = 1;

        if (startIndexStr == null) {
            return startIndex;
        }

        try {
            startIndex = Integer.parseInt(startIndexStr);
        } catch (NumberFormatException e) {
            throw new BadRequestException("Please Provide Valid Number for startIndex parameter");
        }

        return startIndex;
    }

    /**
     * Assign count value to default value, if user haven't sent count
     * @param countStr
     * @return
     * @throws BadRequestException
     */
    public static int processCount(String countStr) throws BadRequestException {

        if (countStr == null) {
            return CharonConfiguration.getInstance().getCountValueForPagination();
        }
        try {
            return Integer.parseInt(countStr);
        } catch (NumberFormatException e) {
            throw new BadRequestException("Please Provide Valid Number for count parameter");
        }
    }
}
