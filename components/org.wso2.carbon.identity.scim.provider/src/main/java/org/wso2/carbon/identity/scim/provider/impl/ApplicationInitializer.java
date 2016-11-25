/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.scim.provider.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.scim.provider.resources.UserResource;
import org.wso2.msf4j.MicroservicesRunner;

/**
 * This performs one-time initialization tasks at the application startup.
 */
public class ApplicationInitializer {

    private static Log logger = LogFactory.getLog(UserResource.class);

    public static void main(String[] args) {
        logger.info("SCIM micro service is starting up.....");

        new MicroservicesRunner().deploy(new UserResource()).start();

        logger.info("SCIM micro service is successfully started.");
    }

}
