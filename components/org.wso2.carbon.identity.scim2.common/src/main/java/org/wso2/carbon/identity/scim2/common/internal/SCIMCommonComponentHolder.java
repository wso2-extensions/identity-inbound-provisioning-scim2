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

package org.wso2.carbon.identity.scim2.common.internal;

import org.wso2.carbon.user.core.service.RealmService;

/**
 * SCIM service holder class.
 *
 */
public class SCIMCommonComponentHolder {

    private static RealmService realmService;

    /**
     * Get realm service.
     *
     * @return
     */
    public static RealmService getRealmService() {

        return SCIMCommonComponentHolder.realmService;
    }

    /**
     * Set realm service.
     *
     * @param realmService
     */
    public static void setRealmService(RealmService realmService) {

        SCIMCommonComponentHolder.realmService = realmService;
    }

}
