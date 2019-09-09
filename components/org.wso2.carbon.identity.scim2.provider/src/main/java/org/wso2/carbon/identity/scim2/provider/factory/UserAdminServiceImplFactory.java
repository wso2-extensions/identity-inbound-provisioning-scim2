/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.scim2.provider.factory;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.mgt.UserAdminManager;
import org.wso2.carbon.user.mgt.UserAdminManagerImpl;
import org.springframework.beans.factory.config.AbstractFactoryBean;

public class UserAdminServiceImplFactory extends AbstractFactoryBean<UserAdminManagerImpl> {

    private org.wso2.carbon.user.mgt.UserAdminManagerImpl userAdminManager;

    @Override
    public Class<UserAdminManagerImpl> getObjectType() {
        return UserAdminManagerImpl.class;
    }

    @Override
    protected UserAdminManagerImpl createInstance() throws Exception {
        if (this.userAdminManager != null) {
            return this.userAdminManager;
        } else {
            UserAdminManagerImpl userAdminManager = (UserAdminManagerImpl) PrivilegedCarbonContext.
                    getThreadLocalCarbonContext().getOSGiService(UserAdminManager.class, null);
            if (userAdminManager != null) {
                this.userAdminManager = userAdminManager;
            }
            return userAdminManager;
        }
    }
}
