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

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.mgt.RolePermissionManagementService;
import org.wso2.carbon.user.mgt.RolePermissionManagementServiceImpl;

/**
 *  Role Permission Management OSGi service factory bean class.
 */
public class RolePermissionManagementServiceImplFactory extends
                                      AbstractFactoryBean<RolePermissionManagementServiceImpl> {

    private org.wso2.carbon.user.mgt.RolePermissionManagementServiceImpl rolePermissionManagementService;

    @Override
    public Class<RolePermissionManagementServiceImpl> getObjectType() {
        return RolePermissionManagementServiceImpl.class;
    }

    @Override
    protected RolePermissionManagementServiceImpl createInstance() throws Exception {
        if (this.rolePermissionManagementService != null) {
            return this.rolePermissionManagementService;
        } else {
            RolePermissionManagementServiceImpl userAdminManager = (RolePermissionManagementServiceImpl)
                    PrivilegedCarbonContext.getThreadLocalCarbonContext()
                            .getOSGiService(RolePermissionManagementService.class, null);
            if (userAdminManager != null) {
                this.rolePermissionManagementService = userAdminManager;
            }
            return userAdminManager;
        }
    }
}
