/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.scim2.common.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.RoleManager;
import org.wso2.charon3.core.objects.Role;
import org.wso2.charon3.core.objects.plainobjects.RolesGetResponse;
import org.wso2.charon3.core.utils.codeutils.Node;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;

import java.util.Map;
import java.util.Set;

/**
 * Implementation of the {@link RoleManager} interface to manage RoleResourceV2.
 */
public class SCIMRoleManagerV2 implements RoleManager {

    private static final Log LOG = LogFactory.getLog(SCIMRoleManagerV2.class);
    // TODO change to new Role manager Service.
    private RoleManagementService roleManagementService;
    private String tenantDomain;
    // TODO check whether can we change this in V2.
    private Set<String> systemRoles;


    // TODO change to new Role manager Service.
    public SCIMRoleManagerV2(RoleManagementService roleManagementService, String tenantDomain) {

        this.roleManagementService = roleManagementService;
        this.tenantDomain = tenantDomain;
        // Get the read only system roles set.
        this.systemRoles = roleManagementService.getSystemRoles();
    }

    @Override
    public Role createRole(Role role)
            throws CharonException, ConflictException, NotImplementedException, BadRequestException {

        return null;
    }

    @Override
    public Role getRole(String s, Map<String, Boolean> map)
            throws NotImplementedException, BadRequestException, CharonException, NotFoundException {

        return null;
    }

    @Override
    public void deleteRole(String s)
            throws NotFoundException, CharonException, NotImplementedException, BadRequestException {

    }

    @Override
    public RolesGetResponse listRolesWithGET(Node node, Integer integer, Integer integer1, String s, String s1)
            throws CharonException, NotImplementedException, BadRequestException {

        return null;
    }

    @Override
    public Role updateRole(Role role, Role role1)
            throws NotImplementedException, BadRequestException, CharonException, ConflictException, NotFoundException {

        return null;
    }

    @Override
    public RolesGetResponse listRolesWithPost(SearchRequest searchRequest)
            throws NotImplementedException, BadRequestException, CharonException {

        return null;
    }
}
