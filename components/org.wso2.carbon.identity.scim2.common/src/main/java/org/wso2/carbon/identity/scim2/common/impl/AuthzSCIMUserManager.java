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

package org.wso2.carbon.identity.scim2.common.impl;

import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.ForbiddenException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.objects.plainobjects.GroupsGetResponse;
import org.wso2.charon3.core.objects.plainobjects.UsersGetResponse;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;

import java.util.Map;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.BULK_CREATE_USER_OP;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.BULK_DELETE_USER_OP;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.BULK_UPDATE_USER_OP;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.validateFineGrainScopes;

/**
 * SCIM UserManager implementation which validates fine-grained scopes for SCIM operations.
 * This class extends the SCIMUserManager and overrides methods to include operational scope validation.
 */
public class AuthzSCIMUserManager implements UserManager {

    private final SCIMUserManager scimUserManager;

    public AuthzSCIMUserManager(UserStoreManager carbonUserStoreManager,
                                ClaimMetadataManagementService claimMetadataManagementService,
                                String tenantDomain) {

        scimUserManager = new SCIMUserManager(carbonUserStoreManager, claimMetadataManagementService, tenantDomain);
    }

    @Override
    public User createUser(User user, Map<String, Boolean> map)
            throws CharonException, ConflictException, BadRequestException, ForbiddenException {

        if (SCIMCommonUtils.isBulkRequest()) {
            validateFineGrainScopes(BULK_CREATE_USER_OP);
        }
        return scimUserManager.createUser(user, map);
    }

    @Override
    public User getUser(String s, Map<String, Boolean> map)
            throws CharonException, BadRequestException, NotFoundException {

        return scimUserManager.getUser(s, map);
    }

    @Override
    public void deleteUser(String s)
            throws NotFoundException, CharonException, NotImplementedException, BadRequestException,
            ForbiddenException {

        if (SCIMCommonUtils.isBulkRequest()) {
            validateFineGrainScopes(BULK_DELETE_USER_OP);
        }
        scimUserManager.deleteUser(s);
    }

    @Override
    public UsersGetResponse listUsersWithPost(SearchRequest searchRequest, Map<String, Boolean> map)
            throws CharonException, NotImplementedException, BadRequestException {

        return scimUserManager.listUsersWithPost(searchRequest, map);
    }

    @Override
    public User updateUser(User user, Map<String, Boolean> map)
            throws NotImplementedException, CharonException, BadRequestException, NotFoundException,
            ForbiddenException {

        if (SCIMCommonUtils.isBulkRequest()) {
            validateFineGrainScopes(BULK_UPDATE_USER_OP);
        }
        return scimUserManager.updateUser(user, map);
    }

    @Override
    public User getMe(String s, Map<String, Boolean> map) throws CharonException, NotFoundException {

        return scimUserManager.getMe(s, map);
    }

    @Override
    public User createMe(User user, Map<String, Boolean> map)
            throws CharonException, ConflictException, BadRequestException, ForbiddenException {

        return scimUserManager.createMe(user, map);
    }

    @Override
    public void deleteMe(String s)
            throws NotFoundException, CharonException, NotImplementedException, BadRequestException {

        scimUserManager.deleteMe(s);
    }

    @Override
    public User updateMe(User user, Map<String, Boolean> map)
            throws NotImplementedException, CharonException, BadRequestException {

        return scimUserManager.updateMe(user, map);
    }

    @Override
    public Group createGroup(Group group, Map<String, Boolean> map)
            throws CharonException, ConflictException, BadRequestException {

        return scimUserManager.createGroup(group, map);
    }

    @Override
    public Group getGroup(String s, Map<String, Boolean> map)
            throws NotImplementedException, BadRequestException, CharonException, NotFoundException {

        return scimUserManager.getGroup(s, map);
    }

    @Override
    public void deleteGroup(String s)
            throws NotFoundException, CharonException, BadRequestException {

        scimUserManager.deleteGroup(s);
    }

    @Override
    public Group updateGroup(Group group, Group group1, Map<String, Boolean> map)
            throws BadRequestException, CharonException, NotFoundException {

        return scimUserManager.updateGroup(group, group1, map);
    }

    @Override
    public GroupsGetResponse listGroupsWithPost(SearchRequest searchRequest, Map<String, Boolean> map)
            throws NotImplementedException, BadRequestException, CharonException {

        return scimUserManager.listGroupsWithPost(searchRequest, map);
    }
}
