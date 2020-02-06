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

package org.wso2.carbon.identity.scim2.common.impl;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.ListUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.mgt.policy.PolicyViolationException;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.utils.AttributeMapper;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.PaginatedUserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.model.Condition;
import org.wso2.carbon.user.core.model.ExpressionAttribute;
import org.wso2.carbon.user.core.model.ExpressionCondition;
import org.wso2.carbon.user.core.model.ExpressionOperation;
import org.wso2.carbon.user.core.model.OperationalCondition;
import org.wso2.carbon.user.core.model.OperationalOperation;
import org.wso2.carbon.user.core.model.UniqueIDUserClaimSearchEntry;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.user.mgt.RolePermissionException;
import org.wso2.charon3.core.attributes.AbstractAttribute;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.ComplexAttribute;
import org.wso2.charon3.core.attributes.MultiValuedAttribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMDefinitions;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.utils.AttributeUtil;
import org.wso2.charon3.core.utils.ResourceManagerUtil;
import org.wso2.charon3.core.utils.codeutils.ExpressionNode;
import org.wso2.charon3.core.utils.codeutils.Node;
import org.wso2.charon3.core.utils.codeutils.OperationNode;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.isFilterUsersAndGroupsOnlyFromPrimaryDomainEnabled;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.isFilteringEnhancementsEnabled;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.mandateDomainForGroupNamesInGroupsResponse;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.mandateDomainForUsernamesAndGroupNamesInResponse;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.prependDomain;

public class SCIMUserManager implements UserManager {

    private static final String FILTERING_DELIMITER = "*";
    private static final String SQL_FILTERING_DELIMITER = "%";
    private static final String ERROR_CODE_INVALID_USERNAME = "31301";
    private static final String ERROR_CODE_INVALID_CREDENTIAL = "30003";
    private static final String ERROR_CODE_INVALID_CREDENTIAL_DURING_UPDATE = "36001";
    private static final Log log = LogFactory.getLog(SCIMUserManager.class);
    private static final String ERROR_CODE_USER_NOT_FOUND = "30007";
    private AbstractUserStoreManager carbonUM;
    private ClaimManager carbonClaimManager;
    private String tenantDomain;
    private ClaimMetadataManagementService claimMetadataManagementService;
    private static final int MAX_ITEM_LIMIT_UNLIMITED = -1;
    private static final String ENABLE_PAGINATED_USER_STORE = "SCIM.EnablePaginatedUserStore";

    // Additional wso2 user schema properties.
    private static final String DISPLAY_NAME_PROPERTY = "displayName";
    private static final String DISPLAY_ORDER_PROPERTY = "displayOrder";
    private static final String REGULAR_EXPRESSION_PROPERTY = "regEx";

    @Deprecated
    public SCIMUserManager(UserStoreManager carbonUserStoreManager, ClaimManager claimManager) {
        carbonUM = (AbstractUserStoreManager) carbonUserStoreManager;
        carbonClaimManager = claimManager;
    }

    public SCIMUserManager(UserStoreManager carbonUserStoreManager,
                           ClaimMetadataManagementService claimMetadataManagementService, String tenantDomain) {

        this.carbonUM = (AbstractUserStoreManager) carbonUserStoreManager;
        this.tenantDomain = tenantDomain;
        this.claimMetadataManagementService = claimMetadataManagementService;
    }

    @Override
    public User createUser(User user, Map<String, Boolean> requiredAttributes)
            throws CharonException, ConflictException, BadRequestException {

        String userStoreName = null;
        try {
            String userStoreDomainFromSP = getUserStoreDomainFromSP();
            if (userStoreDomainFromSP != null) {
                userStoreName = userStoreDomainFromSP;
            }
        } catch (IdentityApplicationManagementException e) {
            throw new CharonException("Error retrieving User Store name. ", e);
        }

        StringBuilder userName = new StringBuilder();

        if (StringUtils.isNotBlank(userStoreName)) {

            // If we have set a user store under provisioning configuration - we should only use that.
            String currentUserName = user.getUserName();
            currentUserName = UserCoreUtil.removeDomainFromName(currentUserName);
            user.setUserName(userName.append(userStoreName)
                    .append(CarbonConstants.DOMAIN_SEPARATOR).append(currentUserName)
                    .toString());
        }

        String userStoreDomainName = IdentityUtil.extractDomainFromName(user.getUserName());
        if (!user.getUserName().contains(CarbonConstants.DOMAIN_SEPARATOR) &&
                !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(userStoreDomainName)) {
            user.setUserName(IdentityUtil.addDomainToName(user.getUserName(), userStoreDomainName));
        }

        if (StringUtils.isNotBlank(userStoreDomainName) && !isSCIMEnabled(userStoreDomainName)) {
            throw new CharonException("Cannot add user through scim to user store " + ". SCIM is not " +
                    "enabled for user store " + userStoreDomainName);
        }

        try {

            // Persist in carbon user store.
            if (log.isDebugEnabled()) {
                log.debug("Creating user: " + user.getUserName());
            }

            // Remove the existing SCIM id attribute as we are going to use the one generated from the user core.
            user.getAttributeList().remove(SCIMConstants.CommonSchemaConstants.ID);

            // Set thread local property to signal the downstream SCIMUserOperationListener
            // about the provisioning route.
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            Map<String, String> claimsMap = AttributeMapper.getClaimsMap(user);

            // Skip groups attribute since we map groups attribute to actual groups in ldap.
            // and do not update it as an attribute in user schema.
            claimsMap.remove(SCIMConstants.UserSchemaConstants.GROUP_URI);

            // Skip roles list since we map SCIM groups to local roles internally. It shouldn't be allowed to
            // manipulate SCIM groups from user endpoint as this attribute has a mutability of "readOnly". Group
            // changes must be applied via Group Resource.
            if (claimsMap.containsKey(SCIMConstants.UserSchemaConstants.ROLES_URI + "." + SCIMConstants.DEFAULT)) {
                claimsMap.remove(SCIMConstants.UserSchemaConstants.ROLES_URI);
            }

            // If we have the user id, we can check the user from it instead of username.
            boolean isExistingUser;
            if (StringUtils.isNotEmpty(user.getId())) {
                isExistingUser = carbonUM.isExistingUserWithID(user.getId());
            } else {
                isExistingUser = carbonUM.isExistingUser(user.getUserName());
            }

            if (isExistingUser) {
                String error = "User with the name: " + user.getUserName() + " already exists in the system.";
                throw new ConflictException(error);
            }

            claimsMap.remove(SCIMConstants.UserSchemaConstants.USER_NAME_URI);

            Map<String, String> claimsInLocalDialect = SCIMCommonUtils.convertSCIMtoLocalDialect(claimsMap);

            // Create the user in the user core.
            org.wso2.carbon.user.core.common.User coreUser = carbonUM.addUserWithID(user.getUserName(),
                    user.getPassword(), null, claimsInLocalDialect, null);

            // We use the generated unique ID of the user core user as the SCIM ID.
            user.setId(coreUser.getUserID());

            log.info("User: " + user.getUserName() + " and with ID " + user.getId() + "  is created through SCIM.");

            // Get Claims related to SCIM claim dialect
            Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();

            // Get required SCIM Claims in local claim dialect.
            List<String> requiredClaimsInLocalDialect = getRequiredClaimsInLocalDialect(scimToLocalClaimsMap,
                    requiredAttributes);

            // Get the user from the user store in order to get the default attributes during the user creation
            // response.
            user = this.getSCIMUser(coreUser, requiredClaimsInLocalDialect, scimToLocalClaimsMap, claimsInLocalDialect);

            // Set the schemas of the SCIM user.
            user.setSchemas();
        } catch (UserStoreException e) {
            handleErrorsOnUserNameAndPasswordPolicy(e);
            String errMsg = "Error in adding the user: " + user.getUserName() + " to the user store. ";
            throw new CharonException(errMsg, e);
        }
        return user;
    }

    private void handleErrorsOnUserNameAndPasswordPolicy(Throwable e) throws BadRequestException {

        int i = 0; // this variable is used to avoid endless loop if the e.getCause never becomes null.
        while (e != null && i < 10) {

            if (e instanceof UserStoreException && (e.getMessage().contains(ERROR_CODE_INVALID_USERNAME) ||
                    e.getMessage().contains(ERROR_CODE_INVALID_CREDENTIAL) || e.getMessage().contains
                    (ERROR_CODE_INVALID_CREDENTIAL_DURING_UPDATE))) {
                throw new BadRequestException(e.getMessage(), ResponseCodeConstants.INVALID_VALUE);
            }
            if (e instanceof PolicyViolationException) {
                throw new BadRequestException(e.getMessage(), ResponseCodeConstants.INVALID_VALUE);
            }
            e = e.getCause();
            i++;
        }
    }

    @Override
    public User getUser(String userId, Map<String, Boolean> requiredAttributes) throws CharonException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving user: " + userId);
        }
        User scimUser;
        try {
            //get the user name of the user with this id
            String userIdLocalClaim = SCIMCommonUtils.getSCIMtoLocalMappings().get(SCIMConstants
                    .CommonSchemaConstants.ID_URI);
            org.wso2.carbon.user.core.common.User coreUser = null;
            if (StringUtils.isNotBlank(userIdLocalClaim)) {
                coreUser = carbonUM.getUserWithID(userId, null, UserCoreConstants.DEFAULT_PROFILE);
            }

            if (coreUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug("User with SCIM id: " + userId + " does not exist in the system.");
                }
                return null;
            } else {
                //get Claims related to SCIM claim dialect
                Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
                List<String> requiredClaimsInLocalDialect = getRequiredClaimsInLocalDialect(scimToLocalClaimsMap,
                        requiredAttributes);
                //we assume (since id is unique per user) only one user exists for a given id
                scimUser = this.getSCIMUser(coreUser, requiredClaimsInLocalDialect, scimToLocalClaimsMap, null);
                //set the schemas of the scim user
                scimUser.setSchemas();
                log.info("User: " + scimUser.getUserName() + " is retrieved through SCIM.");
            }

        } catch (UserStoreException e) {
            if (e.getMessage().contains(ERROR_CODE_USER_NOT_FOUND)) {
                if (log.isDebugEnabled()) {
                    log.debug("User with SCIM id: " + userId + " does not exist in the system.");
                }
                return null;
            } else {
                throw new CharonException("Error in getting user information from Carbon User Store for" +
                        "user: " + userId, e);
            }
        }
        return scimUser;
    }

    @Override
    public void deleteUser(String userId) throws NotFoundException, CharonException {

        if (log.isDebugEnabled()) {
            log.debug("Deleting user: " + userId);
        }
        //get the user name of the user with this id
        org.wso2.carbon.user.core.common.User coreUser = null;
        String userName = null;
        try {

            // Set thread local property to signal the downstream SCIMUserOperationListener
            // about the provisioning route.
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            String userIdLocalClaim = SCIMCommonUtils.getSCIMtoLocalMappings().get(SCIMConstants
                    .CommonSchemaConstants.ID_URI);

            if (StringUtils.isNotBlank(userIdLocalClaim)) {
                // We cannot use getUserWithID because it throws exception when the user cannot be found.
                // (Generic user store exception). If we can send a specific user not found exception in user core level
                // we can use that method.
                List<org.wso2.carbon.user.core.common.User> coreUsers = carbonUM.getUserListWithID(userIdLocalClaim,
                        userId, UserCoreConstants.DEFAULT_PROFILE);
                if (coreUsers.size() > 0) {
                    coreUser = coreUsers.get(0);
                }
            }

            String userStoreDomainFromSP = null;
            try {
                userStoreDomainFromSP = getUserStoreDomainFromSP();
            } catch (IdentityApplicationManagementException e) {
                throw new CharonException("Error retrieving User Store name. ", e);
            }

            if (coreUser == null) {
                // Resource with given id not found
                if (log.isDebugEnabled()) {
                    log.debug("User with id: " + userId + " not found.");
                }
                throw new NotFoundException();
            } else if (userStoreDomainFromSP != null &&
                    !(userStoreDomainFromSP
                            .equalsIgnoreCase(coreUser.getUserStoreDomain()))) {
                throw new CharonException("User :" + coreUser.getUsername() + "is not belong to user store " +
                        userStoreDomainFromSP + "Hence user updating fail");
            } else {
                // We assume (since id is unique per user) only one user exists for a given id.
                userName = coreUser.getUsername();
                String userStoreDomainName = coreUser.getUserStoreDomain();

                // Check if SCIM is enabled for the user store.
                if (!isSCIMEnabled(userStoreDomainName)) {
                    throw new CharonException("Cannot delete user: " + userName + " through SCIM from user store: " +
                            userStoreDomainName + ". SCIM is not enabled for user store: " + userStoreDomainName);
                }
                carbonUM.deleteUserWithID(coreUser.getUserID());
                log.info("User: " + userName + " is deleted through SCIM.");
            }

        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException("Error in deleting user: " + userName, e);
        }
    }

    @Override
    @Deprecated
    public List<Object> listUsersWithGET(Node rootNode, int startIndex, int count, String sortBy, String sortOrder,
                                         String domainName, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException {

        if (sortBy != null || sortOrder != null) {
            throw new NotImplementedException("Sorting is not supported");
        } else if (rootNode != null) {
            return filterUsers(rootNode, requiredAttributes, startIndex, count, sortBy, sortOrder, domainName);
        } else {
            return listUsers(requiredAttributes, startIndex, count, sortBy, sortOrder, domainName);
        }
    }

    @Override
    public List<Object> listUsersWithGET(Node rootNode, Integer startIndex, Integer count, String sortBy,
                                         String sortOrder, String domainName, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException {

        // Validate NULL value for startIndex.
        startIndex = handleStartIndexEqualsNULL(startIndex);
        if (sortBy != null || sortOrder != null) {
            throw new NotImplementedException("Sorting is not supported");
        } else if (count != null && count == 0) {
            return Collections.emptyList();
        } else if (rootNode != null) {
            return filterUsers(rootNode, requiredAttributes, startIndex, count, sortBy, sortOrder, domainName);
        } else {
            return listUsers(requiredAttributes, startIndex, count, sortBy, sortOrder, domainName);
        }
    }

    @Override
    public List<Object> listUsersWithPost(SearchRequest searchRequest, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {

        return listUsersWithGET(searchRequest.getFilter(), (Integer)searchRequest.getStartIndex(),
                (Integer)searchRequest.getCount(), searchRequest.getSortBy(), searchRequest.getSortOder(),
                searchRequest.getDomainName(), requiredAttributes);
    }

    /**
     * Method to list users for given conditions.
     *
     * @param requiredAttributes Required attributes for the response
     * @param offset             Starting index of the count
     * @param limit              Counting value
     * @param sortBy             SortBy
     * @param sortOrder          Sorting order
     * @param domainName         Name of the user store
     * @return User list with detailed attributes
     * @throws CharonException Error while listing users
     */
    private List<Object> listUsers(Map<String, Boolean> requiredAttributes, int offset, Integer limit,
                                   String sortBy, String sortOrder, String domainName) throws CharonException {

        List<Object> users = new ArrayList<>();
        // 0th index is to store total number of results.
        users.add(0);

        // Handle limit equals NULL scenario.
        limit = handleLimitEqualsNULL(limit);
        Set<org.wso2.carbon.user.core.common.User> coreUsers;
        if (StringUtils.isNotEmpty(domainName)) {
            if (canPaginate(offset, limit)) {
                coreUsers = listUsernames(offset, limit, sortBy, sortOrder, domainName);
            } else {
                coreUsers = listUsernamesUsingLegacyAPIs(domainName);
            }
        } else {
            if (canPaginate(offset, limit)) {
                coreUsers = listUsernamesAcrossAllDomains(offset, limit, sortBy, sortOrder);
            } else {
                coreUsers = listUsernamesAcrossAllDomainsUsingLegacyAPIs();
            }
        }

        if (coreUsers.isEmpty()) {
            if (log.isDebugEnabled()) {
                String message = String.format("There are no users who comply with the requested conditions: "
                        + "startIndex = %d, count = %d", offset, limit);
                if (StringUtils.isNotEmpty(domainName)) {
                    message = String.format(message + ", domain = %s", domainName);
                }
                log.debug(message);
            }
        } else {
            List<Object> scimUsers = getUserDetails(coreUsers, requiredAttributes);
            users.set(0, scimUsers.size()); // Set total number of results to 0th index.
            users.addAll(scimUsers); // Set user details from index 1.
        }
        return users;
    }

    /**
     * Method to decide whether to paginate based on the offset and the limit in the request.
     *
     * @param offset Starting index of the count
     * @param limit  Counting value
     * @return true if pagination is possible, false otherwise
     */
    private boolean canPaginate(int offset, int limit) {

        return (offset != 1 || limit != 0);
    }

    /**
     * Method to list paginated usernames from a specific user store using new APIs.
     *
     * @param offset     Starting index of the count
     * @param limit      Counting value
     * @param sortBy     SortBy
     * @param sortOrder  Sorting order
     * @param domainName Name of the user store
     * @return Paginated usernames list
     * @throws CharonException Error while listing usernames
     */
    private Set<org.wso2.carbon.user.core.common.User> listUsernames(int offset, int limit, String sortBy,
                                                                     String sortOrder, String domainName)
            throws CharonException {

        if (isPaginatedUserStoreAvailable()) {
            if (limit == 0) {
                limit = getMaxLimit(domainName);
            }
            // Operator SW set with USERNAME and empty string to get all users.
            ExpressionCondition exCond = new ExpressionCondition(ExpressionOperation.SW.toString(),
                    ExpressionAttribute.USERNAME.toString(), "");
            return filterUsernames(exCond, offset, limit, sortBy, sortOrder, domainName);
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format(
                        "%s is not an instance of PaginatedUserStoreManager. Therefore pagination is not supported.",
                        domainName));
            }
            throw new CharonException(String.format("Pagination is not supported for %s.", domainName));
        }
    }

    /**
     * Method to list usernames of all users from a specific user store using legacy APIs.
     *
     * @param domainName Name of the user store
     * @return Usernames list
     * @throws CharonException Error while listing usernames
     */
    private Set<org.wso2.carbon.user.core.common.User> listUsernamesUsingLegacyAPIs(String domainName)
            throws CharonException {

        Set<org.wso2.carbon.user.core.common.User> users = null;
        try {
            Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
            String userIdLocalClaim = scimToLocalClaimsMap.get(SCIMConstants.CommonSchemaConstants.ID_URI);
            String claimValue = domainName.toUpperCase() + CarbonConstants.DOMAIN_SEPARATOR + SCIMCommonConstants.ANY;
            if (StringUtils.isNotBlank(userIdLocalClaim)) {
                users = new TreeSet<>(Comparator
                        .comparing(org.wso2.carbon.user.core.common.User::getFullQualifiedUsername));
                users.addAll(carbonUM.getUserListWithID(userIdLocalClaim, claimValue, null));
            }
            return users;
        } catch (UserStoreException e) {
            throw new CharonException(String.format("Error while listing usernames from domain: %s.", domainName), e);
        }
    }

    /**
     * Method to list paginated usernames from all user stores using new APIs.
     *
     * @param offset    Starting index of the count
     * @param limit     Counting value
     * @param sortBy    SortBy
     * @param sortOrder Sorting order
     * @return Paginated usernames list
     * @throws CharonException Pagination not support
     */
    private Set<org.wso2.carbon.user.core.common.User> listUsernamesAcrossAllDomains(int offset, int limit,
                                                                                     String sortBy, String sortOrder)
            throws CharonException {

        Set<org.wso2.carbon.user.core.common.User> users;
        if (isPaginatedUserStoreAvailable()) {
            if (limit == 0) {
                users = listUsernamesAcrossAllDomainsUsingLegacyAPIs();
                users = new TreeSet<>(paginateUsers(users, limit, offset));
            } else {
                ExpressionCondition condition = new ExpressionCondition(ExpressionOperation.SW.toString(),
                        ExpressionAttribute.USERNAME.toString(), "");
                users = filterUsersFromMultipleDomains(null, offset, limit, sortBy, sortOrder, condition);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(" The user store is not a paginated user store manager. Therefore pagination "
                        + "is not supported.");
            }
            throw new CharonException("Pagination is not supported.");
        }
        return users;
    }

    /**
     * Method to list usernames of all users across all user stores using legacy APIs.
     *
     * @return Usernames list
     * @throws CharonException Error while listing usernames
     */
    private Set<org.wso2.carbon.user.core.common.User> listUsernamesAcrossAllDomainsUsingLegacyAPIs()
            throws CharonException {

        Set<org.wso2.carbon.user.core.common.User> users = null;
        try {
            Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
            String userIdLocalClaim = scimToLocalClaimsMap.get(SCIMConstants.CommonSchemaConstants.ID_URI);
            if (StringUtils.isNotBlank(userIdLocalClaim)) {
                users = new TreeSet<>(Comparator
                        .comparing(org.wso2.carbon.user.core.common.User::getFullQualifiedUsername));
                users.addAll(carbonUM.getUserListWithID(userIdLocalClaim, SCIMCommonConstants.ANY, null));
            }
            return users;
        } catch (UserStoreException e) {
            throw new CharonException("Error while listing users across all domains. ", e);
        }
    }

    /**
     * Method to get user details of usernames.
     *
     * @param coreUsers          Array of usernames
     * @param requiredAttributes Required attributes for the response
     * @return User list with detailed attributes
     * @throws CharonException Error while retrieving users
     */
    private List<Object> getUserDetails(Set<org.wso2.carbon.user.core.common.User> coreUsers,
                                        Map<String, Boolean> requiredAttributes)
            throws CharonException {

        List<Object> users = new ArrayList<>();
        try {
            Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
            List<String> requiredClaims = getOnlyRequiredClaims(scimToLocalClaimsMap.keySet(), requiredAttributes);
            List<String> requiredClaimsInLocalDialect;
            if (MapUtils.isNotEmpty(scimToLocalClaimsMap)) {
                scimToLocalClaimsMap.keySet().retainAll(requiredClaims);
                requiredClaimsInLocalDialect = new ArrayList<>(scimToLocalClaimsMap.values());
            } else {
                requiredClaimsInLocalDialect = new ArrayList<>();
            }

            Set<User> scimUsers;
            if (isPaginatedUserStoreAvailable()) {
                // Retrieve all SCIM users at once.
                scimUsers = this.getSCIMUsers(coreUsers, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                users.addAll(scimUsers);
            } else {
                // Retrieve SCIM users one by one.
                retriveSCIMUsers(users, coreUsers, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
            }
        } catch (UserStoreException e) {
            throw new CharonException("Error while retrieving users from user store.", e);
        }
        return users;
    }

    private void retriveSCIMUsers(List<Object> users, Set<org.wso2.carbon.user.core.common.User> coreUsers,
                                  List<String> requiredClaims, Map<String, String> scimToLocalClaimsMap)
            throws CharonException {

        for (org.wso2.carbon.user.core.common.User coreUser : coreUsers) {

            if (coreUser.getUsername().contains(UserCoreConstants.NAME_COMBINER)) {
                coreUser.setUsername(coreUser.getUsername().split("\\" + UserCoreConstants.NAME_COMBINER)[0]);
            }

            String userStoreDomainName = coreUser.getUserStoreDomain();
            if (isSCIMEnabled(userStoreDomainName)) {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". "
                            + "Including user : " + coreUser.getUsername() + " in the response.");
                }

                User scimUser = this.getSCIMUser(coreUser, requiredClaims, scimToLocalClaimsMap, null);
                if (scimUser != null) {
                    Map<String, Attribute> attrMap = scimUser.getAttributeList();
                    if (attrMap != null && !attrMap.isEmpty()) {
                        users.add(scimUser);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". "
                            + "Hence user : " + coreUser.getUsername()
                            + " in this domain is excluded in the response.");
                }
            }
        }
    }

    @Override
    public User updateUser(User user, Map<String, Boolean> requiredAttributes) throws CharonException,
            BadRequestException {

        try {
            if (log.isDebugEnabled()) {
                log.debug("Updating user: " + user.getUserName());
            }

            // Set thread local property to signal the downstream SCIMUserOperationListener
            // about the provisioning route.
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            //get user claim values
            Map<String, String> claims = AttributeMapper.getClaimsMap(user);

            // Check if username of the updating user existing in the userstore.
            try {
                String userStoreDomainFromSP = getUserStoreDomainFromSP();
                SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
                User oldUser = this.getUser(user.getId(), ResourceManagerUtil.getAllAttributeURIs(schema));
                if (userStoreDomainFromSP != null && !userStoreDomainFromSP
                        .equalsIgnoreCase(IdentityUtil.extractDomainFromName(oldUser.getUserName()))) {
                    throw new CharonException("User :" + oldUser.getUserName() + "is not belong to user store " +
                            userStoreDomainFromSP + "Hence user updating fail");
                }
                if (getUserStoreDomainFromSP() != null &&
                        !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(getUserStoreDomainFromSP())) {
                    user.setUserName(IdentityUtil
                            .addDomainToName(UserCoreUtil.removeDomainFromName(user.getUserName()),
                                    getUserStoreDomainFromSP()));
                }
            } catch (IdentityApplicationManagementException e) {
                throw new CharonException("Error retrieving User Store name. ", e);
            }

            boolean isExistingUser;
            if (StringUtils.isNotEmpty(user.getId())) {
                isExistingUser = carbonUM.isExistingUserWithID(user.getId());
            } else {
                isExistingUser = carbonUM.isExistingUser(user.getUserName());
            }

            if (!isExistingUser) {
                throw new CharonException("User name is immutable in carbon user store.");
            }

            // Skip groups attribute since we map groups attribute to actual groups in ldap.
            // and do not update it as an attribute in user schema.
            claims.remove(SCIMConstants.UserSchemaConstants.GROUP_URI);

            // Skip roles list since we map SCIM groups to local roles internally. It shouldn't be allowed to
            // manipulate SCIM groups from user endpoint as this attribute has a mutability of "readOnly". Group
            // changes must be applied via Group Resource.
            if (claims.containsKey(SCIMConstants.UserSchemaConstants.ROLES_URI + "." + SCIMConstants.DEFAULT)) {
                claims.remove(SCIMConstants.UserSchemaConstants.ROLES_URI);
            }

            claims.remove(SCIMConstants.UserSchemaConstants.USER_NAME_URI);

            // Since we are already populating last_modified claim value from SCIMUserOperationListener, we need to
            // remove this claim value which is coming from charon-level.
            if (claims.containsKey(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI)) {
                claims.remove(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI);
            }

            // Location is a meta attribute of user object.
            if (claims.containsKey(SCIMConstants.CommonSchemaConstants.LOCATION)) {
                claims.remove(SCIMConstants.CommonSchemaConstants.LOCATION);
            }

            // Resource-Type is a meta attribute of user object.
            if (claims.containsKey(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE)) {
                claims.remove(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE);
            }

            Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
            List<String> requiredClaims = getOnlyRequiredClaims(scimToLocalClaimsMap.keySet(), requiredAttributes);
            List<String> requiredClaimsInLocalDialect;
            if (MapUtils.isNotEmpty(scimToLocalClaimsMap)) {
                scimToLocalClaimsMap.keySet().retainAll(requiredClaims);
                requiredClaimsInLocalDialect = new ArrayList<>(scimToLocalClaimsMap.values());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM to Local Claim mappings list is empty.");
                }
                requiredClaimsInLocalDialect = new ArrayList<>();
            }

            // Get existing user claims.
            Map<String, String> oldClaimList = carbonUM.getUserClaimValuesWithID(user.getId(),
                    requiredClaimsInLocalDialect.toArray(new String[0]), null);

            // Get user claims mapped from SCIM dialect to WSO2 dialect.
            Map<String, String> claimValuesInLocalDialect = SCIMCommonUtils.convertSCIMtoLocalDialect(claims);

            updateUserClaims(user, oldClaimList, claimValuesInLocalDialect);

            // If password is updated, set it separately.
            if (user.getPassword() != null) {
                carbonUM.updateCredentialByAdminWithID(user.getId(), user.getPassword());
            }
            log.info("User: " + user.getUserName() + " updated through SCIM.");
            return getUser(user.getId(), requiredAttributes);
        } catch (UserStoreException e) {
            log.error("Error while updating attributes of user: " + user.getUserName(), e);
            handleErrorsOnUserNameAndPasswordPolicy(e);
            throw new CharonException("Error while updating attributes of user: " + user.getUserName(), e);
        } catch (BadRequestException | CharonException e) {
            log.error("Error occurred while trying to update the user", e);
            throw new CharonException("Error occurred while trying to update the user", e);
        }
    }

    /**
     * Method to handle limit equals NULL in a request.
     *
     * @param limit Limit in the request.
     * @return Updated limit.
     */
    private int handleLimitEqualsNULL(Integer limit) {

        // Limit equal to null implies return all users. Return all users scenario handled by the following methods by
        // expecting count as zero.
        if (limit == null) {
            limit = 0;
        }
        return limit;
    }

    /**
     * Filter users using multi-attribute filters or single attribute filters with pagination.
     *
     * @param node               Filter condition tree.
     * @param requiredAttributes Required attributes.
     * @param offset             Starting index of the count.
     * @param limit              Number of required results (count).
     * @param sortBy             SortBy.
     * @param sortOrder          Sort order.
     * @param domainName         Domain that the filter should perform.
     * @return Detailed user list.
     * @throws CharonException Error filtering the users.
     */
    private List<Object> filterUsers(Node node, Map<String, Boolean> requiredAttributes, int offset, Integer limit,
                                     String sortBy, String sortOrder, String domainName) throws CharonException {

        // Handle limit equals NULL scenario.
        limit = handleLimitEqualsNULL(limit);

        // Handle single attribute search.
        if (node instanceof ExpressionNode) {
            return filterUsersBySingleAttribute((ExpressionNode) node, requiredAttributes, offset, limit, sortBy,
                    sortOrder, domainName);
        } else if (node instanceof OperationNode) {
            if (log.isDebugEnabled()) {
                log.debug("Listing users by multi attribute filter");
            }

            // Support multi attribute filtering.
            return getMultiAttributeFilteredUsers(node, requiredAttributes, offset, limit, sortBy, sortOrder,
                    domainName);
        } else {
            throw new CharonException("Unknown operation. Not either an expression node or an operation node.");
        }
    }

    /**
     * Method to filter users for a filter with a single attribute.
     *
     * @param node               Expression node for single attribute filtering
     * @param requiredAttributes Required attributes for the response
     * @param offset             Starting index of the count
     * @param limit              Counting value
     * @param sortBy             SortBy
     * @param sortOrder          Sorting order
     * @param domainName         Domain to run the filter
     * @return User list with detailed attributes
     * @throws CharonException Error while filtering
     */
    private List<Object> filterUsersBySingleAttribute(ExpressionNode node, Map<String, Boolean> requiredAttributes,
                                                      int offset, int limit, String sortBy, String sortOrder,
                                                      String domainName) throws CharonException {

        Set<org.wso2.carbon.user.core.common.User> users;

        if (log.isDebugEnabled()) {
            log.debug(String.format("Listing users by filter: %s %s %s", node.getAttributeValue(), node.getOperation(),
                    node.getValue()));
        }
        // Check whether the filter operation is supported by the users endpoint.
        if (isFilteringNotSupported(node.getOperation())) {
            String errorMessage =
                    "Filter operation: " + node.getOperation() + " is not supported for filtering in users endpoint.";
            throw new CharonException(errorMessage);
        }
        domainName = resolveDomainName(domainName, node);
        try {
            // Check which APIs should the filter needs to follow.
            if (isUseLegacyAPIs(limit)) {
                users = filterUsersUsingLegacyAPIs(node, limit, offset, domainName);
            } else {
                users = filterUsers(node, offset, limit, sortBy, sortOrder, domainName);
            }
        } catch (NotImplementedException e) {
            String errorMessage = String.format("System does not support filter operator: %s", node.getOperation());
            throw new CharonException(errorMessage, e);
        }

        return getDetailedUsers(users, requiredAttributes);
    }

    /**
     * Method to resolve the domain name.
     *
     * @param domainName Domain to run the filter
     * @param node       Expression node for single attribute filtering
     * @return Resolved domainName
     * @throws CharonException
     */
    private String resolveDomainName(String domainName, ExpressionNode node) throws CharonException {

        try {
            // Extract the domain name if the domain name is embedded in the filter attribute value.
            domainName = resolveDomainNameInAttributeValue(domainName, node);
        } catch (BadRequestException e) {
            String errorMessage = String
                    .format("Domain parameter: %s in request does not match with the domain name in the attribute "
                            + "value: %s ", domainName, node.getValue());
            throw new CharonException(errorMessage, e);
        }
        // Get domain name according to Filter Enhancements properties as in identity.xml
        if (StringUtils.isEmpty(domainName)) {
            domainName = getFilteredDomainName(node);
        }
        return domainName;
    }

    /**
     * Method to decide whether to use new APIs or legacy APIs.
     *
     * @param limit Number of results required for the filter request (limit equals to ZERO will retrieve all users
     *              who matches the filter).
     * @return True if legacy API filtering is needed.
     */
    private boolean isUseLegacyAPIs(int limit) {

        // If the limit is not specified, list all the users using old APIs since the new APIs must have a
        // limit larger than zero.
        if (limit <= 0) {
            return true;
        } else if (!isPaginatedUserStoreAvailable() && !(carbonUM instanceof PaginatedUserStoreManager)) {

            // If the userStore does not support above conditions, filter should use old APIs.
            return true;
        }
        return false;
    }

    /**
     * Validate whether filter enhancements are enabled and then return primary default domain name as the domain to
     * be filtered.
     *
     * @param node Expression node
     * @return PRIMARY domainName if property enabled, Null otherwise.
     */
    private String getFilteredDomainName(ExpressionNode node) {

        // Set filter values.
        String attributeName = node.getAttributeValue();
        String filterOperation = node.getOperation();
        String attributeValue = node.getValue();

        if ((isFilterUsersAndGroupsOnlyFromPrimaryDomainEnabled()) && !StringUtils
                .contains(attributeValue, CarbonConstants.DOMAIN_SEPARATOR)) {
            return UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

        } else if (isFilteringEnhancementsEnabled()) {
            if (SCIMCommonConstants.EQ.equalsIgnoreCase(filterOperation)) {
                if (StringUtils.equals(attributeName, SCIMConstants.UserSchemaConstants.USER_NAME_URI) && !StringUtils
                        .contains(attributeValue, CarbonConstants.DOMAIN_SEPARATOR)) {
                    return UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
                }
            }
        }
        return null;
    }

    /**
     * Update the domain parameter from the domain in attribute value and update the value in the expression node to the
     * newly extracted value.
     *
     * @param domainName Domain name in the filter request
     * @param node       Expression node
     * @return Domain name extracted from the attribute value
     * @throws BadRequestException Domain miss match in domain parameter and attribute value
     */
    private String resolveDomainNameInAttributeValue(String domainName, ExpressionNode node)
            throws BadRequestException {

        String extractedDomain;
        String attributeName = node.getAttributeValue();
        String filterOperation = node.getOperation();
        String attributeValue = node.getValue();

        if (isDomainNameEmbeddedInAttributeValue(filterOperation, attributeName, attributeValue)) {
            int indexOfDomainSeparator = attributeValue.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
            extractedDomain = attributeValue.substring(0, indexOfDomainSeparator).toUpperCase();

            // Update then newly extracted attribute value in the expression node.
            int startingIndexOfAttributeValue = indexOfDomainSeparator + 1;
            node.setValue(attributeValue.substring(startingIndexOfAttributeValue));

            // Check whether the domain name is equal to the extracted domain name from attribute value.
            if (StringUtils.isNotEmpty(domainName) && StringUtils.isNotEmpty(extractedDomain) && !extractedDomain
                    .equalsIgnoreCase(domainName))
                throw new BadRequestException(String.format(
                        " Domain name %s in the domain parameter does not match with the domain name %s in search "
                                + "attribute value of %s claim.", domainName, extractedDomain, attributeName));

            if (StringUtils.isEmpty(domainName) && StringUtils.isNotEmpty(extractedDomain)) {
                if (log.isDebugEnabled())
                    log.debug(String.format("Domain name %s set from the domain name in the attribute value %s ",
                            extractedDomain, attributeValue));
                return extractedDomain;
            }
        }
        return domainName;
    }

    /**
     * Method to verify whether there is a domain in the attribute value.
     *
     * @param filterOperation Operation of the expression node
     * @param attributeName   Attribute name of the expression node
     * @param attributeValue  Value of the expression node
     * @return Whether there is a domain embedded to the attribute value
     */
    private boolean isDomainNameEmbeddedInAttributeValue(String filterOperation, String attributeName,
                                                         String attributeValue) {

        // Checks whether the domain separator is in the attribute value.
        if (StringUtils.contains(attributeValue, CarbonConstants.DOMAIN_SEPARATOR)) {

            // Checks whether the attribute name is username or group uri.
            if (StringUtils.equals(attributeName, SCIMConstants.UserSchemaConstants.USER_NAME_URI) || StringUtils
                    .equals(attributeName, SCIMConstants.UserSchemaConstants.GROUP_URI)) {

                // Checks whether the operator is equal to EQ, SW, EW, CO.
                if (SCIMCommonConstants.EQ.equalsIgnoreCase(filterOperation) || SCIMCommonConstants.SW
                        .equalsIgnoreCase(filterOperation) || SCIMCommonConstants.CO.equalsIgnoreCase(filterOperation)
                        || SCIMCommonConstants.EW.equalsIgnoreCase(filterOperation)) {

                    if (log.isDebugEnabled())
                        log.debug(String.format("Attribute value %s is embedded with a domain in %s claim, ",
                                attributeValue, attributeName));
                    // If all the above conditions are true, then a domain is embedded to the attribute value.
                    return true;
                }
            }
        }
        // If no domain name in the attribute value, return false.
        return false;
    }

    /**
     * Method to get users when a filter is used with a single attribute and when the user store is an instance of
     * PaginatedUserStoreManager since the filter API supports an instance of PaginatedUserStoreManager.
     *
     * @param node       Expression or Operation node
     * @param offset     Start index value
     * @param limit      Count value
     * @param sortBy     SortBy
     * @param sortOrder  Sort order
     * @param domainName Domain to perform the search
     * @return User names of the filtered users
     * @throws CharonException Error while filtering
     */
    private Set<org.wso2.carbon.user.core.common.User> filterUsers(Node node, int offset, int limit, String sortBy,
                                                                   String sortOrder, String domainName)
            throws CharonException {

        // Filter users when the domain is specified in the request.
        if (StringUtils.isNotEmpty(domainName)) {
            return filterUsernames(createConditionForSingleAttributeFilter(domainName, node), offset, limit,
                    sortBy, sortOrder, domainName);
        } else {
            return filterUsersFromMultipleDomains(node, offset, limit, sortBy, sortOrder, null);
        }
    }

    /**
     * Method to perform a multiple domain search when the domain is not specified in the request. The same function
     * can be used to listing users by passing a condition for conditionForListingUsers parameter.
     *
     * @param node                     Expression or Operation node (set the value to null when method is used for
     *                                 list users)
     * @param offset                   Start index value
     * @param limit                    Count value
     * @param sortBy                   SortBy
     * @param sortOrder                Sort order
     * @param conditionForListingUsers Condition for listing users when the function is used to list users except for
     *                                 filtering. For filtering this value should be set to NULL.
     * @return User names of the filtered users
     */
    private Set<org.wso2.carbon.user.core.common.User> filterUsersFromMultipleDomains(Node node, int offset, int limit,
                                                                                      String sortBy, String sortOrder,
                                                                                      Condition
                                                                                              conditionForListingUsers)
            throws CharonException {

        // Filter users when the domain is not set in the request. Then filter through multiple domains.
        String[] userStoreDomainNames = getDomainNames();
        Set<org.wso2.carbon.user.core.common.User> filteredUsernames = new TreeSet<>(Comparator
                .comparing(org.wso2.carbon.user.core.common.User::getFullQualifiedUsername));
        Condition condition;
        for (String userStoreDomainName : userStoreDomainNames) {

            // Check for a user listing scenario. (For filtering this value will be set to NULL)
            if (conditionForListingUsers == null) {

                // Create filter condition for each domain for single attribute filter.
                condition = createConditionForSingleAttributeFilter(userStoreDomainName, node);
            } else {
                condition = conditionForListingUsers;
            }

            // Filter users for given condition and domain.
            Set<org.wso2.carbon.user.core.common.User> coreUsers =
                    filterUsernames(condition, offset, limit, sortBy, sortOrder, userStoreDomainName);

            // Calculating new offset and limit parameters.
            int numberOfFilteredUsers = coreUsers.size();
            if (numberOfFilteredUsers <= 0 && offset > 1) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Filter returned no results for original offset: %d.", offset));
                }
                offset = calculateOffset(condition, offset, sortBy, sortOrder, userStoreDomainName);
            } else {
                // Returned user names size > 0 implies there are users in that domain which is larger than
                // the offset.
                offset = 1;
                limit = calculateLimit(limit, numberOfFilteredUsers);
            }
            filteredUsernames.addAll(coreUsers);

            // If the limit is changed then filtering needs to be stopped.
            if (limit == 0) {
                break;
            }
        }
        return filteredUsernames;
    }

    /**
     * Method to update the count(limit) when iterating a filter across all domains.
     *
     * @param limit                 Counting value (limit)
     * @param numberOfFilteredUsers Amount of users filtered in the search
     * @return Calculated new limit (count)
     */
    private int calculateLimit(int limit, int numberOfFilteredUsers) {

        int newLimit = limit - numberOfFilteredUsers;
        if (limit < 0) {
            newLimit = 0;
        }

        if (log.isDebugEnabled()) {
            log.debug(String.format("New limit: %d calculated using initial offset: %d and filtered user count: %d. ",
                    newLimit, limit, numberOfFilteredUsers));
        }
        return newLimit;
    }

    /**
     * Method to update the offset when iterating a filter across all domains.
     *
     * @param condition  Condition of the single attribute filter
     * @param offset     Starting index
     * @param sortBy     Sort by
     * @param sortOrder  Sort order
     * @param domainName Domain to be filtered
     * @return New calculated offset
     * @throws CharonException Error while filtering the domain from index 1 to offset
     */
    private int calculateOffset(Condition condition, int offset, String sortBy, String sortOrder, String domainName)
            throws CharonException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Checking for number of matches from the beginning to the original offset: %d for "
                    + "the same filter and updating the new offset.", offset));
        }
        // Starting index of the filter
        int initialOffset = 1;

        // Checking the number of matches till the original offset.
        int skippedUserCount;
        Set<org.wso2.carbon.user.core.common.User> skippedUsers =
                filterUsernames(condition, initialOffset, offset, sortBy, sortOrder, domainName);

        skippedUserCount = skippedUsers.size();

        // Calculate the new offset and return
        return offset - skippedUserCount;
    }

    /**
     * Method to get users when a filter domain is known.
     *
     * @param condition  Condition of the single attribute filter
     * @param offset     Start index value
     * @param limit      Count value
     * @param sortBy     SortBy
     * @param sortOrder  Sort order
     * @param domainName Domain to perform the search
     * @return User names of the filtered users
     * @throws CharonException Error while filtering
     */
    private Set<org.wso2.carbon.user.core.common.User> filterUsernames(Condition condition, int offset, int limit,
                                                                       String sortBy, String sortOrder,
                                                                       String domainName) throws CharonException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Filtering users in domain : %s with limit: %d and offset: %d.", domainName, limit,
                    offset));
        }
        try {
            Set<org.wso2.carbon.user.core.common.User> users = new TreeSet<>(Comparator
                    .comparing(org.wso2.carbon.user.core.common.User::getFullQualifiedUsername));
            users.addAll(carbonUM
                    .getUserListWithID(condition, domainName, UserCoreConstants.DEFAULT_PROFILE, limit, offset, sortBy,
                            sortOrder));
            return users;
        } catch (UserStoreException e) {
            String errorMessage = String
                    .format("Error while retrieving users for the domain: %s with limit: %d and offset: %d.",
                            domainName, limit, offset);
            throw new CharonException(errorMessage, e);
        }
    }

    /**
     * Method is to create a condition for a single attribute filter when the node and the domain name is passed.
     *
     * @param domainName Domain name of the user store to be filtered
     * @param node       Node of the single attribute filter
     * @return Condition for the single attribute filter
     * @throws CharonException
     */
    private Condition createConditionForSingleAttributeFilter(String domainName, Node node) throws CharonException {

        if (log.isDebugEnabled()) {
            log.debug("Creating condition for domain : " + domainName);
        }

        Map<String, String> attributes;
        try {
            attributes = getAllAttributes(domainName);
        } catch (CharonException e) {
            String errorMessage = String.format("Error while retrieving attributes for the domain %s.", domainName);
            throw new CharonException(errorMessage, e);
        }
        return getCondition(node, attributes);
    }

    /**
     * Get all the domain names related to user stores.
     *
     * @return A list of all the available domain names
     */
    private String[] getDomainNames() {

        String domainName;
        ArrayList<String> domainsOfUserStores = new ArrayList<>();
        UserStoreManager secondaryUserStore = carbonUM.getSecondaryUserStoreManager();
        while (secondaryUserStore != null) {
            domainName = secondaryUserStore.getRealmConfiguration().
                    getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME).toUpperCase();
            secondaryUserStore = secondaryUserStore.getSecondaryUserStoreManager();
            domainsOfUserStores.add(domainName);
        }
        // Sorting the secondary user stores to maintain an order fo domains so that pagination is consistent.
        Collections.sort(domainsOfUserStores);

        // Append the primary domain name to the front of the domain list since the first iteration of multiple
        // domain filtering should happen for the primary user store.
        domainsOfUserStores.add(0, UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        return domainsOfUserStores.toArray(new String[0]);
    }

    /**
     * Method to filter users if the user store is not an instance of PaginatedUserStoreManager and
     * ENABLE_PAGINATED_USER_STORE is not enabled.
     *
     * @param node   Expression node
     * @param limit  Number of users required for counting
     * @param offset Starting user index for start counting
     * @return List of paginated set of users.
     * @throws NotImplementedException Not supported filter operation
     * @throws UserStoreException
     */
    private Set<org.wso2.carbon.user.core.common.User> filterUsersUsingLegacyAPIs(ExpressionNode node, int limit,
                                                                                  int offset, String domainName)
            throws NotImplementedException, CharonException {

        Set<org.wso2.carbon.user.core.common.User> users;

        // Set filter values.
        String attributeName = node.getAttributeValue();
        String filterOperation = node.getOperation();
        String attributeValue = node.getValue();

        // If there is a domain, append the domain with the domain separator in front of the new attribute value if
        // domain separator is not found in the attribute value.
        if (StringUtils.isNotEmpty(domainName) && StringUtils
                .containsNone(attributeValue, CarbonConstants.DOMAIN_SEPARATOR)) {
            attributeValue = domainName.toUpperCase() + CarbonConstants.DOMAIN_SEPARATOR + node.getValue();
        }
        try {
            if (SCIMConstants.UserSchemaConstants.GROUP_URI.equals(attributeName)) {
                List<String> roleNames = getRoleNames(attributeName, filterOperation, attributeValue);
                users = getUserListOfRoles(roleNames);
            } else {
                // Get the user name of the user with this id.
                users = getUserNames(attributeName, filterOperation, attributeValue);
            }
        } catch (UserStoreException e) {
            String errorMessage = String.format("Error while filtering the users for filter with attribute name: %s ,"
                            + " filter operation: %s and attribute value: %s. ", attributeName, filterOperation,
                    attributeValue);
            throw new CharonException(errorMessage, e);
        }

        paginateUsers(users, limit, offset);
        return users;
    }

    /**
     * Method to remove duplicate users and get the user details.
     *
     * @param coreUsers          Filtered user names
     * @param requiredAttributes Required attributes in the response
     * @return Users list with populated attributes
     * @throws CharonException Error in retrieving user details
     */
    private List<Object> getDetailedUsers(Set<org.wso2.carbon.user.core.common.User> coreUsers,
                                          Map<String, Boolean> requiredAttributes)
            throws CharonException {

        List<Object> filteredUsers = new ArrayList<>();
        // 0th index is to store total number of results.
        filteredUsers.add(0);

        // Set total number of filtered results.
        filteredUsers.set(0, coreUsers.size());

        // Get details of the finalized user list.
        filteredUsers.addAll(getFilteredUserDetails(coreUsers, requiredAttributes));
        return filteredUsers;
    }

    /**
     * This method support multi-attribute filters with paginated search for user(s).
     *
     * @param node               Filter condition tree.
     * @param requiredAttributes Required attributes.
     * @param offset             Starting index of the count.
     * @param limit              Number of required results (count).
     * @param sortBy             SortBy.
     * @param sortOrder          Sort order.
     * @param domainName         Domain that the filter should perform.
     * @return
     * @throws CharonException
     */
    private List<Object> getMultiAttributeFilteredUsers(Node node, Map<String, Boolean> requiredAttributes, int offset,
                                                        int limit, String sortBy, String sortOrder, String domainName)
            throws CharonException {

        List<Object> filteredUsers = new ArrayList<>();
        // 0th index is to store total number of results.
        filteredUsers.add(0);
        Set<org.wso2.carbon.user.core.common.User> users;
        // Handle pagination.
        if (limit > 0) {
            users = getFilteredUsersFromMultiAttributeFiltering(node, offset, limit, sortBy, sortOrder, domainName);
            filteredUsers.set(0, users.size());
            filteredUsers.addAll(getFilteredUserDetails(users, requiredAttributes));
        } else {
            int maxLimit = getMaxLimit(domainName);
            if (StringUtils.isNotEmpty(domainName)) {
                users = getFilteredUsersFromMultiAttributeFiltering(node, offset, maxLimit, sortBy,
                        sortOrder, domainName);
                filteredUsers.set(0, users.size());
                filteredUsers.addAll(getFilteredUserDetails(users, requiredAttributes));
            } else {
                int totalUserCount = 0;
                // If pagination and domain name are not given, then perform filtering on all available user stores.
                while (carbonUM != null) {
                    // If carbonUM is not an instance of Abstract User Store Manger we can't get the domain name.
                    if (carbonUM instanceof AbstractUserStoreManager) {
                        domainName = carbonUM.getRealmConfiguration().getUserStoreProperty("DomainName");
                        users = getFilteredUsersFromMultiAttributeFiltering(node, offset, maxLimit,
                                sortBy, sortOrder, domainName);
                        totalUserCount += users.size();
                        filteredUsers.addAll(getFilteredUserDetails(users, requiredAttributes));
                    }
                    carbonUM = (AbstractUserStoreManager) carbonUM.getSecondaryUserStoreManager();
                }
                //set the total results
                filteredUsers.set(0, totalUserCount);
            }
        }
        return filteredUsers;
    }

    /**
     * Get maximum user limit to retrieve.
     *
     * @param domainName Name of the user store
     * @return Max user limit.
     */
    private int getMaxLimit(String domainName) {

        int givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
        if (StringUtils.isEmpty(domainName)) {
            domainName = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
        }

        if (carbonUM.getSecondaryUserStoreManager(domainName).getRealmConfiguration()
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST) != null) {
            givenMax = Integer.parseInt(carbonUM.getSecondaryUserStoreManager(domainName).getRealmConfiguration()
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST));
        }

        return givenMax;
    }

    /**
     * Generate condition tree for given filters.
     *
     * @param node       Filter condition tree.
     * @param attributes User attributes.
     * @return Validated filter condition tree.
     * @throws CharonException
     */
    private Condition getCondition(Node node, Map<String, String> attributes) throws CharonException {

        if (node instanceof ExpressionNode) {
            String operation = ((ExpressionNode) node).getOperation();
            String attributeName = ((ExpressionNode) node).getAttributeValue();
            String attributeValue = ((ExpressionNode) node).getValue();

            String conditionOperation;
            String conditionAttributeName;

            if (SCIMCommonConstants.EQ.equals(operation)) {
                conditionOperation = ExpressionOperation.EQ.toString();
            } else if (SCIMCommonConstants.SW.equals(operation)) {
                conditionOperation = ExpressionOperation.SW.toString();
            } else if (SCIMCommonConstants.EW.equals(operation)) {
                conditionOperation = ExpressionOperation.EW.toString();
            } else if (SCIMCommonConstants.CO.equals(operation)) {
                conditionOperation = ExpressionOperation.CO.toString();
            } else {
                conditionOperation = operation;
            }

            if (SCIMConstants.UserSchemaConstants.GROUP_URI.equals(attributeName)) {
                conditionAttributeName = ExpressionAttribute.ROLE.toString();
            } else if (SCIMConstants.UserSchemaConstants.USER_NAME_URI.equals(attributeName)) {
                conditionAttributeName = ExpressionAttribute.USERNAME.toString();
            } else if (attributes != null && attributes.get(attributeName) != null) {
                conditionAttributeName = attributes.get(attributeName);
            } else {
                throw new CharonException("Unsupported attribute: " + attributeName);
            }
            return new ExpressionCondition(conditionOperation, conditionAttributeName, attributeValue);
        } else if (node instanceof OperationNode) {
            Condition leftCondition = getCondition(node.getLeftNode(), attributes);
            Condition rightCondition = getCondition(node.getRightNode(), attributes);
            String operation = ((OperationNode) node).getOperation();
            if (OperationalOperation.AND.toString().equalsIgnoreCase(operation)) {
                return new OperationalCondition(OperationalOperation.AND.toString(), leftCondition, rightCondition);
            } else {
                throw new CharonException("Unsupported Operation: " + operation);
            }
        } else {
            throw new CharonException("Unsupported Operation");
        }
    }

    /**
     * Get all attributes for given domain.
     *
     * @param domainName Domain name.
     * @return All attributes of user.
     * @throws CharonException
     */
    private Map<String, String> getAllAttributes(String domainName) throws CharonException {

        Map<String, String> attributes = new HashMap<>();

        if (claimMetadataManagementService != null) {
            attributes.putAll(getMappedAttributes(SCIMCommonConstants.SCIM_CORE_CLAIM_DIALECT, domainName));
            attributes.putAll(getMappedAttributes(SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT, domainName));

            if (SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema() != null) {
                String extensionURI = SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema().getURI();
                attributes.putAll(getMappedAttributes(extensionURI, domainName));
            }
        } else {
            try {
                ClaimMapping[] userClaims;
                ClaimMapping[] coreClaims;
                ClaimMapping[] extensionClaims = null;

                coreClaims = carbonClaimManager.getAllClaimMappings(SCIMCommonConstants.SCIM_CORE_CLAIM_DIALECT);
                userClaims = carbonClaimManager.getAllClaimMappings(SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT);
                if (SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema() != null) {
                    extensionClaims = carbonClaimManager.getAllClaimMappings(
                            SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema().getURI());
                }
                for (ClaimMapping claim : coreClaims) {
                    attributes.put(claim.getClaim().getClaimUri(), claim.getMappedAttribute(domainName));
                }
                for (ClaimMapping claim : userClaims) {
                    attributes.put(claim.getClaim().getClaimUri(), claim.getMappedAttribute(domainName));
                }
                if (extensionClaims != null) {
                    for (ClaimMapping claim : extensionClaims) {
                        attributes.put(claim.getClaim().getClaimUri(), claim.getMappedAttribute(domainName));
                    }
                }
            } catch (UserStoreException e) {
                throw new CharonException("Error in filtering users by multi attributes ", e);
            }
        }
        return attributes;

    }

    /**
     * Get mapped attribute assigned to the specified domain for each claim in the specified external claim dialect.
     * @param extClaimDialectName
     * @param domainName
     * @return
     * @throws ClaimMetadataException
     */
    private Map<String, String> getMappedAttributes(String extClaimDialectName, String domainName)
            throws CharonException {

        Map<String, String> attributes = new HashMap<>();
        Map<ExternalClaim, LocalClaim> externalClaimLocalClaimMap = getMappedLocalClaimsForDialect(extClaimDialectName,
                tenantDomain);

        if (externalClaimLocalClaimMap != null) {
            for (Map.Entry<ExternalClaim, LocalClaim> entry : externalClaimLocalClaimMap.entrySet()) {

                ExternalClaim externalClaim = entry.getKey();
                LocalClaim mappedLocalClaim = entry.getValue();

                String mappedAttribute = mappedLocalClaim.getMappedAttribute(domainName);
                if (StringUtils.isEmpty(mappedAttribute)) {
                    mappedAttribute = mappedLocalClaim.getMappedAttribute(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
                }
                attributes.put(externalClaim.getClaimURI(), mappedAttribute);
            }
        }

        return attributes;
    }

    /**
     * Perform multi attribute filtering.
     *
     * @param node       Filter condition tree.
     * @param offset     Starting index of the count.
     * @param limit      Number of required results (count).
     * @param sortBy     SortBy.
     * @param sortOrder  Sort order.
     * @param domainName Domain that the filter should perform.
     * @return
     * @throws CharonException
     */
    private Set<org.wso2.carbon.user.core.common.User> getFilteredUsersFromMultiAttributeFiltering(Node node,
            int offset, int limit, String sortBy, String sortOrder, String domainName)
            throws CharonException {

        Set<org.wso2.carbon.user.core.common.User> coreUsers;

        try {
            if (StringUtils.isEmpty(domainName)) {
                domainName = "PRIMARY";
            }
            Map<String, String> attributes = getAllAttributes(domainName);
            if (log.isDebugEnabled()) {
                log.debug("Invoking the do get user list for domain: " + domainName);
            }
            coreUsers = new TreeSet<>(Comparator
                    .comparing(org.wso2.carbon.user.core.common.User::getFullQualifiedUsername));
            coreUsers.addAll(carbonUM.getUserListWithID(getCondition(node, attributes), domainName,
                    UserCoreConstants.DEFAULT_PROFILE, limit, offset, sortBy, sortOrder));
            return coreUsers;
        } catch (UserStoreException e) {
            throw new CharonException("Error in filtering users by multi attributes in domain: " + domainName, e);
        }
    }

    /**
     * Get required claim details for filtered user.
     *
     * @param users
     * @param requiredAttributes
     * @return
     * @throws CharonException
     */
    private List<Object> getFilteredUserDetails(Set<org.wso2.carbon.user.core.common.User> users,
                                                Map<String, Boolean> requiredAttributes)
            throws CharonException {

        List<Object> filteredUsers = new ArrayList<>();

        if (users == null || users.size() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("Users for this filter does not exist in the system.");
            }
            return filteredUsers;
        } else {
            try {
                Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
                List<String> requiredClaims = getOnlyRequiredClaims(scimToLocalClaimsMap.keySet(), requiredAttributes);
                List<String> requiredClaimsInLocalDialect;
                if (MapUtils.isNotEmpty(scimToLocalClaimsMap)) {
                    scimToLocalClaimsMap.keySet().retainAll(requiredClaims);
                    requiredClaimsInLocalDialect = new ArrayList<>(scimToLocalClaimsMap.values());
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("SCIM to Local Claim mappings list is empty.");
                    }
                    requiredClaimsInLocalDialect = new ArrayList<>();
                }

                Set<User> scimUsers;
                if (isPaginatedUserStoreAvailable()) {
                    if (carbonUM instanceof PaginatedUserStoreManager) {
                        scimUsers = this.getSCIMUsers(users, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                        filteredUsers.addAll(scimUsers);
                    } else {
                        addSCIMUsers(filteredUsers, users, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                    }
                } else {
                    addSCIMUsers(filteredUsers, users, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                }
            } catch (UserStoreException e) {
                throw new CharonException("Error in retrieve user details. ", e);
            }
        }
        return filteredUsers;
    }

    private void addSCIMUsers(List<Object> filteredUsers, Set<org.wso2.carbon.user.core.common.User> users,
                              List<String> requiredClaims,
                              Map<String, String> scimToLocalClaimsMap)
            throws CharonException {

        User scimUser;
        for (org.wso2.carbon.user.core.common.User user : users) {

            if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(user.getUsername())) {
                continue;
            }

            String userStoreDomainName = user.getUserStoreDomain();
            if (isSCIMEnabled(userStoreDomainName)) {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Including user : " + user.getUsername() + " in the response.");
                }

                scimUser = this.getSCIMUser(user, requiredClaims, scimToLocalClaimsMap, null);
                //if SCIM-ID is not present in the attributes, skip
                if (scimUser != null && StringUtils.isBlank(scimUser.getId())) {
                    continue;
                }
                filteredUsers.add(scimUser);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Hence user : " + user.getUsername() + " in this domain is excluded in the response.");
                }
            }
        }
    }

    @Override
    public User getMe(String userName,
                      Map<String, Boolean> requiredAttributes) throws CharonException, NotFoundException {

        if (log.isDebugEnabled()) {
            log.debug("Getting user: " + userName);
        }

        User scimUser;

        try {
            //get Claims related to SCIM claim dialect
            Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
            List<String> requiredClaims = getOnlyRequiredClaims(scimToLocalClaimsMap.keySet(), requiredAttributes);
            List<String> requiredClaimsInLocalDialect;
            if (MapUtils.isNotEmpty(scimToLocalClaimsMap)) {
                scimToLocalClaimsMap.keySet().retainAll(requiredClaims);
                requiredClaimsInLocalDialect = new ArrayList<>(scimToLocalClaimsMap.values());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM to Local Claim mappings list is empty.");
                }
                requiredClaimsInLocalDialect = new ArrayList<>();
            }

            org.wso2.carbon.user.core.common.User coreUser = carbonUM.getUser(null, userName);

            // We assume (since id is unique per user) only one user exists for a given id.
            scimUser = this.getSCIMUser(coreUser, requiredClaimsInLocalDialect, scimToLocalClaimsMap, null);

            if (scimUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug("User with userName : " + userName + " does not exist in the system.");
                }
                throw new NotFoundException("No such user exist");
            } else {
                // Set the schemas of the scim user.
                scimUser.setSchemas();
                log.info("User: " + scimUser.getUserName() + " is retrieved through SCIM.");
                return scimUser;
            }
        } catch (UserStoreException e) {
            throw new CharonException("Error from getting the authenticated user", e);
        }
    }

    @Override
    public User createMe(User user, Map<String, Boolean> requiredAttributes)
            throws CharonException, ConflictException, BadRequestException {

        return createUser(user, requiredAttributes);
    }

    @Override
    public void deleteMe(String userName) throws NotFoundException, CharonException, NotImplementedException {

        String error = "Self delete is not supported";
        throw new NotImplementedException(error);
    }

    @Override
    public User updateMe(User user, Map<String, Boolean> requiredAttributes)
            throws NotImplementedException, CharonException, BadRequestException {

        return updateUser(user, requiredAttributes);
    }

    @Override
    public Group createGroup(Group group, Map<String, Boolean> requiredAttributes)
            throws CharonException, ConflictException, BadRequestException {

        if (log.isDebugEnabled()) {
            log.debug("Creating group: " + group.getDisplayName());
        }
        try {
            // Modify display name if no domain is specified, in order to support multiple user store feature.
            String originalName = group.getDisplayName();
            String roleNameWithDomain = null;
            String domainName = "";
            try {
                if (getUserStoreDomainFromSP() != null) {
                    domainName = getUserStoreDomainFromSP();
                    roleNameWithDomain = IdentityUtil
                            .addDomainToName(UserCoreUtil.removeDomainFromName(originalName), domainName);
                } else if (originalName.indexOf(CarbonConstants.DOMAIN_SEPARATOR) > 0) {
                    domainName = IdentityUtil.extractDomainFromName(originalName);
                    roleNameWithDomain = IdentityUtil
                            .addDomainToName(UserCoreUtil.removeDomainFromName(originalName), domainName);
                } else {
                    domainName = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
                    roleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(originalName);
                }
            } catch (IdentityApplicationManagementException e) {
                throw new CharonException("Error retrieving User Store name. ", e);
            }

            if (!isInternalOrApplicationGroup(domainName) && StringUtils.isNotBlank(domainName) && !isSCIMEnabled
                    (domainName)) {
                throw new CharonException("Cannot create group through scim to user store " + ". SCIM is not " +
                        "enabled for user store " + domainName);
            }
            group.setDisplayName(roleNameWithDomain);
            //check if the group already exists
            if (carbonUM.isExistingRole(group.getDisplayName(), false)) {
                String error = "Group with name: " + group.getDisplayName() + " already exists in the system.";
                throw new ConflictException(error);
            }

            // Set thread local property to signal the downstream SCIMUserOperationListener about the
            // provisioning route.
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);

            // If members are sent when creating the group, check whether users already exist in the user store.
            List<Object> userIds = group.getMembers();
            List<String> userDisplayNames = group.getMembersWithDisplayName();
            if (isNotEmpty(userIds)) {
                List<String> members = new ArrayList<>();
                for (Object userId : userIds) {
                    String userIdLocalClaim = SCIMCommonUtils.getSCIMtoLocalMappings().get(SCIMConstants
                            .CommonSchemaConstants.ID_URI);
                    org.wso2.carbon.user.core.common.User coreUser = null;
                    if (StringUtils.isNotBlank(userIdLocalClaim)) {
                        coreUser = carbonUM.getUserWithID((String) userId, null, UserCoreConstants.DEFAULT_PROFILE);
                    }
                    if (coreUser == null) {
                        String error = "User: " + userId + " doesn't exist in the user store. " +
                                "Hence, can not create the group: " + group.getDisplayName();
                        throw new IdentitySCIMException(error);
                    } else if (coreUser.getUsername().indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0 &&
                            !StringUtils.containsIgnoreCase(coreUser.getUsername(), domainName)) {
                        String error = "User: " + userId + " doesn't exist in the same user store. " +
                                "Hence, can not create the group: " + group.getDisplayName();
                        throw new IdentitySCIMException(error);
                    } else {
                        members.add(coreUser.getUserID());
                        if (isNotEmpty(userDisplayNames)) {
                            boolean userContains = false;
                            for (String user : userDisplayNames) {
                                user = user.indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0
                                                ? user.split(UserCoreConstants.DOMAIN_SEPARATOR)[1]
                                                : user;
                                if (user.equalsIgnoreCase(coreUser.getUsername()
                                        .indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0
                                        ? coreUser.getUsername().split(UserCoreConstants.DOMAIN_SEPARATOR)[1]
                                        : coreUser.getUsername())) {
                                    userContains = true;
                                    break;
                                }
                            }
                            if (!userContains) {
                                throw new IdentitySCIMException("Given SCIM user Id and name does not match..");
                            }
                        }
                    }
                }
                // Add other scim attributes in the identity DB since user store doesn't support some attributes.
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
                scimGroupHandler.createSCIMAttributes(group);
                carbonUM.addRoleWithID(group.getDisplayName(), members.toArray(new String[0]), null, false);
                log.info("Group: " + group.getDisplayName() + " is created through SCIM.");
            } else {
                // Add other scim attributes in the identity DB since user store doesn't support some attributes.
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
                scimGroupHandler.createSCIMAttributes(group);
                carbonUM.addRoleWithID(group.getDisplayName(), null, null, false);
                log.info("Group: " + group.getDisplayName() + " is created through SCIM.");
            }
        } catch (UserStoreException e) {
            try {
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
                scimGroupHandler.deleteGroupAttributes(group.getDisplayName());
            } catch (UserStoreException | IdentitySCIMException ex) {
                log.error("Error occurred while doing rollback operation of the SCIM table entry for role: "
                        + group.getDisplayName(), ex);
                throw new CharonException("Error occurred while doing rollback operation of the SCIM " +
                        "table entry for role: " + group.getDisplayName(), e);
            }
            throw new CharonException("Error occurred while adding role : " + group.getDisplayName(), e);
        } catch (IdentitySCIMException | BadRequestException e) {
            String error = "One or more group members do not exist in the same user store. " +
                    "Hence, can not create the group: " + group.getDisplayName();
            if (log.isDebugEnabled()) {
                log.debug(error, e);
            }
            throw new BadRequestException(error, ResponseCodeConstants.INVALID_VALUE);
        }
        return group;
    }

    @Override
    public Group getGroup(String id, Map<String, Boolean> requiredAttributes) throws CharonException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving group with id: " + id);
        }
        Group group = null;
        try {
            SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
            // Get group name by Id.
            String groupName = groupHandler.getGroupName(id);

            if (groupName != null) {
                group = getGroupWithName(groupName);
                group.setSchemas();
                return group;
            } else {
                //returning null will send a resource not found error to client by Charon.
                return null;
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException("Error in retrieving group : " + id, e);
        } catch (IdentitySCIMException e) {
            throw new CharonException("Error in retrieving SCIM Group information from database.", e);
        } catch (CharonException | BadRequestException e) {
            throw new CharonException("Error in retrieving the group", e);
        }
    }

    @Override
    public void deleteGroup(String groupId) throws NotFoundException, CharonException {

        if (log.isDebugEnabled()) {
            log.debug("Deleting group: " + groupId);
        }
        try {
            // Set thread local property to signal the downstream SCIMUserOperationListener
            // about the provisioning route.
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);

            // Get group name by id.
            SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
            String groupName = groupHandler.getGroupName(groupId);

            if (groupName != null) {
                String userStoreDomainFromSP = null;
                try {
                    userStoreDomainFromSP = getUserStoreDomainFromSP();
                } catch (IdentityApplicationManagementException e) {
                    throw new CharonException("Error retrieving User Store name. ", e);
                }
                if (userStoreDomainFromSP != null &&
                        !(userStoreDomainFromSP.equalsIgnoreCase(IdentityUtil.extractDomainFromName(groupName)))) {
                    throw new CharonException("Group :" + groupName + "is not belong to user store " +
                            userStoreDomainFromSP + "Hence group updating fail");
                }

                String userStoreDomainName = IdentityUtil.extractDomainFromName(groupName);
                if (!isInternalOrApplicationGroup(userStoreDomainName) && StringUtils.isNotBlank(userStoreDomainName)
                        && !isSCIMEnabled
                        (userStoreDomainName)) {
                    throw new CharonException("Cannot delete group: " + groupName + " through scim from user store: " +
                            userStoreDomainName + ". SCIM is not enabled for user store: " + userStoreDomainName);
                }

                //delete group in carbon UM
                carbonUM.deleteRole(groupName);

                //we do not update Identity_SCIM DB here since it is updated in SCIMUserOperationListener's methods.
                log.info("Group: " + groupName + " is deleted through SCIM.");

            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Group with SCIM id: " + groupId + " doesn't exist in the system.");
                }
                throw new NotFoundException();
            }
        } catch (UserStoreException | IdentitySCIMException e) {
            throw new CharonException("Error occurred while deleting group " + groupId, e);
        }

    }

    @Override
    public List<Object> listGroupsWithGET(Node rootNode, int startIndex, int count, String sortBy, String sortOrder,
                                          String domainName, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {

        // If the startIndex less than 1 should be interpreted as 1 according to the SCIM2 specification.
        startIndex = (startIndex < 1 ? 1 : startIndex);
        if (sortBy != null || sortOrder != null) {
            throw new NotImplementedException("Sorting is not supported");
        } else if (startIndex != 1 && count >= 0) {
            throw new NotImplementedException("Pagination is not supported");
        } else if (rootNode != null) {
            return filterGroups(rootNode, startIndex, count, sortBy, sortOrder, domainName, requiredAttributes);
        } else {
            return listGroups(startIndex, count, sortBy, sortOrder, domainName, requiredAttributes);
        }
    }

    @Override
    public List<Object> listGroupsWithGET(Node rootNode, Integer startIndex, Integer count, String sortBy,
                                          String sortOrder, String domainName, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException {

        // Validate NULL value for startIndex.
        startIndex = handleStartIndexEqualsNULL(startIndex);
        if (sortBy != null || sortOrder != null) {
            throw new NotImplementedException("Sorting is not supported");
        } else if (startIndex != 1 || count != null) {
            throw new NotImplementedException("Pagination is not supported");
        } else if (rootNode != null) {
            return filterGroups(rootNode, startIndex, count, sortBy, sortOrder, domainName, requiredAttributes);
        } else {
            return listGroups(startIndex, count, sortBy, sortOrder, domainName, requiredAttributes);
        }
    }

    /**
     * Method to interpret startIndex as 1 when the startIndex equals to NULL in the request.
     *
     * @param startIndex StartIndex in the request.
     * @return Updated startIndex
     */
    private int handleStartIndexEqualsNULL(Integer startIndex) {

        if (startIndex == null) {
            if (log.isDebugEnabled()) {
                log.debug("NULL value for startIndex argument interpreted as 1");
            }
            return 1;
        }
        return startIndex;
    }

    /**
     * List all the groups.
     *
     * @param startIndex         Start index in the request.
     * @param count              Limit in the request.
     * @param sortBy             SortBy
     * @param sortOrder          Sorting order
     * @param domainName         Domain Name
     * @param requiredAttributes Required attributes
     * @return
     * @throws CharonException
     */
    private List<Object> listGroups(int startIndex, Integer count, String sortBy, String sortOrder, String domainName,
                                    Map<String, Boolean> requiredAttributes) throws CharonException {

        List<Object> groupList = new ArrayList<>();
        //0th index is to store total number of results;
        groupList.add(0);
        try {
            Set<String> roleNames = getRoleNamesForGroupsEndpoint(domainName);
            for (String roleName : roleNames) {
                String userStoreDomainName = IdentityUtil.extractDomainFromName(roleName);
                if (isInternalOrApplicationGroup(userStoreDomainName) || isSCIMEnabled(userStoreDomainName)) {
                    if (log.isDebugEnabled()) {
                        log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". "
                                + "Including group with name : " + roleName + " in the response.");
                    }
                    Group group = this.getGroupWithName(roleName);
                    if (group.getId() != null) {
                        groupList.add(group);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". Hence "
                                + "group with name : " + roleName + " is excluded in the response.");
                    }
                }
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            String errMsg = "Error in obtaining role names from user store.";
            errMsg += e.getMessage();
            throw new CharonException(errMsg, e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errMsg = "Error in retrieving role names from user store.";
            throw new CharonException(errMsg, e);
        } catch (IdentitySCIMException | BadRequestException e) {
            throw new CharonException("Error in retrieving SCIM Group information from database.", e);
        }
        // Set the totalResults value in index 0.
        groupList.set(0, groupList.size() - 1);
        return groupList;
    }

    /**
     * Get role names according to the given domain. If the domain is not specified, roles of all the user
     * stores will be returned.
     *
     * @param domainName Domain name
     * @return Roles List
     * @throws UserStoreException
     * @throws IdentitySCIMException
     */
    private Set<String> getRoleNamesForGroupsEndpoint(String domainName)
            throws UserStoreException, IdentitySCIMException {

        SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
        if (StringUtils.isEmpty(domainName)) {
            Set<String> roleNames = groupHandler.listSCIMRoles();
            Set<String> hybridRoles = new HashSet<>(Arrays.asList(carbonUM.getHybridRoles()));
            List<String> scimDisabledHybridRoles = getSCIMDisabledHybridRoleList(hybridRoles, roleNames);
            if (!scimDisabledHybridRoles.isEmpty()) {
                createSCIMAttributesForSCIMDisabledHybridRoles(scimDisabledHybridRoles);
                roleNames.addAll(scimDisabledHybridRoles);
            }
            return roleNames;
        } else {
            // If the domain is specified create a attribute value with the domain name.
            String searchValue = domainName + CarbonConstants.DOMAIN_SEPARATOR + SCIMCommonConstants.ANY;

            List<String> roleList;
            // Retrieve roles using the above search value.
            if (isInternalOrApplicationGroup(domainName)) {
                // Support for hybrid roles listing with domain parameter. ex: domain=Application.
                roleList = filterHybridRoles(domainName, searchValue);
            } else {
                // Retrieve roles using the above attribute value.
                roleList = Arrays.asList(((AbstractUserStoreManager) carbonUM)
                        .getRoleNames(searchValue, MAX_ITEM_LIMIT_UNLIMITED, true, true, true));
            }
            Set<String> roleNames = new HashSet<>(roleList);
            Set<String> scimRoles = groupHandler.listSCIMRoles();
            List<String> scimDisabledHybridRoles = getSCIMDisabledHybridRoleList(roleNames, scimRoles);
            if (!scimDisabledHybridRoles.isEmpty()) {
                createSCIMAttributesForSCIMDisabledHybridRoles(scimDisabledHybridRoles);
                roleNames.addAll(scimDisabledHybridRoles);
            }
            return roleNames;
        }
    }

    /**
     * Filter users according to a given filter.
     *
     * @param rootNode           Node
     * @param startIndex         Starting index of the results
     * @param count              Number of required results.
     * @param sortBy             SortBy
     * @param sortOrder          Sorting order
     * @param domainName         Domain name in the request
     * @param requiredAttributes Required attributes
     * @return List of filtered groups
     * @throws NotImplementedException Complex filters are used.
     * @throws CharonException         Unknown node operation.
     */
    private List<Object> filterGroups(Node rootNode, int startIndex, Integer count, String sortBy, String sortOrder,
                                      String domainName, Map<String, Boolean> requiredAttributes)
            throws NotImplementedException, CharonException {

        // Handle count equals NULL scenario.
        count = handleLimitEqualsNULL(count);
        if (rootNode instanceof ExpressionNode) {
            return filterGroupsBySingleAttribute((ExpressionNode) rootNode, startIndex, count, sortBy, sortOrder,
                    domainName, requiredAttributes);
        } else if (rootNode instanceof OperationNode) {
            String error = "Complex filters are not supported yet";
            throw new NotImplementedException(error);
        } else {
            throw new CharonException("Unknown operation. Not either an expression node or an operation node.");
        }
    }

    /**
     * Filter groups with a single attribute.
     *
     * @param node               Expression node
     * @param startIndex         Starting index
     * @param count              Number of results required
     * @param sortBy             SortBy
     * @param sortOrder          Sorting order
     * @param domainName         Domain to be filtered
     * @param requiredAttributes Required attributes
     * @return Filtered groups
     * @throws CharonException Error in Filtering
     */
    private List<Object> filterGroupsBySingleAttribute(ExpressionNode node, int startIndex, int count, String sortBy,
                                                       String sortOrder, String domainName,
                                                       Map<String, Boolean> requiredAttributes) throws CharonException {

        String attributeName = node.getAttributeValue();
        String filterOperation = node.getOperation();
        String attributeValue = node.getValue();
        if (log.isDebugEnabled()) {
            log.debug("Filtering groups with filter: " + attributeName + " + " + filterOperation + " + "
                    + attributeValue);
        }
        // Check whether the filter operation is supported for filtering in groups.
        if (isFilteringNotSupported(filterOperation)) {
            String errorMessage = "Filter operation: " + filterOperation + " is not supported for groups filtering.";
            throw new CharonException(errorMessage);
        }
        // Resolve the domain name in request according to 'FilterUsersAndGroupsOnlyFromPrimaryDomain' or
        // EnableFilteringEnhancements' properties in identity.xml or domain name embedded in the filter attribute
        // value.
        domainName = resolveDomain(domainName, node);
        List<Object> filteredGroups = new ArrayList<>();
        // 0th index is to store total number of results.
        filteredGroups.add(0);
        try {
            List<String> roleList = getGroupList(node, domainName);
            if (roleList != null) {
                for (String roleName : roleList) {
                    if (roleName != null && carbonUM.isExistingRole(roleName, false)) {
                        // Skip internal roles.
                        if (CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME.equals(roleName) || UserCoreUtil
                                .isEveryoneRole(roleName, carbonUM.getRealmConfiguration())) {
                            continue;
                        }
                        Group group = getRoleWithDefaultAttributes(roleName);
                        if (group != null && group.getId() != null) {
                            filteredGroups.add(group);
                        }
                    } else {
                        // Returning null will send a resource not found error to client by Charon.
                        filteredGroups.clear();
                        filteredGroups.add(0);
                        return filteredGroups;
                    }
                }
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException(
                    "Error in filtering groups by attribute name : " + attributeName + ", " + "attribute value : "
                            + attributeValue + " and filter operation : " + filterOperation, e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new CharonException(
                    "Error in filtering group with filter: " + attributeName + " + " + filterOperation + " + "
                            + attributeValue, e);
        }
        // Set the totalResults value in index 0.
        filteredGroups.set(0, filteredGroups.size() - 1);
        return filteredGroups;
    }

    /**
     * Resolve the domain name in request according to 'FilterUsersAndGroupsOnlyFromPrimaryDomain' or
     * 'EnableFilteringEnhancements' properties in identity.xml or domain name embedded in the filter attribute value.
     *
     * @param domainName Domain name passed in the request.
     * @param node       Expression node
     * @return Domain name
     * @throws CharonException
     */
    private String resolveDomain(String domainName, ExpressionNode node) throws CharonException {

        try {
            // Update the domain name if a domain is appended to the attribute value.
            domainName = resolveDomainInAttributeValue(domainName, node);

            // Apply filter enhancements if the domain is not specified in the request.
            if (StringUtils.isEmpty(domainName)) {
                domainName = getDomainWithFilterProperties(node);
            }
            return domainName;
        } catch (BadRequestException e) {
            String errorMessage = String
                    .format(" Domain name in the attribute value: %s does not match with the domain parameter: %s in "
                            + "the request.", node.getValue(), domainName);
            throw new CharonException(errorMessage, e);
        }
    }

    /**
     * Check isFilterUsersAndGroupsOnlyFromPrimaryDomainEnabled() or isFilteringEnhancementsEnabled() which
     * enables filtering in primary domain only.
     *
     * @param node Expression node.
     * @return Primary domain name if properties are enabled or return NULL when properties are disabled.
     */
    private String getDomainWithFilterProperties(ExpressionNode node) {

        if (isFilterUsersAndGroupsOnlyFromPrimaryDomainEnabled()) {
            return UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
        } else if (isFilteringEnhancementsEnabled()) {
            // To maintain backward compatibility.
            if (SCIMCommonConstants.EQ.equalsIgnoreCase(node.getOperation())) {
                if (StringUtils.equals(node.getAttributeValue(), SCIMConstants.GroupSchemaConstants.DISPLAY_NAME_URI)) {
                    return UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
                }
            }
        }
        // Domain value should be returned to indicate no special requirement for primary user store filtering.
        return "";
    }

    /**
     * Resolve domain name if a domain is attached to the attribute value.
     *
     * @param domainName Domain name in the request.
     * @param node       Expression Node.
     * @return Domain name
     */
    private String resolveDomainInAttributeValue(String domainName, ExpressionNode node) throws BadRequestException {

        String attributeName = node.getAttributeValue();
        String attributeValue = node.getValue();
        String extractedDomain;
        if (StringUtils.equals(attributeName, SCIMConstants.GroupSchemaConstants.DISPLAY_NAME_URI) || StringUtils
                .equals(attributeName, SCIMConstants.GroupSchemaConstants.DISPLAY_URI) || StringUtils
                .equals(attributeName, SCIMConstants.GroupSchemaConstants.VALUE_URI)) {

            // Split the attribute value by domain separator. If a domain is embedded in the attribute value, then
            // the size of the array will be 2.
            String[] contentInAttributeValue = attributeValue.split(CarbonConstants.DOMAIN_SEPARATOR, 2);

            // Length less than 1 would indicate that there is no domain appended in front of the attribute value.
            if (contentInAttributeValue.length > 1) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Attribute value: %s is embedded with a domain.", attributeValue));
                }
                String domainInAttributeValue = contentInAttributeValue[0];
                if (isInternalOrApplicationGroup(domainInAttributeValue)) {
                    extractedDomain = domainInAttributeValue;
                } else {
                    extractedDomain = domainInAttributeValue.toUpperCase();
                }

                // Check whether the domain name is equal to the extracted domain name from attribute value.
                if (StringUtils.isNotEmpty(domainName) && StringUtils.isNotEmpty(extractedDomain) && !extractedDomain
                        .equalsIgnoreCase(domainName)) {
                    throw new BadRequestException(String.format(
                            " Domain name: %s in the domain parameter does not match with the domain name: %s in "
                                    + "search attribute value of %s claim.", domainName, extractedDomain,
                            attributeName));
                }
                // Remove the domain name from the attribute value and update it in the expression node.
                node.setValue(contentInAttributeValue[1]);
                return extractedDomain;
            } else {
                return domainName;
            }
        } else {
            // If the domain is not embedded, return domain name passed in the request.
            return domainName;
        }
    }

    /**
     * Get the role name with attributes.
     *
     * @param roleName Role name
     * @throws CharonException
     * @throws UserStoreException
     */
    private Group getRoleWithDefaultAttributes(String roleName)
            throws CharonException, UserStoreException {

        String userStoreDomainName = IdentityUtil.extractDomainFromName(roleName);
        if (isInternalOrApplicationGroup(userStoreDomainName) || isSCIMEnabled(userStoreDomainName)) {
            if (log.isDebugEnabled()) {
                log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". "
                        + "Including group with name : " + roleName + " in the response.");
            }
            try {
                return getGroupWithName(roleName);
            } catch (IdentitySCIMException e) {
                throw new CharonException("Error in retrieving SCIM Group information from database.", e);
            } catch (BadRequestException e) {
                throw new CharonException("Error in retrieving SCIM Group.", e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". Hence "
                        + "group with name : " + roleName + " is excluded in the response.");
            }
            // Return NULL implies that a group cannot be created.
            return null;
        }
    }

    @Override
    public void updateGroup(Group oldGroup, Group newGroup) throws CharonException {

        try {
            doUpdateGroup(oldGroup, newGroup);
        } catch (UserStoreException | IdentitySCIMException e) {
            throw new CharonException(e.getMessage(), e);
        } catch (IdentityApplicationManagementException e){
            throw new CharonException("Error retrieving User Store name. ", e);
        } catch (BadRequestException | CharonException e) {
            throw new CharonException("Error in updating the group", e);
        }
    }

    @Override
    public Group updateGroup(Group oldGroup, Group newGroup, Map<String, Boolean> requiredAttributes)
            throws CharonException {

        try {
            boolean updated = doUpdateGroup(oldGroup, newGroup);
            if (updated) {
                log.info("Group: " + oldGroup.getDisplayName() + " is updated through SCIM.");
                // In case the duplicate existing in the newGroup, query the corresponding group
                // again and return it.
                return getGroup(newGroup.getId(), requiredAttributes);
            } else {
                log.warn("There is no updated field in the group: " + oldGroup.getDisplayName()
                        + ". Therefore ignoring the provisioning.");
                // Hence no changes were done, return original group. There are some cases, new group can have
                // duplicated members.
                return oldGroup;
            }
        } catch (UserStoreException | IdentitySCIMException e) {
            throw new CharonException(e.getMessage(), e);
        } catch (IdentityApplicationManagementException e){
            throw new CharonException("Error retrieving User Store name. ", e);
        } catch (BadRequestException | CharonException e) {
            throw new CharonException("Error in updating the group", e);
        }
    }

    public boolean doUpdateGroup(Group oldGroup, Group newGroup) throws CharonException, IdentitySCIMException,
            BadRequestException, IdentityApplicationManagementException, org.wso2.carbon.user.core.UserStoreException {

        setGroupDisplayName(oldGroup, newGroup);
        if (log.isDebugEnabled()) {
            log.debug("Updating group: " + oldGroup.getDisplayName());
        }

        String userStoreDomainForGroup = IdentityUtil.extractDomainFromName(newGroup.getDisplayName());

        if (isNotEmpty(newGroup.getMembers()) && isNotInternalOrApplicationGroup(userStoreDomainForGroup)) {
            appendDomainToMembers(newGroup, userStoreDomainForGroup);
        }

        /*
            Set thread local property to signal the downstream SCIMUserOperationListener
            about the provisioning route.
        */
        SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);

        Set<String> membersInOldGroup = new HashSet<>(oldGroup.getMembersWithDisplayName());
        Set<String> membersInUpdatedGroup = new HashSet<>(newGroup.getMembersWithDisplayName());

        // Check for deleted members
        Set<String> deletedMembers = getDeletedMemberUsernames(membersInOldGroup, membersInUpdatedGroup);
        Set<String> deletedMemberIdsFromUserstore =
                getMemberValuesFromUserstore(deletedMembers, userStoreDomainForGroup, oldGroup.getDisplayName());

        // Check for added members
        Set<String> addedMembers = getAddedMemberUsernames(membersInOldGroup, membersInUpdatedGroup);
        Set<String> addedMemberIdsFromUserstore =
                getMemberValuesFromUserstore(addedMembers, userStoreDomainForGroup, oldGroup.getDisplayName());

        // Find out added userIds from the updated group.
        Set<Object> newlyAddedMemberIds = getNewlyAddedMemberIds(oldGroup, newGroup);

        // Validate the memberIds sent in the update request against the Ids retrieved from the user store.
        validateUserIds(addedMemberIdsFromUserstore, newlyAddedMemberIds);

        // We do not update Identity_SCIM DB here since it is updated in SCIMUserOperationListener's methods.
        // Update name if it is changed.
        String oldGroupDisplayName = oldGroup.getDisplayName();
        String newGroupDisplayName = newGroup.getDisplayName();

        boolean updated = false;
        if (isGroupDisplayNameChanged(oldGroupDisplayName, newGroupDisplayName)) {
            // Update group name in carbon UM
            carbonUM.updateRoleName(oldGroupDisplayName, newGroupDisplayName);
            updated = true;
        }

        // Update the group with added members and deleted members.
        if (isNotEmpty(addedMembers) || isNotEmpty(deletedMembers)) {
            carbonUM.updateUserListOfRoleWithID(newGroupDisplayName,
                    deletedMemberIdsFromUserstore.toArray(new String[0]),
                    addedMemberIdsFromUserstore.toArray(new String[0]));
            updated = true;
        }

        return updated;
    }

    private Set<String> getAddedMemberUsernames(Set<String> oldMembers, Set<String> newMembers) {

        Set<String> addedMembers = new HashSet<>(newMembers);
        addedMembers.removeAll(oldMembers);
        return addedMembers;
    }

    private Set<String> getDeletedMemberUsernames(Set<String> oldMembers, Set<String> newMembers) {

        Set<String> deletedMembers = new HashSet<>(oldMembers);
        deletedMembers.removeAll(newMembers);
        return deletedMembers;
    }

    private Set<Object> getNewlyAddedMemberIds(Group oldGroup, Group newGroup) {

        Set<Object> newlyAddedUserIds = new HashSet<>(newGroup.getMembers());
        Set<Object> oldGroupUserIds = new HashSet<>(oldGroup.getMembers());
        if (isNotEmpty(oldGroupUserIds)) {
            // We will be left with the newly added userIds.
            newlyAddedUserIds.removeAll(oldGroupUserIds);
        }
        return newlyAddedUserIds;
    }

    private Set<String> getMemberValuesFromUserstore(Set<String> memberUsernames, String userStoreDomainOfGroup,
                                                     String displayName) throws IdentitySCIMException,
            org.wso2.carbon.user.core.UserStoreException {

        Set<String> memberUserIds = new HashSet<>();
        for (String userName : memberUsernames) {
            // Compare user store domain of group and user store domain of user name, if there is a mismatch do not
            // update the group.
            String userStoreDomainOfUser = IdentityUtil.extractDomainFromName(userName);
            if (!isInternalOrApplicationGroup(userStoreDomainOfGroup) && !userStoreDomainOfGroup
                    .equalsIgnoreCase(userStoreDomainOfUser)) {
                throw new IdentitySCIMException(
                        String.format("%s doesn't belongs to user store: %s", userName, userStoreDomainOfGroup));
            }

            // Check if the user ids & associated user name sent in updated (new) group exist in the user store.
            org.wso2.carbon.user.core.common.User user = getUserFromUsername(userName);
            if (user == null || StringUtils.isEmpty(user.getUserID())) {
                String error = "User: " + userName + " doesn't exist in the user store. Hence can not update the " +
                        "group: " + displayName;
                throw new IdentitySCIMException(error);
            }
            memberUserIds.add(user.getUserID());
        }
        return memberUserIds;
    }

    private void validateUserIds(Set<String> addedMemberIdsFromUserstore, Set<Object> newlyAddedMemberIds) throws
            IdentitySCIMException {

        for (Object addedUserId : newlyAddedMemberIds) {
            if (!addedMemberIdsFromUserstore.contains(addedUserId.toString())) {
                throw new IdentitySCIMException(String.format("Provided SCIM user Id: %s doesn't match with the "
                        + "userID obtained from user-store for the provided username.", addedUserId.toString()));
            }
        }
    }

    private void setGroupDisplayName(Group oldGroup, Group newGroup)
            throws IdentityApplicationManagementException, CharonException, BadRequestException, IdentitySCIMException {

        String userStoreDomainFromSP = getUserStoreDomainFromSP();

        String oldGroupDomain = IdentityUtil.extractDomainFromName(oldGroup.getDisplayName());
        if(userStoreDomainFromSP != null && !userStoreDomainFromSP.equalsIgnoreCase(oldGroupDomain)) {
            throw new CharonException("Group :" + oldGroup.getDisplayName() + "is not belong to user store " +
                    userStoreDomainFromSP + "Hence group updating fail");
        }

        // If the updated group name does not contain a user store domain, it will be returned as PRIMARY.
        String updatedGroupDomain = IdentityUtil.extractDomainFromName(newGroup.getDisplayName());

        if (isPrimaryDomain(updatedGroupDomain) && !isPrimaryDomain(oldGroupDomain)) {
            // This is the case where the updated group name did not contain a domain name but was returned as PRIMARY
            // from IdentityUtil.extractDomainFromName() method.
            String newGroupNameWithoutDomain = UserCoreUtil.removeDomainFromName(newGroup.getDisplayName());
            newGroup.setDisplayName(IdentityUtil.addDomainToName(newGroupNameWithoutDomain, oldGroupDomain));
        } else if (!oldGroupDomain.equals(updatedGroupDomain)) {
            // This is the case where the updated group domain does not match the old group's domain.
            throw new IdentitySCIMException(
                    "User store domain of the group is not matching with the given SCIM group Id.");
        }

        newGroup.setDisplayName(SCIMCommonUtils.getGroupNameWithDomain(newGroup.getDisplayName()));
        oldGroup.setDisplayName(SCIMCommonUtils.getGroupNameWithDomain(oldGroup.getDisplayName()));
    }

    private boolean isPrimaryDomain(String newGroupDomainName) {

        return newGroupDomainName.equals(IdentityUtil.getPrimaryDomainName());
    }

    private boolean isGroupDisplayNameChanged(String oldGroupDisplayName, String newGroupDisplayName) {

        return !oldGroupDisplayName.equalsIgnoreCase(newGroupDisplayName);
    }

    private org.wso2.carbon.user.core.common.User getUserFromUsername(String username)
            throws org.wso2.carbon.user.core.UserStoreException {

        List<org.wso2.carbon.user.core.common.User> coreUsers = carbonUM.getUserListWithID(
                UserCoreClaimConstants.USERNAME_CLAIM_URI, username, UserCoreConstants.DEFAULT_PROFILE);

        if (!coreUsers.isEmpty()) {
            // TODO: Should we throw an exception if multiple users are found?
            return coreUsers.get(0);
        }

        return null;
    }

    /**
     * Perform user validation, check provided added member(s) details are exists in the user store. Else throw
     * corresponding error
     *
     * @param userId
     * @param userStoreDomainForGroup
     * @param displayName
     * @param addedUserIdsList
     * @throws IdentitySCIMException
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private void doUserValidation(String userId, String userStoreDomainForUser, String userStoreDomainForGroup,
                                  String displayName,
                                  List<Object> addedUserIdsList)
            throws IdentitySCIMException, org.wso2.carbon.user.core.UserStoreException {

        // Compare user store domain of group and user store domain of user name, if there is a mismatch do not
        // update the group.
        if (!isInternalOrApplicationGroup(userStoreDomainForGroup) && !userStoreDomainForGroup
                .equalsIgnoreCase(userStoreDomainForUser)) {
            throw new IdentitySCIMException(userId + " does not belongs to user store " + userStoreDomainForGroup);
        }

        // Check if the user ids & associated user name sent in updated (new) group exist in the user store.
        if (StringUtils.isEmpty(userId)) {
            String error = "User: " + userId + " doesn't exist in the user store. Hence can not update the "
                    + "group: " + displayName;
            throw new IdentitySCIMException(error);
        } else {
            if (!UserCoreUtil.isContain(userId, addedUserIdsList.toArray(new String[0]))) {
                throw new IdentitySCIMException("Provided SCIM user Id: " + userId + " doesn't match with the "
                        + "userID obtained from user-store for the provided username: " + userId);
            }
        }
    }

    @Override
    public List<Object> listGroupsWithPost(SearchRequest searchRequest, Map<String, Boolean> requiredAttributes)
            throws BadRequestException, NotImplementedException, CharonException {

        return listGroupsWithGET(searchRequest.getFilter(), searchRequest.getStartIndex(), searchRequest.getCount(),
                searchRequest.getSortBy(), searchRequest.getSortOder(), searchRequest.getDomainName(),
                requiredAttributes);
    }

    // TODO: fix this method. Looks like the intended purpose of this method is not fulfilled with the current
    //  implementation.
    private String getUserStoreDomainFromSP() throws IdentityApplicationManagementException {

        ServiceProvider serviceProvider = null;

        if (serviceProvider != null && serviceProvider.getInboundProvisioningConfig() != null &&
                !StringUtils.isBlank(serviceProvider.getInboundProvisioningConfig().getProvisioningUserStore())) {
            return serviceProvider.getInboundProvisioningConfig().getProvisioningUserStore();
        }
        return null;
    }

    /**
     * This method will return whether SCIM is enabled or not for a particular userStore. (from SCIMEnabled user
     * store property)
     *
     * @param userStoreName user store name
     * @return whether scim is enabled or not for the particular user store
     */
    private boolean isSCIMEnabled(String userStoreName) {

        UserStoreManager userStoreManager = carbonUM.getSecondaryUserStoreManager(userStoreName);
        if (userStoreManager != null) {
            try {
                return userStoreManager.isSCIMEnabled();
            } catch (UserStoreException e) {
                log.error("Error while evaluating isSCIMEnalbed for user store " + userStoreName, e);
            }
        }
        return false;
    }

    /**
     * get the specfied user from the store
     *
     * @param coreUser User of the underlying user store.
     * @param claimURIList
     * @return
     * @throws CharonException
     */
    private User getSCIMUser(org.wso2.carbon.user.core.common.User coreUser, List<String> claimURIList,
                             Map<String, String> scimToLocalClaimsMap, Map<String, String> userClaimValues)
            throws CharonException {

        User scimUser = null;

        String userStoreDomainName = coreUser.getUserStoreDomain();
        if (StringUtils.isNotBlank(userStoreDomainName) && !isSCIMEnabled(userStoreDomainName)) {
            throw new CharonException("Cannot get user through SCIM to user store. SCIM is not enabled for user store: "
                    + userStoreDomainName);
        }

        try {
            // TODO: If we can get the updated user claim values from the add user method, we don't need to do
            //  this call. Please check the status of the issue: https://github.com/wso2/product-is/issues/7160
            userClaimValues = carbonUM.getUserClaimValuesWithID(coreUser.getUserID(),
                    claimURIList.toArray(new String[0]), null);

            Map<String, String> attributes = SCIMCommonUtils.convertLocalToSCIMDialect(userClaimValues,
                    scimToLocalClaimsMap);

            if (!attributes.containsKey(SCIMConstants.CommonSchemaConstants.ID_URI)) {
                return scimUser;
            }

            // Skip simple type addresses claim because it is complex with sub types in the schema.
            attributes.remove(SCIMConstants.UserSchemaConstants.ADDRESSES_URI);

            // Add username with domain name.
            attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, coreUser.getUsername());

            // Location URI is not available for users who created from the mgt console also location URI is not
            // tenant aware, so need to update the location URI according to the tenant.
            String locationURI = SCIMCommonUtils
                    .getSCIMUserURL(attributes.get(SCIMConstants.CommonSchemaConstants.ID_URI));
            attributes.put(SCIMConstants.CommonSchemaConstants.LOCATION_URI, locationURI);

            if (!attributes.containsKey(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI)) {
                attributes.put(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI, SCIMConstants.USER);
            }

            // Get groups of user and add it as groups attribute.
            List<String> roles = carbonUM.getRoleListOfUserWithID(coreUser.getUserID());
            checkForSCIMDisabledHybridRoles(roles);

            // Construct the SCIM Object from the attributes.
            scimUser = (User) AttributeMapper.constructSCIMObjectFromAttributes(attributes, 1);

            // Add username with domain name.
            if (mandateDomainForUsernamesAndGroupNamesInResponse()) {
                scimUser.setUserName(prependDomain(coreUser.getUsername()));
            }

            Map<String, Group> groupMetaAttributesCache = new HashMap<>();

            // Add groups of user.
            for (String role : roles) {
                if (UserCoreUtil.isEveryoneRole(role, carbonUM.getRealmConfiguration())
                        || CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME.equalsIgnoreCase(role)) {
                    // Carbon specific roles do not possess SCIM info, hence skipping them.
                    continue;
                }

                if (mandateDomainForUsernamesAndGroupNamesInResponse()) {
                    role = prependDomain(role);
                } else if (isFilteringEnhancementsEnabled()) {
                    role = prependDomain(role);
                }

                Group group = groupMetaAttributesCache.get(role);
                if (group == null && !groupMetaAttributesCache.containsKey(role)) {
                    group = getGroupOnlyWithMetaAttributes(role);
                    groupMetaAttributesCache.put(role, group);
                }

                if (group != null) { // can be null for non SCIM groups
                    scimUser.setGroup(null, group);
                }
            }
        } catch (UserStoreException | CharonException | NotFoundException | IdentitySCIMException |
                BadRequestException e) {
            throw new CharonException("Error in getting user information for user: " + scimUser.getUserName(), e);
        }

        return scimUser;
    }

    /**
     * get the specified user from the store
     *
     * @param users    Set of users
     * @param claimURIList Requested claim list
     * @return Array of SCIM User
     * @throws CharonException CharonException
     */
    private Set<User> getSCIMUsers(Set<org.wso2.carbon.user.core.common.User> users, List<String> claimURIList,
                                   Map<String, String> scimToLocalClaimsMap) throws CharonException {

        List<User> scimUsers = new ArrayList<>();

        //obtain user claim values
        List<UniqueIDUserClaimSearchEntry> searchEntries;
        Map<String, List<String>> usersRoles;

        try {
            searchEntries = carbonUM.getUsersClaimValuesWithID(users
                    .stream()
                    .map(org.wso2.carbon.user.core.common.User::getUserID)
                    .collect(Collectors.toList()), claimURIList, null);
            usersRoles = carbonUM.getRoleListOfUsersWithID(users
                    .stream()
                    .map(org.wso2.carbon.user.core.common.User::getUserID)
                    .collect(Collectors.toList()));
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException("Error occurred while retrieving SCIM user information", e);
        }

        Map<String, Group> groupMetaAttributesCache = new HashMap<>();

        for (org.wso2.carbon.user.core.common.User user : users) {
            String userStoreDomainName = user.getUserStoreDomain();
            if (isSCIMEnabled(userStoreDomainName)) {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Including user : " + user.getUsername() + " in the response.");
                }
                User scimUser;
                Map<String, String> userClaimValues = new HashMap<>();
                for (UniqueIDUserClaimSearchEntry entry : searchEntries) {
                    if (entry.getUser() != null && StringUtils.isNotBlank(entry.getUser().getUserID())
                            && entry.getUser().getUserID().equals(user.getUserID())) {
                        userClaimValues = entry.getClaims();
                    }
                }
                Map<String, String> attributes;
                try {
                    attributes = SCIMCommonUtils.convertLocalToSCIMDialect(userClaimValues, scimToLocalClaimsMap);
                } catch (UserStoreException e) {
                    throw new CharonException("Error in converting local claims to SCIM dialect for user: "
                            + user.getUsername(), e);
                }

                try {
                    if (!attributes.containsKey(SCIMConstants.CommonSchemaConstants.ID_URI)) {
                        if (log.isDebugEnabled()) {
                            log.debug(String.format("Skipping adding user %s with id %s as attribute %s is not " +
                                            "available.", user.getFullQualifiedUsername(), user.getUserID(),
                                    SCIMConstants.CommonSchemaConstants.ID_URI));
                        }
                        continue;
                    }
                    //skip simple type addresses claim because it is complex with sub types in the schema
                    if (attributes.containsKey(SCIMConstants.UserSchemaConstants.ADDRESSES_URI)) {
                        attributes.remove(SCIMConstants.UserSchemaConstants.ADDRESSES_URI);
                    }

                    // Location URI is not available for users who created from the mgt console also location URI is not
                    // tenant aware, so need to update the location URI according to the tenant.
                    String locationURI = SCIMCommonUtils
                            .getSCIMUserURL(attributes.get(SCIMConstants.CommonSchemaConstants.ID_URI));
                    attributes.put(SCIMConstants.CommonSchemaConstants.LOCATION_URI, locationURI);

                    if (!attributes.containsKey(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI)) {
                        attributes.put(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI, SCIMConstants.USER);
                    }

                    //get groups of user and add it as groups attribute
                    List<String> roleList = usersRoles.get(user.getUserID());
                    List<String> roles = new ArrayList<>();
                    if (isNotEmpty(roleList)) {
                        roles = roleList;
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug(String.format("Roles not found for user %s with id %s .",
                                    user.getFullQualifiedUsername(), user.getUserID()));
                        }
                    }
                    checkForSCIMDisabledHybridRoles(roles);

                    // Add username with domain name
                    if (mandateDomainForUsernamesAndGroupNamesInResponse()) {
                        attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, user
                                .getFullQualifiedUsername());
                    } else {
                        attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, user.getUsername());
                    }

                    //construct the SCIM Object from the attributes
                    scimUser = (User) AttributeMapper.constructSCIMObjectFromAttributes(attributes, 1);

                    //add groups of user
                    for (String role : roles) {
                        if (UserCoreUtil.isEveryoneRole(role, carbonUM.getRealmConfiguration())
                                || CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME.equalsIgnoreCase(role)) {
                            // Carbon specific roles do not possess SCIM info, hence skipping them.
                            continue;
                        }

                        if (mandateDomainForUsernamesAndGroupNamesInResponse()) {
                            role = prependDomain(role);
                        } else if (isFilteringEnhancementsEnabled()) {
                            role = prependDomain(role);
                        }

                        Group group = groupMetaAttributesCache.get(role);
                        if (group == null && !groupMetaAttributesCache.containsKey(role)) {
                            group = getGroupOnlyWithMetaAttributes(role);
                            groupMetaAttributesCache.put(role, group);
                        }

                        if (group != null) { // can be null for non SCIM groups
                            scimUser.setGroup(null, group);
                        }
                    }
                } catch (UserStoreException | CharonException | NotFoundException | IdentitySCIMException |
                        BadRequestException e) {
                    throw new CharonException("Error in getting user information for user: " + user.getUsername(), e);
                }

                if (scimUser != null) {
                    scimUsers.add(scimUser);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Hence user : " + user.getUsername() + " in this domain is excluded in the response.");
                }
            }
        }
        TreeSet<User> scimUserSet = new TreeSet<>(Comparator.comparing(User::getUsername));
        scimUserSet.addAll(scimUsers);
        return scimUserSet;
    }

    /**
     * Get group with only meta attributes.
     *
     * @param groupName
     * @return
     * @throws CharonException
     * @throws IdentitySCIMException
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private Group getGroupOnlyWithMetaAttributes(String groupName) throws CharonException, IdentitySCIMException,
            org.wso2.carbon.user.core.UserStoreException, BadRequestException {
        //get other group attributes and set.
        Group group = new Group();
        group.setDisplayName(groupName);
        SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
        return groupHandler.getGroupWithAttributes(group, groupName);
    }

    /**
     * returns whether particular user store domain is application or internal.
     *
     * @param userstoreDomain user store domain
     * @return whether passed domain name is "internal" or "application"
     */
    private boolean isInternalOrApplicationGroup(String userstoreDomain) {

        return StringUtils.isNotBlank(userstoreDomain) &&
                (SCIMCommonConstants.APPLICATION_DOMAIN.equalsIgnoreCase(userstoreDomain) ||
                        SCIMCommonConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userstoreDomain));
    }

    private boolean isNotInternalOrApplicationGroup(String userStoreDomain) {

        return !isInternalOrApplicationGroup(userStoreDomain);
    }

    /**
     * This is used to add domain name to the members of a group
     *
     * @param group
     * @param userStoreDomain
     * @return
     * @throws CharonException
     */
    private void appendDomainToMembers(Group group, String userStoreDomain) throws CharonException {

        if (StringUtils.isBlank(userStoreDomain) || CollectionUtils.isEmpty(group.getMembers())) {
            return;
        }

        if (group.isAttributeExist(SCIMConstants.GroupSchemaConstants.MEMBERS)) {
            MultiValuedAttribute members = (MultiValuedAttribute) group.getAttributeList().get(
                    SCIMConstants.GroupSchemaConstants.MEMBERS);
            List<Attribute> attributeValues = members.getAttributeValues();

            if (attributeValues != null && !attributeValues.isEmpty()) {
                for (Attribute attributeValue : attributeValues) {
                    SimpleAttribute displayNameAttribute = (SimpleAttribute) attributeValue.getSubAttribute(
                            SCIMConstants.CommonSchemaConstants.DISPLAY);
                    String displayName =
                            AttributeUtil.getStringValueOfAttribute(displayNameAttribute.getValue(),
                                    displayNameAttribute.getType());
                    displayNameAttribute.setValue(IdentityUtil.addDomainToName(
                            UserCoreUtil.removeDomainFromName(displayName), userStoreDomain));
                }
            }
        }
    }

    /**
     * Get the full group with all the details including users.
     *
     * @param groupName
     * @return
     * @throws CharonException
     * @throws org.wso2.carbon.user.core.UserStoreException
     * @throws IdentitySCIMException
     */
    private Group getGroupWithName(String groupName)
            throws CharonException, org.wso2.carbon.user.core.UserStoreException, IdentitySCIMException,
            BadRequestException {

        String userStoreDomainName = IdentityUtil.extractDomainFromName(groupName);
        if (!isInternalOrApplicationGroup(userStoreDomainName) && StringUtils.isNotBlank(userStoreDomainName) &&
                !isSCIMEnabled(userStoreDomainName)) {
            throw new CharonException("Cannot retrieve group through scim to user store " + ". SCIM is not " +
                    "enabled for user store " + userStoreDomainName);
        }

        Group group = new Group();
        if (mandateDomainForUsernamesAndGroupNamesInResponse()) {
            groupName = prependDomain(groupName);
            group.setDisplayName(groupName);
        } else if (mandateDomainForGroupNamesInGroupsResponse()) {
            groupName = prependDomain(groupName);
            group.setDisplayName(groupName);
        } else {
            group.setDisplayName(groupName);
        }

        List<org.wso2.carbon.user.core.common.User> coreUsers = carbonUM.getUserListOfRoleWithID(groupName);

        //get the ids of the users and set them in the group with id + display name
        if (coreUsers != null && coreUsers.size() != 0) {
            for (org.wso2.carbon.user.core.common.User coreUser : coreUsers) {
                String userId = coreUser.getUserID();
                String userName = coreUser.getDomainQualifiedUsername();
                if (mandateDomainForUsernamesAndGroupNamesInResponse()) {
                    userName = prependDomain(userName);
                }
                String locationURI = SCIMCommonUtils.getSCIMUserURL(userId);
                User user = new User();
                user.setUserName(userName);
                user.setId(userId);
                user.setLocation(locationURI);
                group.setMember(user);
            }
        }
        //get other group attributes and set.
        SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
        group = groupHandler.getGroupWithAttributes(group, groupName);
        return group;
    }

    /**
     * This is used to add domain name to the members of a group
     *
     * @param group
     * @param userStoreDomain
     * @return
     * @throws CharonException
     */
    private Group addDomainToUserMembers(Group group, String userStoreDomain) throws CharonException {

        List<Object> membersId = group.getMembers();

        if (StringUtils.isBlank(userStoreDomain) || membersId == null || membersId.isEmpty()) {
            return group;
        }

        if (group.isAttributeExist(SCIMConstants.GroupSchemaConstants.MEMBERS)) {
            MultiValuedAttribute members = (MultiValuedAttribute) group.getAttributeList().get(
                    SCIMConstants.GroupSchemaConstants.MEMBERS);
            List<Attribute> attributeValues = members.getAttributeValues();

            if (attributeValues != null && !attributeValues.isEmpty()) {
                for (Attribute attributeValue : attributeValues) {
                    SimpleAttribute displayNameAttribute = (SimpleAttribute) attributeValue.getSubAttribute(
                            SCIMConstants.CommonSchemaConstants.DISPLAY);
                    String displayName =
                            AttributeUtil.getStringValueOfAttribute(displayNameAttribute.getValue(),
                                    displayNameAttribute.getType());
                    displayNameAttribute.setValue(IdentityUtil.addDomainToName(
                            UserCoreUtil.removeDomainFromName(displayName), userStoreDomain));
                }
            }
        }
        return group;
    }

    private List<String> getMappedClaimList(Map<String, Boolean> requiredAttributes) {

        ArrayList<String> claimsList = new ArrayList<>();

        for (Map.Entry<String, Boolean> claim : requiredAttributes.entrySet()) {
            if (claim.getValue().equals(true)) {

            } else {
                claimsList.add(claim.getKey());
            }
        }

        return claimsList;
    }

    /**
     * This returns the only required attributes for value querying
     *
     * @param claimURIList
     * @param requiredAttributes
     * @return
     */
    private List<String> getOnlyRequiredClaims(Set<String> claimURIList, Map<String, Boolean> requiredAttributes) {

        List<String> requiredClaimList = new ArrayList<>();
        for (String requiredClaim : requiredAttributes.keySet()) {
            if (requiredAttributes.get(requiredClaim)) {
                if (claimURIList.contains(requiredClaim)) {
                    requiredClaimList.add(requiredClaim);
                } else {
                    String[] parts = requiredClaim.split("[.]");
                    for (String claim : claimURIList) {
                        if (parts.length == 3) {
                            if (claim.contains(parts[0] + "." + parts[1])) {
                                if (!requiredClaimList.contains(claim)) {
                                    requiredClaimList.add(claim);
                                }
                            }
                        } else if (parts.length == 2) {
                            if (claim.contains(parts[0])) {
                                if (!requiredClaimList.contains(claim)) {
                                    requiredClaimList.add(claim);
                                }
                            }
                        }

                    }
                }
            } else {
                if (!requiredClaimList.contains(requiredClaim)) {
                    requiredClaimList.add(requiredClaim);
                }
            }
        }
        return requiredClaimList;
    }

    /**
     * Paginate a list of users names according to a given offset and a count.
     *
     * @param users  A list of unpaginated users.
     * @param limit  The total number of results required (ZERO will return all the users).
     * @param offset The starting index of the count (limit).
     * @return A list of paginated users
     */
    private Set<org.wso2.carbon.user.core.common.User> paginateUsers(Set<org.wso2.carbon.user.core.common.User> users,
                                                                     int limit, int offset) {

        // If the results are empty, an empty list should be returned.
        if (users == null) {
            return new TreeSet<>(Comparator.comparing(org.wso2.carbon.user.core.common.User::getFullQualifiedUsername));
        }

        TreeSet<org.wso2.carbon.user.core.common.User> sortedSet;
        if (!(users instanceof TreeSet)) {
            sortedSet = new TreeSet<>(Comparator
                    .comparing(org.wso2.carbon.user.core.common.User::getFullQualifiedUsername));
            sortedSet.addAll(users);
        } else {
            sortedSet = (TreeSet<org.wso2.carbon.user.core.common.User>) users;
        }

        // Validate offset value.
        if (offset <= 0) {
            offset = 1;
        }

        // If the results are less than the offset, return an empty user list.
        if (offset > sortedSet.size()) {
            return new TreeSet<>(Comparator.comparing(org.wso2.carbon.user.core.common.User::getFullQualifiedUsername));
        }

        // If the limit is zero, all the users needs to be returned after verifying the offset.
        if (limit <= 0) {
            if (offset == 1) {

                // This is to support backward compatibility.
                return users;
            } else {
                return new TreeSet<>(new ArrayList<>(sortedSet).subList(offset - 1, sortedSet.size()));
            }
        } else {
            // If users.length > limit + offset, then return only the users bounded by the offset and the limit.
            if (users.size() > limit + offset) {
                return new TreeSet<>(new ArrayList<>(sortedSet).subList(offset - 1, limit + offset - 1));
            } else {
                // Return all the users from the offset.
                return new TreeSet<>(new ArrayList<>(sortedSet).subList(offset - 1, sortedSet.size()));
            }
        }
    }

    /**
     * Check whether the filtering is supported.
     *
     * @param filterOperation Operator to be used for filtering
     * @return boolean to check whether operator is supported
     */
    private boolean isFilteringNotSupported(String filterOperation) {

        return !filterOperation.equalsIgnoreCase(SCIMCommonConstants.EQ) && !filterOperation
                .equalsIgnoreCase(SCIMCommonConstants.CO) && !filterOperation.equalsIgnoreCase(SCIMCommonConstants.SW)
                && !filterOperation.equalsIgnoreCase(SCIMCommonConstants.EW);
    }

    private Set<org.wso2.carbon.user.core.common.User> getUserListOfRoles(List<String> roleNames)
            throws org.wso2.carbon.user.core.UserStoreException {

        Set<org.wso2.carbon.user.core.common.User> users = new HashSet<>();
        if (roleNames != null) {
            for (String roleName : roleNames) {
                users.addAll(new HashSet<>(carbonUM.getUserListOfRoleWithID(roleName)));
            }
        }
        return users;
    }

    /**
     * Get the search value after appending the delimiters according to the attribute name to be filtered.
     *
     * @param attributeName   Filter attribute name
     * @param filterOperation Operator value
     * @param attributeValue  Search value
     * @param delimiter       Filter delimiter based on search type
     * @return Search attribute
     */
    private String getSearchAttribute(String attributeName, String filterOperation, String attributeValue,
                                      String delimiter) {

        String searchAttribute = null;
        if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.CO)) {
            searchAttribute = createSearchValueForCoOperation(attributeName, filterOperation, attributeValue,
                    delimiter);
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.SW)) {
            searchAttribute = attributeValue + delimiter;
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EW)) {
            searchAttribute = createSearchValueForEwOperation(attributeName, filterOperation, attributeValue,
                    delimiter);
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EQ)) {
            searchAttribute = attributeValue;
        }
        return searchAttribute;
    }

    /**
     * Create search value for CO operation.
     *
     * @param attributeName   Filter attribute name
     * @param filterOperation Operator value
     * @param attributeValue  Filter attribute value
     * @param delimiter       Filter delimiter based on search type
     * @return Search attribute value
     */
    private String createSearchValueForCoOperation(String attributeName, String filterOperation, String attributeValue,
                                                   String delimiter) {

        // For attributes which support domain embedding, create search value by appending the delimiter after
        // the domain separator.
        if (isDomainSupportedAttribute(attributeName)) {

            // Check whether domain is embedded in the attribute value.
            String[] attributeItems = attributeValue.split(CarbonConstants.DOMAIN_SEPARATOR, 2);
            if (attributeItems.length > 1) {
                return createSearchValueWithDomainForCoEwOperations(attributeName, filterOperation, attributeValue,
                        delimiter, attributeItems);
            } else {
                return delimiter + attributeValue + delimiter;
            }
        } else {
            return delimiter + attributeValue + delimiter;
        }
    }

    /**
     * Create search value for EW operation.
     *
     * @param attributeName   Filter attribute name
     * @param filterOperation Operator value
     * @param attributeValue  Filter attribute value
     * @param delimiter       Filter delimiter based on search type
     * @return Search attribute value
     */
    private String createSearchValueForEwOperation(String attributeName, String filterOperation, String attributeValue,
                                                   String delimiter) {

        // For attributes which support domain embedding, create search value by appending the delimiter after
        // the domain separator.
        if (isDomainSupportedAttribute(attributeName)) {
            // Extract the domain attached to the attribute value and then append the delimiter.
            String[] attributeItems = attributeValue.split(CarbonConstants.DOMAIN_SEPARATOR, 2);
            if (attributeItems.length > 1) {
                return createSearchValueWithDomainForCoEwOperations(attributeName, filterOperation, attributeValue,
                        delimiter, attributeItems);
            } else {
                return delimiter + attributeValue;
            }
        } else {
            return delimiter + attributeValue;
        }
    }

    /**
     * Create search value for CO and EW operations when domain is detected in the filter attribute value.
     *
     * @param attributeName   Filter attribute name
     * @param filterOperation Operator value
     * @param attributeValue  Search value
     * @param delimiter       Filter delimiter based on search type
     * @param attributeItems  Extracted domain and filter value
     * @return Search attribute value
     */
    private String createSearchValueWithDomainForCoEwOperations(String attributeName, String filterOperation,
                                                                String attributeValue, String delimiter,
                                                                String[] attributeItems) {

        String searchAttribute;
        if (log.isDebugEnabled()) {
            log.debug(String.format(
                    "Domain detected in attribute value: %s for filter attribute: %s for " + "filter operation: %s.",
                    attributeValue, attributeName, filterOperation));
        }
        if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EW)) {
            searchAttribute = attributeItems[0] + CarbonConstants.DOMAIN_SEPARATOR + delimiter + attributeItems[1];
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.CO)) {
            searchAttribute =
                    attributeItems[0] + CarbonConstants.DOMAIN_SEPARATOR + delimiter + attributeItems[1] + delimiter;
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Filter operation: %s is not supported by method "
                        + "createSearchValueWithDomainForCoEwOperations to create a search value."));
            }
            searchAttribute = attributeValue;
        }
        if (log.isDebugEnabled()) {
            log.debug(
                    String.format("Search attribute value : %s is created for operation: %s created with domain : %s ",
                            searchAttribute, filterOperation, attributeItems[0]));
        }
        return searchAttribute;
    }

    /**
     * Check whether the filter attribute support filtering with the domain embedded in the attribute value.
     *
     * @param attributeName Attribute to filter
     * @return True if the given attribute support embedding domain in attribute value.
     */
    private boolean isDomainSupportedAttribute(String attributeName) {

        return SCIMConstants.UserSchemaConstants.USER_NAME_URI.equalsIgnoreCase(attributeName)
                || SCIMConstants.CommonSchemaConstants.ID_URI.equalsIgnoreCase(attributeName)
                || SCIMConstants.UserSchemaConstants.GROUP_URI.equalsIgnoreCase(attributeName)
                || SCIMConstants.GroupSchemaConstants.DISPLAY_NAME_URI.equalsIgnoreCase(attributeName)
                || SCIMConstants.GroupSchemaConstants.DISPLAY_URI.equalsIgnoreCase(attributeName);
    }

    /**
     * Get list of roles that matches the search criteria.
     *
     * @param attributeName   Filter attribute name
     * @param filterOperation Operator value
     * @param attributeValue  Search value
     * @return List of role names
     * @throws org.wso2.carbon.user.core.UserStoreException Error getting roleNames.
     */
    private List<String> getRoleNames(String attributeName, String filterOperation, String attributeValue)
            throws org.wso2.carbon.user.core.UserStoreException {

        String searchAttribute = getSearchAttribute(attributeName, filterOperation, attributeValue,
                FILTERING_DELIMITER);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Filtering roleNames from search attribute: %s", searchAttribute));
        }
        String domain = SCIMCommonUtils.extractDomain(attributeValue);
        // Extract domain from attribute value.
        if (isInternalOrApplicationGroup(domain)) {
            return filterHybridRoles(domain, searchAttribute);
        } else if (StringUtils.isEmpty(domain)) {
            // When domain is empty filter through all the domains.
            return Arrays.asList(carbonUM.getRoleNames(searchAttribute, MAX_ITEM_LIMIT_UNLIMITED, false, true, true));
        } else {
            return Arrays.asList(carbonUM.getRoleNames(searchAttribute, MAX_ITEM_LIMIT_UNLIMITED, true, true, true));
        }
    }

    /**
     * Get list of user that matches the search criteria.
     *
     * @param attributeName   Field name for search
     * @param filterOperation Operator
     * @param attributeValue  Search value
     * @return List of users
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private Set<org.wso2.carbon.user.core.common.User> getUserNames(String attributeName, String filterOperation,
                                                                    String attributeValue)
            throws org.wso2.carbon.user.core.UserStoreException {

        String searchAttribute = getSearchAttribute(attributeName, filterOperation, attributeValue,
                FILTERING_DELIMITER);
        String attributeNameInLocalDialect = SCIMCommonUtils.getSCIMtoLocalMappings().get(attributeName);
        if (StringUtils.isBlank(attributeNameInLocalDialect)) {
            attributeNameInLocalDialect = attributeName;
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("Filtering userNames from search attribute: %s", searchAttribute));
        }

        return new HashSet<>(carbonUM.getUserListWithID(attributeNameInLocalDialect, searchAttribute,
                UserCoreConstants.DEFAULT_PROFILE));
    }

    /**
     * Get the list of groups that matches the search criteria.
     *
     * @param expressionNode Expression node for the filter.
     * @param domainName     Domain name
     * @return List of user groups
     * @throws org.wso2.carbon.user.core.UserStoreException
     * @throws IdentitySCIMException
     */
    private List<String> getGroupList(ExpressionNode expressionNode, String domainName)
            throws org.wso2.carbon.user.core.UserStoreException, CharonException {

        String attributeName = expressionNode.getAttributeValue();
        String filterOperation = expressionNode.getOperation();
        String attributeValue = expressionNode.getValue();

        // Groups endpoint only support display uri and value uri.
        if (attributeName.equals(SCIMConstants.GroupSchemaConstants.DISPLAY_URI) || attributeName
                .equals(SCIMConstants.GroupSchemaConstants.VALUE_URI)) {

            Set<org.wso2.carbon.user.core.common.User> userList;

            // Update attribute value with the domain name.
            attributeValue = prependDomainNameToTheAttributeValue(attributeValue, domainName);

            // Listing users.
            if (attributeName.equals(SCIMConstants.GroupSchemaConstants.DISPLAY_URI)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Filter attribute: %s mapped to filter attribute: %s to filter users in "
                            + "groups endpoint.", attributeName, SCIMConstants.UserSchemaConstants.USER_NAME_URI));
                }
                userList = getUserNames(SCIMConstants.UserSchemaConstants.USER_NAME_URI, filterOperation,
                        attributeValue);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Filter attribute: %s mapped to filter attribute: %s to filter users in "
                            + "groups endpoint", attributeName, SCIMConstants.CommonSchemaConstants.ID_URI));
                }
                userList = getUserNames(SCIMConstants.CommonSchemaConstants.ID_URI, filterOperation, attributeValue);
            }

            // Get the roles of the users.
            Set<String> fullRoleList = new HashSet<>();
            for (org.wso2.carbon.user.core.common.User user : userList) {
                fullRoleList.addAll(carbonUM.getRoleListOfUserWithID(user.getUserID()));
            }

            List<String> roles = new ArrayList<>(fullRoleList);
            checkForSCIMDisabledHybridRoles(roles);
            return roles;
        } else if (attributeName.equals(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME_URI)) {
            attributeValue = prependDomainNameToTheAttributeValue(attributeValue, domainName);
            List<String> roles = getRoleNames(attributeName, filterOperation, attributeValue);
            checkForSCIMDisabledHybridRoles(roles);
            return roles;
        } else {
            try {
                return getGroupNamesFromDB(attributeName, filterOperation, attributeValue, domainName);
            } catch (IdentitySCIMException e) {
                throw new CharonException("Error in retrieving SCIM Group information from database.", e);
            }
        }
    }

    /**
     * Check for hybrid roles created while SCIM is disabled and create SCIM attributes for them.
     *
     * @param roles Role list.
     * @throws CharonException {@link CharonException}.
     */
    private void checkForSCIMDisabledHybridRoles(List<String> roles) throws CharonException {

        try {
            SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
            Set<String> scimRoles = groupHandler.listSCIMRoles();
            List<String> scimDisabledHybridRoles = getSCIMDisabledHybridRoleList(new HashSet<>(roles), scimRoles);
            if (!scimDisabledHybridRoles.isEmpty()) {
                createSCIMAttributesForSCIMDisabledHybridRoles(scimDisabledHybridRoles);
            }
        } catch (org.wso2.carbon.user.core.UserStoreException | IdentitySCIMException e) {
            throw new CharonException("Error in retrieving SCIM Group information from database.", e);
        }
    }

    /**
     * Prepend the domain name in front of the attribute value to be searched.
     *
     * @param attributeValue
     * @param domainName
     * @return
     */
    private String prependDomainNameToTheAttributeValue(String attributeValue, String domainName) {

        if (StringUtils.isNotEmpty(domainName)) {
            return domainName + CarbonConstants.DOMAIN_SEPARATOR + attributeValue;
        } else {
            return attributeValue;
        }
    }

    /**
     * Return group names when search using meta data; list of groups.
     *
     * @param attributeName   Attribute name which is used to search.
     * @param filterOperation Operator value.
     * @param attributeValue  Search value.
     * @param domainName      Domain to be filtered.
     * @return list of groups
     * @throws org.wso2.carbon.user.core.UserStoreException
     * @throws IdentitySCIMException
     */
    private List<String> getGroupNamesFromDB(String attributeName, String filterOperation, String attributeValue,
                                         String domainName) throws org.wso2.carbon.user.core.UserStoreException,
            IdentitySCIMException {

        String searchAttribute = getSearchAttribute(attributeName, filterOperation, attributeValue,
                SQL_FILTERING_DELIMITER);
        SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
        if (log.isDebugEnabled()) {
            log.debug(String.format("Filtering roleNames from DB from search attribute: %s", searchAttribute));
        }
        return Arrays.asList(groupHandler.getGroupListFromAttributeName(attributeName, searchAttribute, domainName));
    }

    private boolean isPaginatedUserStoreAvailable() {

        String enablePaginatedUserStore = IdentityUtil.getProperty(ENABLE_PAGINATED_USER_STORE);
        if (StringUtils.isNotBlank(enablePaginatedUserStore)) {
            return Boolean.parseBoolean(enablePaginatedUserStore);
        }
        return true;
    }

    /**
     * Check whether claim is an immutable claim.
     *
     * @param claim claim URI.
     * @return
     */
    private boolean isImmutableClaim(String claim) throws UserStoreException {

        Map<String, String> claimMappings = SCIMCommonUtils.getSCIMtoLocalMappings();

        return claim.equals(claimMappings.get(SCIMConstants.CommonSchemaConstants.ID_URI)) ||
                claim.equals(claimMappings.get(SCIMConstants.UserSchemaConstants.USER_NAME_URI)) ||
                claim.equals(claimMappings.get(SCIMConstants.UserSchemaConstants.ROLES_URI + "."
                        + SCIMConstants.DEFAULT)) ||
                claim.equals(claimMappings.get(SCIMConstants.CommonSchemaConstants.CREATED_URI)) ||
                claim.equals(claimMappings.get(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI)) ||
                claim.equals(claimMappings.get(SCIMConstants.CommonSchemaConstants.LOCATION_URI)) ||
                claim.equals(claimMappings.get(SCIMConstants.UserSchemaConstants.FAMILY_NAME_URI)) ||
                claim.contains(UserCoreConstants.ClaimTypeURIs.IDENTITY_CLAIM_URI);
    }

    /**
     * Get the local claims mapped to the required scim claims.
     */
    private List<String> getRequiredClaimsInLocalDialect(Map<String, String> scimToLocalClaimsMap, Map<String,
            Boolean> requiredAttributes)
            throws UserStoreException {

        List<String> requiredClaims = getOnlyRequiredClaims(scimToLocalClaimsMap.keySet(), requiredAttributes);
        List<String> requiredClaimsInLocalDialect;
        if (MapUtils.isNotEmpty(scimToLocalClaimsMap)) {
            scimToLocalClaimsMap.keySet().retainAll(requiredClaims);
            requiredClaimsInLocalDialect = new ArrayList<>(scimToLocalClaimsMap.values());
        } else {
            if (log.isDebugEnabled()) {
                log.debug("SCIM to Local Claim mappings list is empty.");
            }
            requiredClaimsInLocalDialect = new ArrayList<>();
        }
        return requiredClaimsInLocalDialect;
    }

    /**
     * Evaluate old user claims and the new claims. Then DELETE, ADD and MODIFY user claim values. The DELETE,
     * ADD and MODIFY operations are done in the same order.
     *
     * @param user         {@link User} object.
     * @param oldClaimList User claim list for the user's existing state.
     * @param newClaimList User claim list for the user's new state.
     * @throws UserStoreException Error while accessing the user store.
     * @throws CharonException    {@link CharonException}.
     */
    private void updateUserClaims(User user, Map<String, String> oldClaimList,
                                  Map<String, String> newClaimList) throws UserStoreException, CharonException {

        Map<String, String> userClaimsToBeAdded = new HashMap<>(newClaimList);
        Map<String, String> userClaimsToBeDeleted = new HashMap<>(oldClaimList);
        Map<String, String> userClaimsToBeModified = new HashMap<>();

        // Get all the old claims, which are not available in the new claims.
        userClaimsToBeDeleted.keySet().removeAll(newClaimList.keySet());

        // Get all the new claims, which are not available in the existing claims.
        userClaimsToBeAdded.keySet().removeAll(oldClaimList.keySet());

        // Get all new claims, which are only modifying the value of an existing claim.
        for (Map.Entry<String, String> eachNewClaim : newClaimList.entrySet()) {
            if (oldClaimList.containsKey(eachNewClaim.getKey()) &&
                    !oldClaimList.get(eachNewClaim.getKey()).equals(eachNewClaim.getValue())) {
                userClaimsToBeModified.put(eachNewClaim.getKey(), eachNewClaim.getValue());
            }
        }

        // Remove user claims.
        for (Map.Entry<String, String> entry : userClaimsToBeDeleted.entrySet()) {
            if (!isImmutableClaim(entry.getKey())) {
                carbonUM.deleteUserClaimValueWithID(user.getId(), entry.getKey(), null);
            }
        }

        // Update user claims.
        userClaimsToBeModified.putAll(userClaimsToBeAdded);
        carbonUM.setUserClaimValuesWithID(user.getId(), userClaimsToBeModified, null);
    }

    /**
     * Method to filter hybrid roles (Application & Internal) from a search value.
     *
     * @param domainInAttributeValue domain of the hybrid role
     * @param searchAttribute        search value
     * @return Array of filtered hybrid roles.
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private List<String> filterHybridRoles(String domainInAttributeValue, String searchAttribute)
            throws org.wso2.carbon.user.core.UserStoreException {

        List<String> roleList = new ArrayList<>();
        // Get filtered hybrid roles by passing noInternalRoles=false.
        String[] hybridRoles = ((AbstractUserStoreManager) carbonUM)
                .getRoleNames(searchAttribute, MAX_ITEM_LIMIT_UNLIMITED, false, true, true);
        // Iterate through received hybrid roles and filter out specific hybrid role
        // domain(Application or Internal) values.
        for (String hybridRole : hybridRoles) {
            if (domainInAttributeValue != null && !hybridRole.startsWith(domainInAttributeValue)) {
                continue;
            }
            if (hybridRole.toLowerCase().startsWith(SCIMCommonConstants.INTERNAL_DOMAIN.toLowerCase()) || hybridRole
                    .toLowerCase().startsWith(SCIMCommonConstants.APPLICATION_DOMAIN.toLowerCase())) {
                roleList.add(hybridRole);
            }
        }
        return roleList;
    }

    /**
     * Get the list of hybrid roles that were created while SCIM is disabled in the user store.
     *
     * @param roles     Roles list.
     * @param scimRoles Roles created while SCIM is enabled in the user store.
     * @return List of hybrid roles created while SCIM is disabled in the user store.
     */
    private List<String> getSCIMDisabledHybridRoleList(Set<String> roles, Set<String> scimRoles) {

        List<String> scimDisabledHybridRoles = new ArrayList<>();
        for (String role : roles) {
            if (!scimRoles.contains(role) && SCIMCommonUtils.isHybridRole(role) && !UserCoreUtil.isEveryoneRole(role,
                    carbonUM.getRealmConfiguration())) {
                scimDisabledHybridRoles.add(role);
            }
        }

        return scimDisabledHybridRoles;
    }

    /**
     * Create and add group attributes to the IDN_SCIM_GROUP table for hybrid roles created while SCIM is disabled in
     * the user store.
     *
     * @param scimDisabledHybridRoles List of hybrid roles created while SCIM is disabled in the user store.
     * @throws org.wso2.carbon.user.core.UserStoreException Error in loading user store manager.
     * @throws IdentitySCIMException                        Error in persisting.
     */
    private void createSCIMAttributesForSCIMDisabledHybridRoles(List<String> scimDisabledHybridRoles)
            throws org.wso2.carbon.user.core.UserStoreException, IdentitySCIMException {

        Map<String, Map<String, String>> attributesList = new HashMap<>();

        for (String scimDisabledHybridRole : scimDisabledHybridRoles) {
            Map<String, String> groupAttributes = new HashMap<>();
            String id = UUID.randomUUID().toString();
            groupAttributes.put(SCIMConstants.CommonSchemaConstants.ID_URI, id);
            String createdDate = AttributeUtil.formatDateTime(Instant.now());
            groupAttributes.put(SCIMConstants.CommonSchemaConstants.CREATED_URI, createdDate);
            groupAttributes.put(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI, createdDate);
            groupAttributes.put(SCIMConstants.CommonSchemaConstants.LOCATION_URI, SCIMCommonUtils.getSCIMGroupURL(id));
            attributesList.put(scimDisabledHybridRole, groupAttributes);
        }

        GroupDAO groupDAO = new GroupDAO();
        groupDAO.addSCIMGroupAttributesToSCIMDisabledHybridRoles(carbonUM.getTenantId(), attributesList);
        log.info("Persisted SCIM metadata for hybrid roles created while SCIM is disabled in the user store.");
    }

    /**
     * Get permissions of a group.
     *
     * @param groupName group name.
     * @return String[] of permissions.
     * @throws UserStoreException
     * @throws RolePermissionException
     */
    public String[] getGroupPermissions(String groupName) throws UserStoreException, RolePermissionException {

        return SCIMCommonComponentHolder.getRolePermissionManagementService().getRolePermissions(groupName,
                carbonUM.getTenantId());
    }

    /**
     * Set permissions of a group.
     *
     * @param groupName   group name.
     * @param permissions array of permissions.
     * @throws UserStoreException
     * @throws RolePermissionException
     */
    public void setGroupPermissions(String groupName, String[] permissions) throws RolePermissionException {

        SCIMCommonComponentHolder.getRolePermissionManagementService().setRolePermissions(groupName, permissions);
    }

    /**
     * Add or remove permissions of a group.
     *
     * @param groupName          group name.
     * @param permissionToAdd    permissions to add.
     * @param permissionToRemove permissions to remove.
     * @throws UserStoreException
     * @throws RolePermissionException
     */
    public void updatePermissionListOfGroup(String groupName, String[] permissionToAdd, String[] permissionToRemove)
            throws UserStoreException, RolePermissionException {

        List permissions = Arrays.asList(getGroupPermissions(groupName));
        if (permissions.isEmpty()) {
            if (ArrayUtils.isNotEmpty(permissionToAdd)) {
                SCIMCommonComponentHolder.getRolePermissionManagementService().setRolePermissions(groupName,
                        permissionToAdd);
            }
        } else {
            if (ArrayUtils.isNotEmpty(permissionToAdd)) {
                permissions = ListUtils.union(permissions, Arrays.asList(permissionToAdd));
            }
            if (ArrayUtils.isNotEmpty(permissionToRemove)) {
                permissions = ListUtils.subtract(permissions, Arrays.asList(permissionToRemove));
            }
            SCIMCommonComponentHolder.getRolePermissionManagementService().setRolePermissions(groupName,
                    (String[]) permissions.toArray(new String[0]));
        }
    }

    @Override
    public List<Attribute> getUserSchema() throws CharonException {

        Map<ExternalClaim, LocalClaim> scimClaimToLocalClaimMap =
                getMappedLocalClaimsForDialect(SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT, tenantDomain);

        Map<String, Attribute> filteredFlatAttributeMap = getFilteredUserSchemaAttributes(scimClaimToLocalClaimMap);
        Map<String, Attribute> hierarchicalAttributeMap = buildHierarchicalAttributeMap(filteredFlatAttributeMap);

        List<Attribute> userSchemaAttributesList = new ArrayList(hierarchicalAttributeMap.values());
        if (log.isDebugEnabled()) {
            logSchemaAttributes(userSchemaAttributesList);
        }

        return userSchemaAttributesList;
    }

    /**
     * Get mapped local claims for the claims in specified external claim dialect.
     *
     * @param externalClaimDialect
     * @param tenantDomain
     * @return
     * @throws ClaimMetadataException
     */
    private Map<ExternalClaim, LocalClaim> getMappedLocalClaimsForDialect(String externalClaimDialect,
                                                                          String tenantDomain) throws CharonException {

        try {
            List<ExternalClaim> externalClaimList =
                    this.claimMetadataManagementService.getExternalClaims(externalClaimDialect, tenantDomain);
            List<LocalClaim> localClaimList = this.claimMetadataManagementService.getLocalClaims(tenantDomain);

            Map<ExternalClaim, LocalClaim> externalClaimLocalClaimMap = new HashMap<>();

            if (externalClaimList != null && localClaimList != null) {

                externalClaimList.forEach(externalClaim ->
                        getMappedLocalClaim(externalClaim, localClaimList)
                                .ifPresent(mappedLocalClaim -> externalClaimLocalClaimMap.put(externalClaim,
                                        mappedLocalClaim)));
            }
            return externalClaimLocalClaimMap;

        } catch (ClaimMetadataException e) {
            throw new CharonException("Error while retrieving schema attribute details.", e);
        }
    }

    /**
     * Get mapped local claim for specified external claim.
     *
     * @param externalClaim
     * @param localClaimList
     * @return
     */
    private Optional<LocalClaim> getMappedLocalClaim(ExternalClaim externalClaim, List<LocalClaim> localClaimList) {

        if (localClaimList == null) {
            return Optional.empty();
        }

        return localClaimList.stream()
                .filter(localClaim -> localClaim.getClaimURI().equals(externalClaim.getMappedLocalClaim()))
                .findAny();
    }

    /**
     * Get filtered claims that can be used in the schema attributes.
     * This will allow only the username claim or the claims with supported-by-default value true.
     *
     * @param scimClaimToLocalClaimMap
     * @return
     */
    private Map<String, Attribute> getFilteredUserSchemaAttributes(Map<ExternalClaim, LocalClaim>
                                                                           scimClaimToLocalClaimMap) {

        Map<String, Attribute> filteredFlatAttributeMap = new HashMap<>();

        for (Map.Entry<ExternalClaim, LocalClaim> entry: scimClaimToLocalClaimMap.entrySet()) {

            ExternalClaim scimClaim = entry.getKey();
            LocalClaim mappedLocalClaim = entry.getValue();

            if (isSupportedByDefault(mappedLocalClaim) || isUsernameClaim(scimClaim)) {
                // Return only the schema of supported-by-default claims and the username claim.
                Attribute schemaAttribute = getSchemaAttributes(scimClaim, mappedLocalClaim);
                filteredFlatAttributeMap.put(schemaAttribute.getName(), schemaAttribute);
            }
        }

        return filteredFlatAttributeMap;
    }

    private boolean isSupportedByDefault(LocalClaim mappedLocalClaim) {

        String supportedByDefault = mappedLocalClaim.getClaimProperty(ClaimConstants.SUPPORTED_BY_DEFAULT_PROPERTY);
        return Boolean.parseBoolean(supportedByDefault);
    }

    private boolean isUsernameClaim(ExternalClaim scimClaim) {

        return SCIMConstants.UserSchemaConstants.USER_NAME_URI.equals(scimClaim.getClaimURI());
    }

    /**
     * Build and return the Charon Attribute representation using the claim metadata.
     *
     * @param scimClaim
     * @param mappedLocalClaim
     * @return
     */
    private Attribute getSchemaAttributes(ExternalClaim scimClaim, LocalClaim mappedLocalClaim) {

        String name = scimClaim.getClaimURI();
        if (name.startsWith(scimClaim.getClaimDialectURI())) {
            name = name.substring(scimClaim.getClaimDialectURI().length() + 1);
        }

        AbstractAttribute attribute;
        if (isComplexAttribute(name)) {
            attribute = new ComplexAttribute(name);
        } else {
            attribute = new SimpleAttribute(name, null);
        }

        pupulateBasicAttributes(mappedLocalClaim, attribute);

        return attribute;
    }

    private boolean isComplexAttribute(String name) {

        switch(name) {
            case "name" :
            case "emails" :
            case "phoneNumbers" :
            case "ims" :
            case "photos" :
            case "addresses" :
            case "groups" :
            case "entitlements" :
            case "roles" :
            case "x509Certificates" :
                return true;
            default :
                return false;
        }
    }

    private boolean isMultivaluedAttribute(String name) {

        switch(name) {
            case "emails" :
            case "phoneNumbers" :
            case "ims" :
            case "photos" :
            case "addresses" :
            case "groups" :
            case "entitlements" :
            case "roles" :
            case "x509Certificates" :
                return true;
            default :
                return false;
        }
    }

    /**
     * Populates basic Charon Attributes details using the claim metadata.
     *
     * @param mappedLocalClaim
     * @param attribute
     */
    private void pupulateBasicAttributes(LocalClaim mappedLocalClaim, AbstractAttribute attribute) {

        if (mappedLocalClaim != null) {
            attribute.setDescription(mappedLocalClaim.getClaimProperty(ClaimConstants.DESCRIPTION_PROPERTY));

            attribute.setRequired(Boolean.parseBoolean(mappedLocalClaim.
                    getClaimProperty(ClaimConstants.REQUIRED_PROPERTY)));

            String readOnlyProperty = mappedLocalClaim.getClaimProperty(ClaimConstants.READ_ONLY_PROPERTY);
            if (Boolean.parseBoolean(readOnlyProperty)) {
                attribute.setMutability(SCIMDefinitions.Mutability.READ_ONLY);
            } else {
                attribute.setMutability(SCIMDefinitions.Mutability.READ_WRITE);
            }
        }

        // Fixed schema attributes
        attribute.setCaseExact(false);
        if (attribute instanceof ComplexAttribute) {
            attribute.setType(SCIMDefinitions.DataType.COMPLEX);
        } else {
            attribute.setType(SCIMDefinitions.DataType.STRING);
        }

        attribute.setMultiValued(isMultivaluedAttribute(attribute.getName()));
        attribute.setReturned(SCIMDefinitions.Returned.DEFAULT);
        attribute.setUniqueness(SCIMDefinitions.Uniqueness.NONE);

        if (mappedLocalClaim != null) {
            // Additional schema attributes
            attribute.addAttributeProperty(DISPLAY_NAME_PROPERTY,
                    mappedLocalClaim.getClaimProperty(ClaimConstants.DISPLAY_NAME_PROPERTY));
            attribute.addAttributeProperty(DISPLAY_ORDER_PROPERTY,
                    mappedLocalClaim.getClaimProperty(ClaimConstants.DISPLAY_ORDER_PROPERTY));
            attribute.addAttributeProperty(REGULAR_EXPRESSION_PROPERTY,
                    mappedLocalClaim.getClaimProperty(ClaimConstants.REGULAR_EXPRESSION_PROPERTY));
        }
    }

    /**
     * Builds complex attribute schema with correct sub attributes using the flat attribute map.
     *
     * @param filteredFlatAttributeMap
     * @return
     */
    private Map<String, Attribute> buildHierarchicalAttributeMap(Map<String, Attribute> filteredFlatAttributeMap)
            throws CharonException {

        Map<String, Attribute> simpleAttributeMap = new HashMap<>();

        Map<String, ComplexAttribute> complexAttributeMap = new HashMap<>();
        for (Map.Entry<String, Attribute> userAttribute: filteredFlatAttributeMap.entrySet()) {
            String attributeName = userAttribute.getKey();
            Attribute attribute = userAttribute.getValue();

            if (attributeName.contains(".")) {
                ComplexAttribute parentAttribute = handleSubAttribute(attribute, filteredFlatAttributeMap,
                        complexAttributeMap);
                complexAttributeMap.put(parentAttribute.getName(), parentAttribute);
            } else {
                simpleAttributeMap.put(attributeName, attribute);
            }
        }
        simpleAttributeMap.putAll(complexAttributeMap);

        return simpleAttributeMap;
    }

    /**
     * Set sub attribute to the correct parent attribute and return complex parent attribute.
     *
     * @param attribute
     * @param flatAttributeMap
     * @param complexAttributeMap
     * @return
     */
    private ComplexAttribute handleSubAttribute(Attribute attribute, Map<String, Attribute> flatAttributeMap,
                                                Map<String, ComplexAttribute> complexAttributeMap)
            throws CharonException {

        String attributeName = attribute.getName();
        String parentAttributeName = attributeName.substring(0, attributeName.indexOf("."));
        String subAttributeName = attributeName.substring(attributeName.indexOf(".") + 1);

        ComplexAttribute parentAttribute = (ComplexAttribute) flatAttributeMap.get(parentAttributeName);

        if (parentAttribute == null) {
            parentAttribute = complexAttributeMap.get(parentAttributeName);
        }

        if (parentAttribute == null) {
            parentAttribute = new ComplexAttribute(parentAttributeName);
            pupulateBasicAttributes(null, parentAttribute);
            complexAttributeMap.put(parentAttributeName, parentAttribute);
        }

        if (attribute instanceof AbstractAttribute) {
            ((AbstractAttribute) attribute).setName(subAttributeName);
        } else {
            throw new CharonException("Unsupported attribute type");
        }
        parentAttribute.setSubAttribute(attribute);

        return parentAttribute;
    }

    private void logSchemaAttributes(List<Attribute> userSchemaAttributesList) {

        StringBuffer sb = new StringBuffer();
        sb.append("Final user schema attribute list calculated as: [");
        boolean isFirst = true;
        for (Attribute userSchemaAttribute: userSchemaAttributesList) {

            if (!isFirst) {
                sb.append(", ");
            }

            sb.append("{");
            sb.append(userSchemaAttribute.getName());
            sb.append("}");
        }
        sb.append("]");
        log.debug(sb);
    }
}
