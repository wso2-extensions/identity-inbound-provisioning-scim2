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
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.mgt.policy.PolicyViolationException;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
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
import org.wso2.carbon.user.core.model.Condition;
import org.wso2.carbon.user.core.model.ExpressionAttribute;
import org.wso2.carbon.user.core.model.ExpressionCondition;
import org.wso2.carbon.user.core.model.ExpressionOperation;
import org.wso2.carbon.user.core.model.OperationalCondition;
import org.wso2.carbon.user.core.model.OperationalOperation;
import org.wso2.carbon.user.core.model.UserClaimSearchEntry;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.charon3.core.attributes.Attribute;
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
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.utils.AttributeUtil;
import org.wso2.charon3.core.utils.ResourceManagerUtil;
import org.wso2.charon3.core.utils.codeutils.ExpressionNode;
import org.wso2.charon3.core.utils.codeutils.Node;
import org.wso2.charon3.core.utils.codeutils.OperationNode;
import org.wso2.charon3.core.utils.codeutils.SearchRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.isFilterUsersAndGroupsOnlyFromPrimaryDomainEnabled;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.isFilteringEnhancementsEnabled;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.mandateDomainForGroupNamesInGroupsResponse;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.mandateDomainForUsernamesAndGroupNamesInResponse;
import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.prependDomain;

public class SCIMUserManager implements UserManager {

    public static final String FILTERING_DELIMITER = "*";
    public static final String SQL_FILTERING_DELIMITER = "%";
    private static final String ERROR_CODE_INVALID_USERNAME = "31301";
    private static final String ERROR_CODE_INVALID_CREDENTIAL = "30003";
    private static Log log = LogFactory.getLog(SCIMUserManager.class);
    private UserStoreManager carbonUM = null;
    private ClaimManager carbonClaimManager = null;
    private static final int MAX_ITEM_LIMIT_UNLIMITED = -1;
    private static final String ENABLE_PAGINATED_USER_STORE = "SCIM.EnablePaginatedUserStore";

    public SCIMUserManager(UserStoreManager carbonUserStoreManager, ClaimManager claimManager) {
        carbonUM = carbonUserStoreManager;
        carbonClaimManager = claimManager;
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
            // if we have set a user store under provisioning configuration - we should only use that.
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
        if(StringUtils.isNotBlank(userStoreDomainName) && !isSCIMEnabled(userStoreDomainName)){
            throw new CharonException("Cannot add user through scim to user store " + ". SCIM is not " +
                    "enabled for user store " + userStoreDomainName);
        }

        try {

            //Persist in carbon user store
            if (log.isDebugEnabled()) {
                log.debug("Creating user: " + user.getUserName());
            }
                /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            Map<String, String> claimsMap = AttributeMapper.getClaimsMap(user);

                /*skip groups attribute since we map groups attribute to actual groups in ldap.
                and do not update it as an attribute in user schema*/
            if (claimsMap.containsKey(SCIMConstants.UserSchemaConstants.GROUP_URI)) {
                claimsMap.remove(SCIMConstants.UserSchemaConstants.GROUP_URI);
            }

            /* Skip roles list since we map SCIM groups to local roles internally. It shouldn't be allowed to
                manipulate SCIM groups from user endpoint as this attribute has a mutability of "readOnly". Group
                changes must be applied via Group Resource */
            if (claimsMap.containsKey(SCIMConstants.UserSchemaConstants.ROLES_URI + "." + SCIMConstants.DEFAULT)) {
                claimsMap.remove(SCIMConstants.UserSchemaConstants.ROLES_URI);
            }

            if (carbonUM.isExistingUser(user.getUserName())) {
                String error = "User with the name: " + user.getUserName() + " already exists in the system.";
                throw new ConflictException(error);
            }
            if (claimsMap.containsKey(SCIMConstants.UserSchemaConstants.USER_NAME_URI)) {
                claimsMap.remove(SCIMConstants.UserSchemaConstants.USER_NAME_URI);
            }
            Map<String, String> claimsInLocalDialect = SCIMCommonUtils.convertSCIMtoLocalDialect(claimsMap);
            carbonUM.addUser(user.getUserName(), user.getPassword(), null, claimsInLocalDialect, null);
            log.info("User: " + user.getUserName() + " is created through SCIM.");

            // Get Claims related to SCIM claim dialect
            Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
            // Get required SCIM Claims in local claim dialect.
            List<String> requiredClaimsInLocalDialect = getRequiredClaimsInLocalDialect(scimToLocalClaimsMap,
                    requiredAttributes);
            // Get the user from the user store in order to get the default attributes during the user creation
            // response.
            user = this.getSCIMUser(user.getUserName(), requiredClaimsInLocalDialect, scimToLocalClaimsMap);
            // Set the schemas of the scim user.
            user.setSchemas();
        } catch (UserStoreException e) {
            handleErrorsOnUserNameAndPasswordPolicy(e);
            String errMsg = "Error in adding the user: " + user.getUserName() + " to the user store. ";
            errMsg += e.getMessage();
            throw new CharonException(errMsg, e);
        }
        return user;
    }

    private void handleErrorsOnUserNameAndPasswordPolicy(Throwable e) throws BadRequestException {

        int i = 0; // this variable is used to avoid endless loop if the e.getCause never becomes null.
        while (e != null && i < 10) {

            if (e instanceof UserStoreException && (e.getMessage().contains(ERROR_CODE_INVALID_USERNAME) ||
                    e.getMessage().contains(ERROR_CODE_INVALID_CREDENTIAL))) {
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
            String[] userNames = null;
            if (StringUtils.isNotBlank(userIdLocalClaim)) {
                userNames = carbonUM.getUserList(userIdLocalClaim, userId, UserCoreConstants.DEFAULT_PROFILE);
            }

            if (userNames == null || userNames.length == 0) {
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
                scimUser = this.getSCIMUser(userNames[0], requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                //set the schemas of the scim user
                scimUser.setSchemas();
                log.info("User: " + scimUser.getUserName() + " is retrieved through SCIM.");
            }

        } catch (UserStoreException e) {
            throw new CharonException("Error in getting user information from Carbon User Store for" +
                    "user: " + userId, e);
        }
        return scimUser;
    }

    @Override
    public void deleteUser(String userId) throws NotFoundException, CharonException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting user: " + userId);
        }
        //get the user name of the user with this id
        String[] userNames = null;
        String userName = null;
        try {
            /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            String userIdLocalClaim = SCIMCommonUtils.getSCIMtoLocalMappings().get(SCIMConstants
                    .CommonSchemaConstants.ID_URI);
            if (StringUtils.isNotBlank(userIdLocalClaim)) {
                userNames = carbonUM.getUserList(userIdLocalClaim, userId, UserCoreConstants.DEFAULT_PROFILE);
            }
            String userStoreDomainFromSP = null;
            try {
                userStoreDomainFromSP = getUserStoreDomainFromSP();
            } catch (IdentityApplicationManagementException e) {
                throw new CharonException("Error retrieving User Store name. ", e);
            }
            if (userNames == null || userNames.length == 0) {
                //resource with given id not found
                if (log.isDebugEnabled()) {
                    log.debug("User with id: " + userId + " not found.");
                }
                throw new NotFoundException();
            } else if (userStoreDomainFromSP != null &&
                    !(userStoreDomainFromSP
                            .equalsIgnoreCase(IdentityUtil.extractDomainFromName(userNames[0])))) {
                throw new CharonException("User :" + userNames[0] + "is not belong to user store " +
                        userStoreDomainFromSP + "Hence user updating fail");
            } else {
                //we assume (since id is unique per user) only one user exists for a given id
                userName = userNames[0];
                String userStoreDomainName = IdentityUtil.extractDomainFromName(userName);
                //check if SCIM is enabled for the user store
                if (!isSCIMEnabled(userStoreDomainName)) {
                    throw new CharonException("Cannot delete user: " + userName + " through SCIM from user store: " +
                            userStoreDomainName + ". SCIM is not enabled for user store: " + userStoreDomainName);
                }
                carbonUM.deleteUser(userName);
                log.info("User: " + userName + " is deleted through SCIM.");
            }

        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException("Error in deleting user: " + userName, e);
        }

    }

    @Override
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
        return listUsersWithGET(searchRequest.getFilter(), searchRequest.getStartIndex(), searchRequest.getCount(),
                searchRequest.getSortBy(), searchRequest.getSortOder(), searchRequest.getDomainName(),
                requiredAttributes);
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
        String[] userNames;
        if (StringUtils.isNotEmpty(domainName)) {
            if (canPaginate(offset, limit)) {
                userNames = listUsernames(offset, limit, sortBy, sortOrder, domainName);
            } else {
                userNames = listUsernamesUsingLegacyAPIs(domainName);
            }
        } else {
            if (canPaginate(offset, limit)) {
                userNames = listUsernamesAcrossAllDomains(offset, limit, sortBy, sortOrder);
            } else {
                userNames = listUsernamesAcrossAllDomainsUsingLegacyAPIs();
            }
        }

        if (ArrayUtils.isEmpty(userNames)) {
            if (log.isDebugEnabled()) {
                String message = String.format("There are no users who comply with the requested conditions: "
                        + "startIndex = %d, count = %d", offset, limit);
                if (StringUtils.isNotEmpty(domainName)) {
                    message = String.format(message + ", domain = %s", domainName);
                }
                log.debug(message);
            }
        } else {
            List<Object> scimUsers = getUserDetails(userNames, requiredAttributes);
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
    private String[] listUsernames(int offset, int limit, String sortBy, String sortOrder, String domainName)
            throws CharonException {

        if (isPaginatedUserStoreAvailable() && carbonUM instanceof PaginatedUserStoreManager) {
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
    private String[] listUsernamesUsingLegacyAPIs(String domainName) throws CharonException {

        String[] userNames = null;
        try {
            Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
            String userIdLocalClaim = scimToLocalClaimsMap.get(SCIMConstants.CommonSchemaConstants.ID_URI);
            String claimValue = domainName.toUpperCase() + CarbonConstants.DOMAIN_SEPARATOR + SCIMCommonConstants.ANY;
            if (StringUtils.isNotBlank(userIdLocalClaim)) {
                userNames = carbonUM.getUserList(userIdLocalClaim, claimValue, null);
            }
            return userNames;
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
    private String[] listUsernamesAcrossAllDomains(int offset, int limit, String sortBy, String sortOrder)
            throws CharonException {

        String[] usernames;
        if (isPaginatedUserStoreAvailable() && carbonUM instanceof PaginatedUserStoreManager) {
            if (limit == 0) {
                usernames = listUsernamesAcrossAllDomainsUsingLegacyAPIs();
                usernames = paginateUsers(usernames, limit, offset);
            } else {
                ExpressionCondition condition = new ExpressionCondition(ExpressionOperation.SW.toString(),
                        ExpressionAttribute.USERNAME.toString(), "");
                usernames = filterUsersFromMultipleDomains(null, offset, limit, sortBy, sortOrder, condition);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(" The user store is not a paginated user store manager. Therefore pagination "
                        + "is not supported.");
            }
            throw new CharonException("Pagination is not supported.");
        }
        return usernames;
    }

    /**
     * Method to list usernames of all users across all user stores using legacy APIs.
     *
     * @return Usernames list
     * @throws CharonException Error while listing usernames
     */
    private String[] listUsernamesAcrossAllDomainsUsingLegacyAPIs() throws CharonException {

        String[] userNames = null;
        try {
            Map<String, String> scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
            String userIdLocalClaim = scimToLocalClaimsMap.get(SCIMConstants.CommonSchemaConstants.ID_URI);
            if (StringUtils.isNotBlank(userIdLocalClaim)) {
                userNames = carbonUM.getUserList(userIdLocalClaim, SCIMCommonConstants.ANY, null);
            }
            return userNames;
        } catch (UserStoreException e) {
            throw new CharonException("Error while listing usernames across all domains. ", e);
        }
    }

    /**
     * Method to get user details of usernames.
     *
     * @param userNames          Array of usernames
     * @param requiredAttributes Required attributes for the response
     * @return User list with detailed attributes
     * @throws CharonException Error while retrieving users
     */
    private List<Object> getUserDetails(String[] userNames, Map<String, Boolean> requiredAttributes)
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

            User[] scimUsers;
            if (isPaginatedUserStoreAvailable() && carbonUM instanceof PaginatedUserStoreManager) {
                // Retrieve all SCIM users at once.
                scimUsers = this.getSCIMUsers(userNames, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                users.addAll(Arrays.asList(scimUsers));
            } else {
                // Retrieve SCIM users one by one.
                retriveSCIMUsers(users, userNames, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
            }
        } catch (UserStoreException e) {
            throw new CharonException("Error while retrieving users from user store.", e);
        }
        return users;
    }

    private void retriveSCIMUsers(List<Object> users, String[] userNames, List<String> requiredClaims,
            Map<String, String> scimToLocalClaimsMap) throws CharonException {
        for (String userName : userNames) {
            if (userName.contains(UserCoreConstants.NAME_COMBINER)) {
                userName = userName.split("\\" + UserCoreConstants.NAME_COMBINER)[0];
            }
            String userStoreDomainName = IdentityUtil.extractDomainFromName(userName);
            if (isSCIMEnabled(userStoreDomainName)) {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". "
                            + "Including user : " + userName + " in the response.");
                }
                User scimUser = this.getSCIMUser(userName, requiredClaims, scimToLocalClaimsMap);
                if (scimUser != null) {
                    Map<String, Attribute> attrMap = scimUser.getAttributeList();
                    if (attrMap != null && !attrMap.isEmpty()) {
                        users.add(scimUser);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". "
                            + "Hence user : " + userName + " in this domain is excluded in the response.");
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

            /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            //get user claim values
            Map<String, String> claims = AttributeMapper.getClaimsMap(user);

            //check if username of the updating user existing in the userstore.
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
            if (!carbonUM.isExistingUser(user.getUserName())) {
                throw new CharonException("User name is immutable in carbon user store.");
            }

                /*skip groups attribute since we map groups attribute to actual groups in ldap.
                and do not update it as an attribute in user schema*/
            if (claims.containsKey(SCIMConstants.UserSchemaConstants.GROUP_URI)) {
                claims.remove(SCIMConstants.UserSchemaConstants.GROUP_URI);
            }
            
                /* Skip roles list since we map SCIM groups to local roles internally. It shouldn't be allowed to
                manipulate SCIM groups from user endpoint as this attribute has a mutability of "readOnly". Group
                changes must be applied via Group Resource */
            if (claims.containsKey(SCIMConstants.UserSchemaConstants.ROLES_URI + "." + SCIMConstants.DEFAULT)) {
                claims.remove(SCIMConstants.UserSchemaConstants.ROLES_URI);
            }

            if (claims.containsKey(SCIMConstants.UserSchemaConstants.USER_NAME_URI)) {
                claims.remove(SCIMConstants.UserSchemaConstants.USER_NAME_URI);
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
            Map<String, String> oldClaimList = carbonUM.getUserClaimValues(user.getUserName(), requiredClaimsInLocalDialect
                    .toArray(new String[requiredClaimsInLocalDialect.size()]), null);

            // Get user claims mapped from SCIM dialect to WSO2 dialect.
            Map<String, String> claimValuesInLocalDialect = SCIMCommonUtils.convertSCIMtoLocalDialect(claims);

            updateUserClaims(user, oldClaimList, claimValuesInLocalDialect);

            //if password is updated, set it separately
            if (user.getPassword() != null) {
                carbonUM.updateCredentialByAdmin(user.getUserName(), user.getPassword());
            }
            log.info("User: " + user.getUserName() + " updated through SCIM.");
            return getUser(user.getId(),requiredAttributes);
        } catch (UserStoreException e) {
            handleErrorsOnUserNameAndPasswordPolicy(e);
            throw new CharonException("Error while updating attributes of user: " + user.getUserName(), e);
        } catch (BadRequestException | CharonException e) {
            throw new CharonException("Error occured while trying to update the user", e);
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
     * @param node               Node
     * @param requiredAttributes Required attributes
     * @param offset             Starting index of the count
     * @param limit              Number of required results (count)
     * @param sortBy             SortBy
     * @param sortOrder          Sort order
     * @param domainName         Domain that the filter should perform
     * @return Detailed user list
     * @throws CharonException
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
            if (log.isDebugEnabled())
                log.debug("Listing users by multi attribute filter");
            List<Object> filteredUsers = new ArrayList<>();

            // 0th index is to store total number of results.
            filteredUsers.add(0);

            // Support multi attribute filtering.
            return getMultiAttributeFilteredUsers(node, requiredAttributes, offset, limit, sortBy, sortOrder,
                    domainName, filteredUsers);
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
            int offset, int limit, String sortBy, String sortOrder, String domainName) throws CharonException {

        String[] userNames;

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
                userNames = filterUsersUsingLegacyAPIs(node, limit, offset, domainName);
            } else {
                userNames = filterUsers(node, offset, limit, sortBy, sortOrder, domainName);
            }
        } catch (NotImplementedException e) {
            String errorMessage = String.format("System does not support filter operator: %s", node.getOperation());
            throw new CharonException(errorMessage, e);
        }
        return getDetailedUsers(userNames, requiredAttributes);
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
    private String[] filterUsers(Node node, int offset, int limit, String sortBy, String sortOrder, String domainName)
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
    private String[] filterUsersFromMultipleDomains(Node node, int offset, int limit, String sortBy, String sortOrder,
            Condition conditionForListingUsers) throws CharonException {

        // Filter users when the domain is not set in the request. Then filter through multiple domains.
        String[] userStoreDomainNames = getDomainNames();
        ArrayList<String> filteredUsernames = new ArrayList<>();
        Condition condition;
        for (String userStoreDomainName : userStoreDomainNames) {

            // Check whether the used case is for listing users.
            if (conditionForListingUsers == null) {
                // Create filter condition for each domain for single attribute filter.
                condition = createConditionForSingleAttributeFilter(userStoreDomainName, node);
            } else {
                condition = conditionForListingUsers;
            }

            // Filter users for given condition and domain.
            String[] userNames = filterUsernames(condition, offset, limit, sortBy, sortOrder, userStoreDomainName);
            if (userNames == null) {
                userNames = new String[0];
            }

            // Calculating new offset and limit parameters.
            int numberOfFilteredUsers = userNames.length;
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
            filteredUsernames.addAll(Arrays.asList(userNames));

            // If the limit is changed then filtering needs to be stopped.
            if (limit == 0) {
                break;
            }
        }
        return filteredUsernames.toArray(new String[0]);
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
        String[] skippedUsers = filterUsernames(condition, initialOffset, offset, sortBy, sortOrder, domainName);
        if (skippedUsers == null) {
            skippedUserCount = 0;
        } else {
            skippedUserCount = skippedUsers.length;
        }

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
    private String[] filterUsernames(Condition condition, int offset, int limit, String sortBy, String sortOrder,
            String domainName) throws CharonException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Filtering users in domain : %s with limit: %d and offset: %d.", domainName, limit,
                    offset));
        }
        try {
            return ((PaginatedUserStoreManager) carbonUM)
                    .getUserList(condition, domainName, UserCoreConstants.DEFAULT_PROFILE, limit, offset, sortBy,
                            sortOrder);
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
        } catch (UserStoreException e) {
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
    private String[] filterUsersUsingLegacyAPIs(ExpressionNode node, int limit, int offset, String domainName)
            throws NotImplementedException, CharonException {

        String[] userNames;

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
                if (carbonUM instanceof AbstractUserStoreManager) {
                    String[] roleNames = getRoleNames(attributeName, filterOperation, attributeValue);
                    userNames = getUserListOfRoles(roleNames);
                } else {
                    String errorMessage = String
                            .format("Filter operator %s is not supported by the user store.", filterOperation);
                    throw new NotImplementedException(errorMessage);
                }
            } else {
                // Get the user name of the user with this id.
                userNames = getUserNames(attributeName, filterOperation, attributeValue);
            }
        } catch (UserStoreException e) {
            String errorMessage = String.format("Error while filtering the users for filter with attribute name: %s ,"
                            + " filter operation: %s and attribute value: %s. ", attributeName, filterOperation,
                    attributeValue);
            throw new CharonException(errorMessage, e);
        }
        userNames = paginateUsers(userNames, limit, offset);
        return userNames;
    }

    /**
     * Method to remove duplicate users and get the user details.
     *
     * @param userNames          Filtered user names
     * @param requiredAttributes Required attributes in the response
     * @return Users list with populated attributes
     * @throws CharonException Error in retrieving user details
     */
    private List<Object> getDetailedUsers(String[] userNames, Map<String, Boolean> requiredAttributes)
            throws CharonException {

        List<Object> filteredUsers = new ArrayList<>();
        // 0th index is to store total number of results.
        filteredUsers.add(0);

        // Remove duplicate users.
        HashSet<String> userNamesSet = new HashSet<>(Arrays.asList(userNames));
        userNames = userNamesSet.toArray(new String[0]);

        // Set total number of filtered results.
        filteredUsers.set(0, userNames.length);

        // Get details of the finalized user list.
        filteredUsers.addAll(getFilteredUserDetails(userNames, requiredAttributes));
        return filteredUsers;
    }

    /**
     * This method support multi-attribute filters with paginated search for user(s).
     *
     * @param node
     * @param requiredAttributes
     * @param offset
     * @param limit
     * @param sortBy
     * @param sortOrder
     * @param domainName
     * @param filteredUsers
     * @return
     * @throws CharonException
     */
    private List<Object> getMultiAttributeFilteredUsers(Node node, Map<String, Boolean> requiredAttributes, int offset,
            int limit, String sortBy, String sortOrder, String domainName, List<Object> filteredUsers)
            throws CharonException {

        String[] userNames;
        // Handle pagination.
        if (limit > 0) {
            userNames = getFilteredUsersFromMultiAttributeFiltering(node, offset, limit, sortBy, sortOrder, domainName);
            filteredUsers.set(0, userNames.length);
            filteredUsers.addAll(getFilteredUserDetails(userNames, requiredAttributes));
        } else {
            int maxLimit = getMaxLimit(domainName);
            if (StringUtils.isNotEmpty(domainName)) {
                userNames = getFilteredUsersFromMultiAttributeFiltering(node, offset, maxLimit, sortBy,
                        sortOrder, domainName);
                filteredUsers.set(0, userNames.length);
                filteredUsers.addAll(getFilteredUserDetails(userNames, requiredAttributes));
            } else {
                int totalUserCount = 0;
                // If pagination and domain name are not given, then perform filtering on all available user stores.
                while (carbonUM != null) {
                    // If carbonUM is not an instance of Abstract User Store Manger we can't get the domain name.
                    if (carbonUM instanceof AbstractUserStoreManager) {
                        domainName = carbonUM.getRealmConfiguration().getUserStoreProperty("DomainName");
                        userNames = getFilteredUsersFromMultiAttributeFiltering(node, offset, maxLimit,
                                sortBy, sortOrder, domainName);
                        totalUserCount += userNames.length;
                        filteredUsers.addAll(getFilteredUserDetails(userNames, requiredAttributes));
                    }
                    carbonUM = carbonUM.getSecondaryUserStoreManager();
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
     * @return
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
     * @param node
     * @param attributes
     * @return
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
     * @param domainName
     * @return
     * @throws UserStoreException
     */
    private Map<String, String> getAllAttributes(String domainName) throws UserStoreException {

        ClaimMapping[] userClaims;
        ClaimMapping[] coreClaims;
        ClaimMapping[] extensionClaims = null;

        try {
            coreClaims = carbonClaimManager.getAllClaimMappings(SCIMCommonConstants.SCIM_CORE_CLAIM_DIALECT);
            userClaims = carbonClaimManager.getAllClaimMappings(SCIMCommonConstants.SCIM_USER_CLAIM_DIALECT);
            if (SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema() != null) {
                extensionClaims = carbonClaimManager.getAllClaimMappings(
                        SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema().getURI());
            }
            Map<String, String> attributes = new HashMap<>();
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
            return attributes;
        } catch (UserStoreException e) {
            throw new UserStoreException("Error in filtering users by multi attributes ", e);
        }
    }

    /**
     * Perform multi attribute filtering.
     *
     * @param node
     * @param offset
     * @param limit
     * @param sortBy
     * @param sortOrder
     * @param domainName
     * @return
     * @throws CharonException
     */
    private String[] getFilteredUsersFromMultiAttributeFiltering(Node node, int offset, int limit, String sortBy,
                                                                 String sortOrder, String domainName)
            throws CharonException {

        String[] userNames;

        try {
            if (StringUtils.isEmpty(domainName)) {
                domainName = "PRIMARY";
            }
            Map<String, String> attributes = getAllAttributes(domainName);
            if (log.isDebugEnabled()) {
                log.debug("Invoking the do get user list for domain: " + domainName);
            }
            userNames = ((PaginatedUserStoreManager) carbonUM).getUserList(getCondition(node, attributes), domainName,
                    UserCoreConstants.DEFAULT_PROFILE, limit, offset, sortBy, sortOrder);
            return userNames;
        } catch (UserStoreException e) {
            throw new CharonException("Error in filtering users by multi attributes ", e);
        }
    }

    /**
     * Get required claim details for filtered user.
     *
     * @param userNames
     * @param requiredAttributes
     * @return
     * @throws CharonException
     */
    private List<Object> getFilteredUserDetails(String[] userNames, Map<String, Boolean> requiredAttributes)
            throws CharonException {

        List<Object> filteredUsers = new ArrayList<>();

        if (userNames == null || userNames.length == 0) {
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

                User[] scimUsers;
                if (isPaginatedUserStoreAvailable()) {
                    if (carbonUM instanceof PaginatedUserStoreManager) {
                        scimUsers = this.getSCIMUsers(userNames, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                        filteredUsers.addAll(Arrays.asList(scimUsers));
                    } else {
                        addSCIMUsers(filteredUsers, userNames, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                    }
                } else {
                    addSCIMUsers(filteredUsers, userNames, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                }
            } catch (UserStoreException e) {
                throw new CharonException("Error in retrieve user details. ", e);
            }
        }
        return filteredUsers;
    }

    private void addSCIMUsers(List<Object> filteredUsers, String[] userNames, List<String> requiredClaims,
                              Map<String, String> scimToLocalClaimsMap)
            throws CharonException {

        User scimUser;
        for (String userName : userNames) {
            if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
                continue;
            }
            String userStoreDomainName = IdentityUtil.extractDomainFromName(userName);
            if (isSCIMEnabled(userStoreDomainName)) {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Including user : " + userName + " in the response.");
                }
                scimUser = this.getSCIMUser(userName, requiredClaims, scimToLocalClaimsMap);
                //if SCIM-ID is not present in the attributes, skip
                if (scimUser != null && StringUtils.isBlank(scimUser.getId())) {
                    continue;
                }
                filteredUsers.add(scimUser);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Hence user : "+ userName + " in this domain is excluded in the response.");
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
            //we assume (since id is unique per user) only one user exists for a given id
            scimUser = this.getSCIMUser(userName, requiredClaimsInLocalDialect, scimToLocalClaimsMap);

            if (scimUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug("User with userName : " + userName + " does not exist in the system.");
                }
                throw new NotFoundException("No such user exist");
            } else {
                //set the schemas of the scim user
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
            //modify display name if no domain is specified, in order to support multiple user store feature
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

            if(!isInternalOrApplicationGroup(domainName) && StringUtils.isNotBlank(domainName) && !isSCIMEnabled
                    (domainName)){
                throw new CharonException("Cannot create group through scim to user store " + ". SCIM is not " +
                        "enabled for user store " + domainName);
            }
            group.setDisplayName(roleNameWithDomain);
            //check if the group already exists
            if (carbonUM.isExistingRole(group.getDisplayName(), false)) {
                String error = "Group with name: " + group.getDisplayName() +" already exists in the system.";
                throw new ConflictException(error);
            }

                /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
                /*if members are sent when creating the group, check whether users already exist in the
                user store*/
            List<Object> userIds = group.getMembers();
            List<String> userDisplayNames = group.getMembersWithDisplayName();
            if (CollectionUtils.isNotEmpty(userIds)) {
                List<String> members = new ArrayList<>();
                for (Object userId : userIds) {
                    String userIdLocalClaim = SCIMCommonUtils.getSCIMtoLocalMappings().get(SCIMConstants
                            .CommonSchemaConstants.ID_URI);
                    String[] userNames = null;
                    if (StringUtils.isNotBlank(userIdLocalClaim)) {
                        userNames = carbonUM.getUserList(userIdLocalClaim, (String) userId, UserCoreConstants
                                .DEFAULT_PROFILE);
                    }
                    if (userNames == null || userNames.length == 0) {
                        String error = "User: " + userId + " doesn't exist in the user store. " +
                                "Hence, can not create the group: " + group.getDisplayName();
                        throw new IdentitySCIMException(error);
                    } else if (userNames[0].indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0 &&
                            !StringUtils.containsIgnoreCase(userNames[0], domainName)) {
                        String error = "User: " + userId + " doesn't exist in the same user store. " +
                                "Hence, can not create the group: " + group.getDisplayName();
                        throw new IdentitySCIMException(error);
                    } else {
                        members.add(userNames[0]);
                        if (CollectionUtils.isNotEmpty(userDisplayNames)) {
                            boolean userContains = false;
                            for (String user : userDisplayNames) {
                                user =
                                        user.indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0
                                                ? user.split(UserCoreConstants.DOMAIN_SEPARATOR)[1]
                                                : user;
                                if (user.equalsIgnoreCase(userNames[0].indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0
                                        ? userNames[0].split(UserCoreConstants.DOMAIN_SEPARATOR)[1]
                                        : userNames[0])) {
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
                //add other scim attributes in the identity DB since user store doesn't support some attributes.
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
                scimGroupHandler.createSCIMAttributes(group);
                carbonUM.addRole(group.getDisplayName(),
                        members.toArray(new String[members.size()]), null, false);
                log.info("Group: " + group.getDisplayName() + " is created through SCIM.");
            } else {
                //add other scim attributes in the identity DB since user store doesn't support some attributes.
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
                scimGroupHandler.createSCIMAttributes(group);
                carbonUM.addRole(group.getDisplayName(), null, null, false);
                log.info("Group: " + group.getDisplayName() + " is created through SCIM.");
            }
        } catch (UserStoreException e) {
            try {
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
                scimGroupHandler.deleteGroupAttributes(group.getDisplayName());
            } catch (UserStoreException | IdentitySCIMException ex) {
                log.error("Error occurred while doing rollback operation of the SCIM table entry for role: " + group.getDisplayName(), ex);
                throw new CharonException("Error occurred while doing rollback operation of the SCIM table entry for role: " + group.getDisplayName(), e);
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
            //get group name by Id
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
            /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);

            //get group name by id
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
        startIndex  = (startIndex < 1 ? 1 : startIndex);
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
        } else if (count != null && count == 0) {
            return Collections.emptyList();
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
            return groupHandler.listSCIMRoles();
        } else {
            // If the domain is specified create a attribute value with the domain name.
            String searchValue = domainName + CarbonConstants.DOMAIN_SEPARATOR + SCIMCommonConstants.ANY;

            List<String> roleList;
            // Retrieve roles using the above search value.
            if (isInternalOrApplicationGroup(domainName)) {
                // Support for hybrid roles listing with domain parameter. ex: domain=Application.
                roleList = Arrays.asList(filterHybridRoles(domainName, searchValue));
            } else {
                // Retrieve roles using the above attribute value.
                roleList = Arrays.asList(((AbstractUserStoreManager) carbonUM)
                        .getRoleNames(searchValue, MAX_ITEM_LIMIT_UNLIMITED, true, true, true));
            }
            Set<String> roleNames = new HashSet<>(roleList);
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
            String sortOrder, String domainName, Map<String, Boolean> requiredAttributes) throws CharonException {

        String attributeName = node.getAttributeValue();
        String filterOperation = node.getOperation();
        String attributeValue = node.getValue();
        if (log.isDebugEnabled()) {
            log.debug("Filtering groups with filter: " + attributeName + " + " + filterOperation + " + "
                    + attributeValue);
        }
        // Check whether the filter operation is supported for filtering in groups.
        if (isFilteringNotSupported(filterOperation)){
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
            String[] roleList = getGroupList(node, domainName);
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
     * @param roleName       Role name
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
    public Group updateGroup(Group oldGroup, Group newGroup, Map<String, Boolean> requiredAttributes)
            throws CharonException {

        try {
            String userStoreDomainFromSP = getUserStoreDomainFromSP();

            if(userStoreDomainFromSP != null && !userStoreDomainFromSP.equalsIgnoreCase(
                    IdentityUtil.extractDomainFromName(oldGroup.getDisplayName()))) {
                throw new CharonException("Group :" + oldGroup.getDisplayName() + "is not belong to user store " +
                        userStoreDomainFromSP + "Hence group updating fail");
            }
            oldGroup.setDisplayName(IdentityUtil.addDomainToName(UserCoreUtil.removeDomainFromName(oldGroup.getDisplayName()),
                    IdentityUtil.extractDomainFromName(oldGroup.getDisplayName())));

            newGroup.setDisplayName(IdentityUtil.addDomainToName(UserCoreUtil.removeDomainFromName(newGroup.getDisplayName()),
                    IdentityUtil.extractDomainFromName(newGroup.getDisplayName())));

            String primaryDomain = IdentityUtil.getPrimaryDomainName();
            if (IdentityUtil.extractDomainFromName(newGroup.getDisplayName()).equals(primaryDomain) && !(IdentityUtil
                    .extractDomainFromName(oldGroup.getDisplayName())
                    .equals(primaryDomain))) {
                String userStoreDomain = IdentityUtil.extractDomainFromName(oldGroup.getDisplayName());
                newGroup.setDisplayName(IdentityUtil.addDomainToName(newGroup.getDisplayName(), userStoreDomain));

            } else if (!IdentityUtil.extractDomainFromName(oldGroup.getDisplayName())
                    .equals(IdentityUtil.extractDomainFromName(newGroup.getDisplayName()))) {
                throw new IdentitySCIMException(
                        "User store domain of the group is not matching with the given SCIM group Id.");
            }

            newGroup.setDisplayName(SCIMCommonUtils.getGroupNameWithDomain(newGroup.getDisplayName()));
            oldGroup.setDisplayName(SCIMCommonUtils.getGroupNameWithDomain(oldGroup.getDisplayName()));

            if (log.isDebugEnabled()) {
                log.debug("Updating group: " + oldGroup.getDisplayName());
            }

            String groupName = newGroup.getDisplayName();
            String userStoreDomainForGroup = IdentityUtil.extractDomainFromName(groupName);

            if (newGroup.getMembers() != null && !(newGroup.getMembers().isEmpty()) &&
                    !isInternalOrApplicationGroup(userStoreDomainForGroup)) {
                newGroup = addDomainToUserMembers(newGroup, userStoreDomainForGroup);
            }
            boolean updated = false;
                /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);

            // Find out added user's user ids as a list.
            List<Object> newlyAddedUserIds = newGroup.getMembers();
            List<Object> oldGroupUserIds = oldGroup.getMembers();
            if (oldGroupUserIds != null && oldGroupUserIds.size() > 0) {
                newlyAddedUserIds.removeAll(oldGroup.getMembers());
            }
            // Find out added members and deleted members..
            List<String> addedMembers = new ArrayList<>();
            List<String> deletedMembers = new ArrayList<>();

            List<String> oldMembers = oldGroup.getMembersWithDisplayName();
            List<String> newMembers = newGroup.getMembersWithDisplayName();
            if (newMembers != null) {
                //check for deleted members
                if (CollectionUtils.isNotEmpty(oldMembers)) {
                    for (String oldMember : oldMembers) {
                        if (newMembers != null && newMembers.contains(oldMember)) {
                            continue;
                        }
                        deletedMembers.add(oldMember);
                    }
                }

                //check for added members
                if (CollectionUtils.isNotEmpty(newMembers)) {
                    for (String newMember : newMembers) {
                        if (oldMembers != null && oldMembers.contains(newMember)) {
                            continue;
                        }
                        doUserValidation(newMember, userStoreDomainForGroup, oldGroup.getDisplayName(),
                                newlyAddedUserIds);
                        addedMembers.add(newMember);
                    }
                }
            }

            // We do not update Identity_SCIM DB here since it is updated in SCIMUserOperationListener's methods.
            // Update name if it is changed
            if (!(oldGroup.getDisplayName().equalsIgnoreCase(newGroup.getDisplayName()))) {
                // Update group name in carbon UM
                carbonUM.updateRoleName(oldGroup.getDisplayName(), newGroup.getDisplayName());
                updated = true;
            }

            // Update the group with added members and deleted members.
            if (CollectionUtils.isNotEmpty(addedMembers) || CollectionUtils.isNotEmpty(deletedMembers)) {
                carbonUM.updateUserListOfRole(newGroup.getDisplayName(),
                        deletedMembers.toArray(new String[deletedMembers.size()]),
                        addedMembers.toArray(new String[addedMembers.size()]));
                updated = true;
            }

            if (updated) {
                log.info("Group: " + oldGroup.getDisplayName() + " is updated through SCIM.");
                // Duplicate may exist in newGroup, to make sure, query the corresponding group again and return it.
                Group newUpdatedGroup = getGroup(newGroup.getId(), requiredAttributes);
                return newUpdatedGroup;
            } else {
                log.warn("There is no updated field in the group: " + oldGroup.getDisplayName() +
                        ". Therefore ignoring the provisioning.");
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

    /**
     * Perform user validation, check provided added member(s) details are exists in the user store. Else throw
     * corresponding error
     *
     * @param userName
     * @param userStoreDomainForGroup
     * @param displayName
     * @param addedUserIdsList
     * @throws IdentitySCIMException
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private void doUserValidation(String userName, String userStoreDomainForGroup, String displayName,
            List<Object> addedUserIdsList) throws IdentitySCIMException, org.wso2.carbon.user.core.UserStoreException {

        // Compare user store domain of group and user store domain of user name, if there is a mismatch do not
        // update the group.
        String userStoreDomainForUser = IdentityUtil.extractDomainFromName(userName);
        if (!isInternalOrApplicationGroup(userStoreDomainForGroup) && !userStoreDomainForGroup
                .equalsIgnoreCase(userStoreDomainForUser)) {
            throw new IdentitySCIMException(userName + " does not belongs to user store " + userStoreDomainForGroup);
        }

        // Check if the user ids & associated user name sent in updated (new) group exist in the user store.
        if (userName != null) {
            String userId = carbonUM.getUserClaimValue(userName, SCIMConstants.CommonSchemaConstants.ID_URI, null);
            if (userId == null || userId.isEmpty()) {
                String error = "User: " + userName + " doesn't exist in the user store. Hence, can not update the "
                        + "group: " + displayName;
                throw new IdentitySCIMException(error);
            } else {
                if (!UserCoreUtil.isContain(userId, addedUserIdsList.toArray(new String[addedUserIdsList.size()]))) {
                    throw new IdentitySCIMException("Given SCIM user Id and name not matching..");
                }
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
     * @param userName
     * @param claimURIList
     * @return
     * @throws CharonException
     */
    private User getSCIMUser(String userName, List<String> claimURIList, Map<String, String> scimToLocalClaimsMap)
            throws CharonException {
        User scimUser = null;

        String userStoreDomainName = IdentityUtil.extractDomainFromName(userName);
        if(StringUtils.isNotBlank(userStoreDomainName) && !isSCIMEnabled(userStoreDomainName)){
            throw new CharonException("Cannot get user through scim to user store " + ". SCIM is not " +
                    "enabled for user store " + userStoreDomainName);
        }
        try {
            //obtain user claim values
            Map<String, String> userClaimValues = carbonUM.getUserClaimValues(
                    userName, claimURIList.toArray(new String[claimURIList.size()]), null);
            Map<String, String> attributes = SCIMCommonUtils.convertLocalToSCIMDialect(userClaimValues,
                    scimToLocalClaimsMap);

            if (!attributes.containsKey(SCIMConstants.CommonSchemaConstants.ID_URI)) {
                return scimUser;
            }

            //skip simple type addresses claim because it is complex with sub types in the schema
            if (attributes.containsKey(SCIMConstants.UserSchemaConstants.ADDRESSES_URI)) {
                attributes.remove(SCIMConstants.UserSchemaConstants.ADDRESSES_URI);
            }

            // Add username with domain name
            attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, userName);

            // Location URI is not available for users who created from the mgt console also location URI is not
            // tenant aware, so need to update the location URI according to the tenant.
            String locationURI = SCIMCommonUtils
                    .getSCIMUserURL(attributes.get(SCIMConstants.CommonSchemaConstants.ID_URI));
            attributes.put(SCIMConstants.CommonSchemaConstants.LOCATION_URI, locationURI);

            if (!attributes.containsKey(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI)) {
                attributes.put(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI, SCIMConstants.USER);
            }

            //get groups of user and add it as groups attribute
            String[] roles = carbonUM.getRoleListOfUser(userName);
            // Add username with domain name
            if (mandateDomainForUsernamesAndGroupNamesInResponse()) {
                userName = prependDomain(userName);
            }
            //construct the SCIM Object from the attributes
            scimUser = (User) AttributeMapper.constructSCIMObjectFromAttributes(attributes, 1);

            Map<String, Group> groupMetaAttributesCache = new HashMap<>();
            //add groups of user:
            for (String role : roles) {
                if (UserCoreUtil.isEveryoneRole(role, carbonUM.getRealmConfiguration())
                        || CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME.equalsIgnoreCase(role)
                        || role.toLowerCase().startsWith((UserCoreConstants.INTERNAL_DOMAIN +
                        CarbonConstants.DOMAIN_SEPARATOR).toLowerCase())) {
                    // carbon specific roles do not possess SCIM info, hence
                    // skipping them.
                    // skip intenal roles
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
        } catch (UserStoreException | CharonException | NotFoundException | IdentitySCIMException |BadRequestException e) {
            throw new CharonException("Error in getting user information for user: " + userName, e);
        }
        return scimUser;
    }

    /**
     * get the specified user from the store
     *
     * @param userNames    Array of usernames
     * @param claimURIList Requested claim list
     * @return Array of SCIM User
     * @throws CharonException CharonException
     */
    private User[] getSCIMUsers(String[] userNames, List<String> claimURIList, Map<String, String>
            scimToLocalClaimsMap) throws CharonException {

        List<User> scimUsers = new ArrayList<>();

        //obtain user claim values
        UserClaimSearchEntry[] searchEntries;
        Map<String, List<String>> usersRoles;

        try {
            searchEntries = ((AbstractUserStoreManager) carbonUM).getUsersClaimValues(
                    userNames, claimURIList.toArray(new String[claimURIList.size()]), null);

            usersRoles = ((AbstractUserStoreManager) carbonUM).getRoleListOfUsers(userNames);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException("Error occurred while retrieving SCIM user information", e);
        }

        Map<String, Group> groupMetaAttributesCache = new HashMap<>();

        for (String userName : userNames) {
            String userStoreDomainName = IdentityUtil.extractDomainFromName(userName);
            if (isSCIMEnabled(userStoreDomainName)) {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Including user : " + userName + " in the response.");
                }
                User scimUser;
                Map<String, String> userClaimValues = new HashMap<>();
                for (UserClaimSearchEntry entry : searchEntries) {
                    if (StringUtils.isNotBlank(entry.getUserName()) && entry.getUserName().equals(userName)) {
                        userClaimValues = entry.getClaims();
                    }
                }
                Map<String, String> attributes;
                try {
                    attributes = SCIMCommonUtils.convertLocalToSCIMDialect(userClaimValues, scimToLocalClaimsMap);
                } catch (UserStoreException e) {
                    throw new CharonException("Error in converting local claims to SCIM dialect for user: " + userName, e);
                }

                try {
                    if (!attributes.containsKey(SCIMConstants.CommonSchemaConstants.ID_URI)) {
                        continue;
                    }
                    //skip simple type addresses claim because it is complex with sub types in the schema
                    if (attributes.containsKey(SCIMConstants.UserSchemaConstants.ADDRESSES_URI)) {
                        attributes.remove(SCIMConstants.UserSchemaConstants.ADDRESSES_URI);
                    }

                    //get groups of user and add it as groups attribute
                    List<String> roleList = usersRoles.get(userName);
                    String[] roles = new String[0];
                    if (CollectionUtils.isNotEmpty(roleList)) {
                        roles = roleList.toArray(new String[0]);
                    }
                    // Add username with domain name
                    if (mandateDomainForUsernamesAndGroupNamesInResponse()) {
                        userName = prependDomain(userName);
                    }
                    attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, userName);
                    //construct the SCIM Object from the attributes
                    scimUser = (User) AttributeMapper.constructSCIMObjectFromAttributes(attributes, 1);

                    //add groups of user
                    for (String role : roles) {
                        if (UserCoreUtil.isEveryoneRole(role, carbonUM.getRealmConfiguration())
                                || CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME.equalsIgnoreCase(role)
                                || role.toLowerCase().startsWith((UserCoreConstants.INTERNAL_DOMAIN +
                                CarbonConstants.DOMAIN_SEPARATOR).toLowerCase())) {
                            // carbon specific roles do not possess SCIM info, hence
                            // skipping them.
                            // skip internal roles
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
                            scimUser.setGroup(null, group.getId(), role);
                        }
                    }
                } catch (UserStoreException | CharonException | NotFoundException | IdentitySCIMException | BadRequestException e) {
                    throw new CharonException("Error in getting user information for user: " + userName, e);
                }

                if (scimUser != null) {
                    scimUsers.add(scimUser);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Hence user : "+ userName + " in this domain is excluded in the response.");
                }
            }
        }
        return scimUsers.toArray(new User[0]);
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
     * @param userstoreDomain user store domain
     * @return whether passed domain name is "internal" or "application"
     */
    private boolean isInternalOrApplicationGroup(String userstoreDomain){
        if(StringUtils.isNotBlank(userstoreDomain) &&
                (SCIMCommonConstants.APPLICATION_DOMAIN.equalsIgnoreCase(userstoreDomain) ||
                        SCIMCommonConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userstoreDomain))){
            return true;
        }
        return false;
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
            throws CharonException, org.wso2.carbon.user.core.UserStoreException, IdentitySCIMException, BadRequestException {

        String userStoreDomainName = IdentityUtil.extractDomainFromName(groupName);
        if(!isInternalOrApplicationGroup(userStoreDomainName) && StringUtils.isNotBlank(userStoreDomainName) &&
                !isSCIMEnabled(userStoreDomainName)){
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
        String[] userNames = carbonUM.getUserListOfRole(groupName);

        //get the ids of the users and set them in the group with id + display name
        if (userNames != null && userNames.length != 0) {
            for (String userName : userNames) {
                String userId = carbonUM.getUserClaimValue(userName, SCIMConstants.CommonSchemaConstants.ID_URI, null);
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

    private List<String> getMappedClaimList(Map<String, Boolean> requiredAttributes){
        ArrayList<String> claimsList = new ArrayList<>();

        for(Map.Entry<String, Boolean> claim : requiredAttributes.entrySet()){
            if(claim.getValue().equals(true)){


            } else {
                claimsList.add(claim.getKey());
            }
        }


        return claimsList;
    }

    /*
     * This returns the only required attributes for value querying
     * @param claimURIList
     * @param requiredAttributes
     * @return
     */
    private List<String> getOnlyRequiredClaims(Set<String> claimURIList, Map<String, Boolean> requiredAttributes) {
        List<String> requiredClaimList = new ArrayList<>();
        for(String requiredClaim : requiredAttributes.keySet()) {
            if(requiredAttributes.get(requiredClaim)) {
                if (claimURIList.contains(requiredClaim)) {
                    requiredClaimList.add(requiredClaim);
                } else {
                    String[] parts = requiredClaim.split("[.]");
                    for (String claim : claimURIList) {
                        if (parts.length == 3) {
                            if (claim.contains(parts[0] +"." + parts[1])) {
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
    private String[] paginateUsers(String[] users, int limit, int offset) {

        // If the results are empty, an empty list should be returned.
        if (users == null) {
            return new String[0];
        }
        Arrays.sort(users);

        // Validate offset value.
        if (offset <= 0) {
            offset = 1;
        }

        // If the results are less than the offset, return an empty user list.
        if (offset > users.length) {
            return new String[0];
        }

        // If the limit is zero, all the users needs to be returned after verifying the offset.
        if (limit <= 0) {
            if (offset == 1) {
                // This is to support backward compatibility.
                return users;
            } else {
                return Arrays.copyOfRange(users, offset - 1, users.length);
            }
        } else {
            // If users.length > limit + offset, then return only the users bounded by the offset and the limit.
            if (users.length > limit + offset) {
                return Arrays.copyOfRange(users, offset - 1, limit + offset - 1);
            } else {
                // Return all the users from the offset.
                return Arrays.copyOfRange(users, offset - 1, users.length);
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

    private String[] getUserListOfRoles(String[] roleNames) throws org.wso2.carbon.user.core.UserStoreException {

        String[] userNames;
        Set<String> users = new HashSet<>();
        if (roleNames != null) {
            for (String roleName : roleNames) {
                users.addAll(Arrays.asList(carbonUM.getUserListOfRole(roleName)));
            }
        }
        userNames = users.toArray(new String[0]);
        return userNames;
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
            String attributeValue, String delimiter, String[] attributeItems) {

        String searchAttribute;
        if (log.isDebugEnabled()) {
            log.debug(String.format(
                    "Domain detected in attribute value: %s for filter attribute: %s for " + "filter operation; %s.",
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
    private String[] getRoleNames(String attributeName, String filterOperation, String attributeValue)
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
            return ((AbstractUserStoreManager) carbonUM)
                    .getRoleNames(searchAttribute, MAX_ITEM_LIMIT_UNLIMITED, false, true, true);
        } else {
            return ((AbstractUserStoreManager) carbonUM)
                    .getRoleNames(searchAttribute, MAX_ITEM_LIMIT_UNLIMITED, true, true, true);
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
    private String[] getUserNames(String attributeName, String filterOperation, String attributeValue)
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
        return carbonUM.getUserList(attributeNameInLocalDialect, searchAttribute, UserCoreConstants.DEFAULT_PROFILE);
    }

    /**
     * Get the list of groups that matches the search criteria.
     *
     * @param expressionNode Expression node for the filter.
     * @param domainName Domain name
     * @return List of user groups
     * @throws org.wso2.carbon.user.core.UserStoreException
     * @throws IdentitySCIMException
     */
    private String[] getGroupList(ExpressionNode expressionNode, String domainName)
            throws org.wso2.carbon.user.core.UserStoreException, CharonException {

        String attributeName = expressionNode.getAttributeValue();
        String filterOperation = expressionNode.getOperation();
        String attributeValue = expressionNode.getValue();

        // Groups endpoint only support display uri and value uri.
        if (attributeName.equals(SCIMConstants.GroupSchemaConstants.DISPLAY_URI) || attributeName
                .equals(SCIMConstants.GroupSchemaConstants.VALUE_URI)) {
            String[] userList;

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
            if (userList != null) {
                for (String userName : userList) {
                    fullRoleList.addAll(Arrays.asList(carbonUM.getRoleListOfUser(userName)));
                }
            }
            return fullRoleList.toArray(new String[0]);
        } else if (attributeName.equals(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME_URI)) {
            attributeValue = prependDomainNameToTheAttributeValue(attributeValue, domainName);
            return getRoleNames(attributeName, filterOperation, attributeValue);
        } else {
            try {
                return getGroupNamesFromDB(attributeName, filterOperation, attributeValue, domainName);
            } catch (IdentitySCIMException e) {
                throw new CharonException("Error in retrieving SCIM Group information from database.", e);
            }
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
    private String[] getGroupNamesFromDB(String attributeName, String filterOperation, String attributeValue,
            String domainName) throws org.wso2.carbon.user.core.UserStoreException, IdentitySCIMException {

        String searchAttribute = getSearchAttribute(attributeName, filterOperation, attributeValue,
                SQL_FILTERING_DELIMITER);
        SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
        if (log.isDebugEnabled()) {
            log.debug(String.format("Filtering roleNames from DB from search attribute: %s", searchAttribute));
        }
        return groupHandler.getGroupListFromAttributeName(attributeName, searchAttribute, domainName);
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
                claim.equals(claimMappings.get(SCIMConstants.UserSchemaConstants.ROLES_URI + "." + SCIMConstants.DEFAULT)) ||
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
     * @param user {@link User} object.
     * @param oldClaimList User claim list for the user's existing state.
     * @param newClaimList User claim list for the user's new state.
     * @throws UserStoreException Error while accessing the user store.
     * @throws CharonException {@link CharonException}.
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
                carbonUM.deleteUserClaimValue(user.getUserName(), entry.getKey(), null);
            }
        }

        // Update user claims.
        userClaimsToBeModified.putAll(userClaimsToBeAdded);
        carbonUM.setUserClaimValues(user.getUserName(), userClaimsToBeModified, null);
    }

    /**
     * Method to filter hybrid roles (Application & Internal) from a search value.
     *
     * @param domainInAttributeValue domain of the hybrid role
     * @param searchAttribute        search value
     * @return Array of filtered hybrid roles.
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private String[] filterHybridRoles(String domainInAttributeValue, String searchAttribute)
            throws org.wso2.carbon.user.core.UserStoreException {

        List<String> roleList = new ArrayList<>();
        // Get filtered hybrid roles by passing noInternalRoles=false.
        String[] hybridRoles = ((AbstractUserStoreManager) carbonUM)
                .getRoleNames(searchAttribute, MAX_ITEM_LIMIT_UNLIMITED, false, true, true);
        // Iterate through received hybrid roles and filter out specific hybrid role domain(Application or Internal) values
        for (String hybridRole : hybridRoles) {
            if (domainInAttributeValue != null && !hybridRole.startsWith(domainInAttributeValue)) {
                continue;
            }
            if (hybridRole.toLowerCase().startsWith(SCIMCommonConstants.INTERNAL_DOMAIN.toLowerCase()) || hybridRole
                    .toLowerCase().startsWith(SCIMCommonConstants.APPLICATION_DOMAIN.toLowerCase())) {
                roleList.add(hybridRole);
            }
        }
        return roleList.toArray(new String[roleList.size()]);
    }
}
