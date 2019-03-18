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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
            return listUsers(requiredAttributes, startIndex, count, domainName);
        }
    }

    @Override
    public List<Object> listUsersWithPost(SearchRequest searchRequest, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {
        return listUsersWithGET(searchRequest.getFilter(), searchRequest.getStartIndex(), searchRequest.getCount(),
                searchRequest.getSortBy(), searchRequest.getSortOder(), searchRequest.getDomainName(),
                requiredAttributes);
    }

    private List<Object> listUsers(Map<String, Boolean> requiredAttributes, int offset, int limit, String domainName) throws CharonException {

        ClaimMapping[] coreClaims;
        ClaimMapping[] userClaims;
        ClaimMapping[] extensionClaims = null;
        List<Object> users = new ArrayList<>();
        //0th index is to store total number of results;
        users.add(0);
        try {
            String[] userNames = null;
            Map<String, String> scimToLocalClaimsMap;
            if (domainName==null) {
                scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
                String userIdLocalClaim = scimToLocalClaimsMap.get(SCIMConstants
                        .CommonSchemaConstants.ID_URI);
                if (StringUtils.isNotBlank(userIdLocalClaim)) {
                    userNames = carbonUM.getUserList(userIdLocalClaim, "*", null);
                    userNames = paginateUsers(userNames, limit, offset);// pagination enabled
                }
            } else {
                scimToLocalClaimsMap = SCIMCommonUtils.getSCIMtoLocalMappings();
                String userNameClaim = scimToLocalClaimsMap.get(SCIMConstants.UserSchemaConstants.USER_NAME_URI);
                String claimValue = domainName.toUpperCase() + CarbonConstants.DOMAIN_SEPARATOR;
                userNames = getUserNames(userNameClaim, SCIMCommonConstants.SW, claimValue);
                userNames = paginateUsers(userNames, limit, offset);// pagination enabled
            }
            if (userNames != null && userNames.length != 0) {
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

                if (isPaginatedUserStoreAvailable()) {
                    if (carbonUM instanceof PaginatedUserStoreManager) {
                        User[] scimUsers = this.getSCIMUsers(userNames, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                        users.addAll(Arrays.asList(scimUsers));
                    } else {
                        retriveSCIMUsers(users, userNames, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                    }
                } else {
                    retriveSCIMUsers(users, userNames, requiredClaimsInLocalDialect, scimToLocalClaimsMap);
                }

                //set the totalResults value in index 0
                users.set(0, users.size()-1);
            }
        } catch (UserStoreException e) {
            throw new CharonException("Error while retrieving users from user store..", e);
        }
        log.info("User list is retrieved through SCIM.");
        return users;
    }

    private void retriveSCIMUsers(List<Object> users, String[] userNames, List<String> requiredClaims, Map<String,
            String> scimToLocalClaimsMap)
            throws CharonException {
        for (String userName : userNames) {
            if (userName.contains(UserCoreConstants.NAME_COMBINER)) {
                userName = userName.split("\\" + UserCoreConstants.NAME_COMBINER)[0];
            }
            String userStoreDomainName = IdentityUtil.extractDomainFromName(userName);
            if (isSCIMEnabled(userStoreDomainName)) {
                if (log.isDebugEnabled()) {
                    log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Including user : " + userName + " in the response.");
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
                    log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". " +
                            "Hence user : " + userName + " in this domain is excluded in the response.");
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

            Map<String, String> oldClaimList = carbonUM.getUserClaimValues(user.getUserName(), requiredClaimsInLocalDialect
                    .toArray(new String[requiredClaims.size()]), null);

            for (Map.Entry<String, String> entry : oldClaimList.entrySet()) {
                if (!isImmutableClaim(entry.getKey())) {
                    carbonUM.deleteUserClaimValue(user.getUserName(), entry.getKey(), null);
                }
            }
            // Get user claims mapped from SCIM dialect to WSO2 dialect.
            Map<String, String> claimValuesInLocalDialect = SCIMCommonUtils.convertSCIMtoLocalDialect(claims);
            //set user claim values
            carbonUM.setUserClaimValues(user.getUserName(), claimValuesInLocalDialect, null);
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
     * Filter users using multi-attribute filters or single attribute filters with pagination.
     *
     * @param node
     * @param requiredAttributes
     * @param offset
     * @param limit
     * @param sortBy
     * @param sortOrder
     * @param domainName
     * @return
     * @throws NotImplementedException
     * @throws CharonException
     */
    private List<Object> filterUsers(Node node, Map<String, Boolean> requiredAttributes, int offset, int limit,
                                     String sortBy, String sortOrder, String domainName)
            throws NotImplementedException, CharonException {

        List<Object> filteredUsers = new ArrayList<>();
        //0th index is to store total number of results
        filteredUsers.add(0);
        String[] userNames;

        //Handle single attribute search
        if (node instanceof ExpressionNode) {
            String attributeName = ((ExpressionNode) node).getAttributeValue();
            String filterOperation = ((ExpressionNode) node).getOperation();
            String attributeValue = ((ExpressionNode) node).getValue();

            if (log.isDebugEnabled()) {
                log.debug(String.format("Listing users by filter: %s %s %s",
                        attributeName, filterOperation, attributeValue));
            }

            try {
                if (isNotFilteringSupported(filterOperation)) {
                    throw new NotImplementedException(String.format("System does not support filter operator: %s",
                            filterOperation));
                }

                if (SCIMCommonUtils.isFilteringEnhancementsEnabled()) {
                    if (SCIMCommonConstants.EQ.equalsIgnoreCase(filterOperation)) {
                        if (StringUtils.equals(attributeName, SCIMConstants.UserSchemaConstants.USER_NAME_URI) &&
                                !StringUtils.contains(attributeValue, CarbonConstants.DOMAIN_SEPARATOR)) {
                            attributeValue = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME +
                                    CarbonConstants.DOMAIN_SEPARATOR + attributeValue;
                        }
                    }
                }

                if (!SCIMConstants.UserSchemaConstants.GROUP_URI.equals(attributeName)) {
                    //get the user name of the user with this id
                    userNames = getUserNames(attributeName, filterOperation, attributeValue);
                } else {
                    if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EQ)) {
                        userNames = carbonUM.getUserListOfRole(attributeValue);
                    } else if (carbonUM instanceof AbstractUserStoreManager) {
                        String[] roleNames = getRoleNames(filterOperation, attributeValue);
                        userNames = getUserListOfRoles(roleNames);
                    } else {
                        throw new NotImplementedException(String.format("Filter operator %s is not supported " +
                                "by the user store.", filterOperation));
                    }
                }
            } catch (UserStoreException e) {
                throw new CharonException(String.format("Error in filtering users by attribute name: %s, " +
                                "attribute value: %s and filter operation %s", attributeName, attributeValue,
                        filterOperation), e);
            }

            userNames = paginateUsers(userNames, limit, offset);
            //remove duplicated username entries
            HashSet<String> userNamesSet = new HashSet<String>(Arrays.asList(userNames));
            userNames = userNamesSet.toArray(new String[userNamesSet.size()]);
            filteredUsers.set(0, userNames.length);
            filteredUsers.addAll(getFilteredUserDetails(userNames, requiredAttributes));
            return filteredUsers;

        } else if (node instanceof OperationNode) {
            // Support multi attribute filtering.
            return getMultiAttributeFilteredUsers(node, requiredAttributes, offset, limit, sortBy, sortOrder,
                    domainName, filteredUsers);
        } else {
            throw new CharonException("Unsupported Operation");
        }
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
    private List<Object> getMultiAttributeFilteredUsers(Node node, Map<String, Boolean> requiredAttributes,
                                                        int offset, int limit, String sortBy, String sortOrder,
                                                        String domainName, List<Object> filteredUsers)
            throws CharonException {

        String[] userNames;

        // Handle pagination.
        if (limit > 0) {
            userNames = getFilteredUsersFromMultiAttributeFiltering(node, offset, limit, sortBy,
                    sortOrder, domainName);
            filteredUsers.set(0, userNames.length);
            filteredUsers.addAll(getFilteredUserDetails(userNames, requiredAttributes));
        } else {
            int maxLimit = getMaxLimit();
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
     * @return
     */
    private int getMaxLimit() {

        int givenMax;

        try {
            givenMax = Integer.parseInt(carbonUM.getRealmConfiguration().getUserStoreProperty(
                    "MaxUserNameListLength"));
        } catch (Exception e) {
            givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
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
            } else if (attributes.get(attributeName) != null) {
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
    public List<Object> listGroupsWithGET(Node rootNode, int startIndex,
                                          int count, String sortBy, String sortOrder, String domainName,
                                          Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {
        if(sortBy != null || sortOrder != null) {
            throw new NotImplementedException("Sorting is not supported");
        }  else if(startIndex != 1){
            throw new NotImplementedException("Pagination is not supported");
        } else if(rootNode != null) {
            return filterGroups(rootNode, requiredAttributes);
        } else {
            return listGroups(requiredAttributes);
        }
    }

    private List<Object> listGroups(Map<String, Boolean> requiredAttributes) throws CharonException {
        List<Object> groupList = new ArrayList<>();
        //0th index is to store total number of results;
        groupList.add(0);
        try {
            SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
            Set<String> roleNames = groupHandler.listSCIMRoles();
            for (String roleName : roleNames) {
                String userStoreDomainName = IdentityUtil.extractDomainFromName(roleName);
                if (isInternalOrApplicationGroup(userStoreDomainName) || isSCIMEnabled(userStoreDomainName)) {
                    if (log.isDebugEnabled()) {
                        log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". " +
                                "Including group with name : " + roleName + " in the response.");
                    }
                    Group group = this.getGroupWithName(roleName);
                    if (group.getId() != null) {
                        groupList.add(group);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". Hence " +
                                "group with name : " + roleName + " is excluded in the response.");
                    }
                }
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            String errMsg = "Error in obtaining role names from user store.";
            errMsg += e.getMessage();
            throw new CharonException(errMsg, e);
        } catch (IdentitySCIMException | BadRequestException e) {
            throw new CharonException("Error in retrieving SCIM Group information from database.", e);
        }
        //set the totalResults value in index 0
        groupList.set(0, groupList.size()-1);
        return groupList;
    }


    private List<Object> filterGroups(Node node, Map<String, Boolean> requiredAttributes)
            throws NotImplementedException, CharonException {

        if(node.getLeftNode() != null || node.getRightNode() != null){
            String error = "Complex filters are not supported yet";
            throw new NotImplementedException(error);
        }
        String attributeName = ((ExpressionNode)node).getAttributeValue();
        String filterOperation = ((ExpressionNode)node).getOperation();
        String attributeValue = ((ExpressionNode)node).getValue();

        if (isNotFilteringSupported(filterOperation)) {
            String error = "System does not support filter operator: " + filterOperation;
            throw new NotImplementedException(error);
        }

        if (SCIMCommonUtils.isFilteringEnhancementsEnabled()) {
            if (SCIMCommonConstants.EQ.equalsIgnoreCase(filterOperation)) {
                if (StringUtils.equals(attributeName, SCIMConstants.GroupSchemaConstants.DISPLAY_NAME_URI) &&
                        !StringUtils.contains(attributeValue, CarbonConstants.DOMAIN_SEPARATOR)) {
                    attributeValue = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME +
                            CarbonConstants.DOMAIN_SEPARATOR + attributeValue;
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Listing groups with filter: " + attributeName + filterOperation +
                    attributeValue);
        }
        List<Object> filteredGroups = new ArrayList<>();
        //0th index is to store total number of results;
        filteredGroups.add(0);
        try {
            String[] roleList = getGroupList(attributeName, filterOperation, attributeValue);
            if (roleList != null) {
                for (String roleName : roleList) {
                    if (roleName != null && carbonUM.isExistingRole(roleName, false)) {
                        //skip internal roles
                        if ((CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME.equals(roleName)) ||
                                UserCoreUtil.isEveryoneRole(roleName, carbonUM.getRealmConfiguration())) {
                            continue;
                        }
                        /**construct the group name with domain -if not already provided, in order to support
                         multiple user store feature with SCIM.**/
                        String groupNameWithDomain = null;
                        if (roleName.indexOf(CarbonConstants.DOMAIN_SEPARATOR) > 0) {
                            groupNameWithDomain = roleName;
                        } else {
                            groupNameWithDomain = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME + CarbonConstants.DOMAIN_SEPARATOR
                                    + roleName;
                        }
                        String userStoreDomainName = IdentityUtil.extractDomainFromName(roleName);
                        if (isInternalOrApplicationGroup(userStoreDomainName) || isSCIMEnabled(userStoreDomainName)) {
                            if (log.isDebugEnabled()) {
                                log.debug("SCIM is enabled for the user-store domain : " + userStoreDomainName + ". " +
                                        "Including group with name : " + roleName + " in the response.");
                            }
                            Group group = getGroupWithName(groupNameWithDomain);
                            filteredGroups.add(group);
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("SCIM is disabled for the user-store domain : " + userStoreDomainName + ". Hence " +
                                        "group with name : " + roleName + " is excluded in the response.");
                            }
                        }
                    } else {
                        //returning null will send a resource not found error to client by Charon.
                        filteredGroups.clear();
                        filteredGroups.add(0);
                        return filteredGroups;
                    }
                }
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException("Error in filtering groups by attribute name : " + attributeName + ", " +
                    "attribute value : " + attributeValue + " and filter operation " + filterOperation, e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new CharonException("Error in filtering group with filter: "
                    + attributeName + filterOperation + attributeValue, e);
        } catch (IdentitySCIMException e) {
            throw new CharonException("Error in retrieving SCIM Group information from database.", e);
        } catch (BadRequestException e) {
            throw new CharonException("Error in retrieving SCIM Group.", e);
        }
        //set the totalResults value in index 0
        filteredGroups.set(0, filteredGroups.size() - 1);
        return filteredGroups;
    }


    @Override
    public Group updateGroup(Group oldGroup, Group newGroup, Map<String, Boolean> requiredAttributes)
            throws CharonException {
        String displayName = null;
        displayName = oldGroup.getDisplayName();
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
            //check if the user ids sent in updated group exist in the user store and the associated user name
            //also a matching one.
            List<Object> userIds = newGroup.getMembers();
            List<String> userDisplayNames = newGroup.getMembersWithDisplayName();

                /* compare user store domain of group and user store domain of user name , if there is a mismatch do not
                 update the group */
            if (userDisplayNames != null && userDisplayNames.size() > 0) {
                for (String userDisplayName : userDisplayNames) {
                    String userStoreDomainForUser =
                            IdentityUtil.extractDomainFromName(userDisplayName);
                    if (!isInternalOrApplicationGroup(userStoreDomainForGroup) && !userStoreDomainForGroup.equalsIgnoreCase
                            (userStoreDomainForUser)) {
                        throw new IdentitySCIMException(
                                userDisplayName + " does not " + "belongs to user store " + userStoreDomainForGroup);
                    }

                }
            }

            if (CollectionUtils.isNotEmpty(userIds)) {
                String[] userNames = null;
                for (Object userId : userIds) {
                    if (userId != null) {
                        String userIdLocalClaim = SCIMCommonUtils.getSCIMtoLocalMappings().get(SCIMConstants
                                .CommonSchemaConstants.ID_URI);
                        if (StringUtils.isNotBlank(userIdLocalClaim)) {
                            userNames = carbonUM.getUserList(userIdLocalClaim, IdentityUtil.addDomainToName((String)
                                            userId, userStoreDomainForGroup), UserCoreConstants.DEFAULT_PROFILE);
                        }
                        if (userNames == null || userNames.length == 0) {
                            String error = "User: " + userId + " doesn't exist in the user store. " +
                                    "Hence, can not update the group: " + oldGroup.getDisplayName();
                            throw new IdentitySCIMException(error);
                        } else {
                            if (!UserCoreUtil.isContain(UserCoreUtil.removeDomainFromName(userNames[0]),
                                    UserCoreUtil.removeDomainFromNames(userDisplayNames.toArray(
                                            new String[userDisplayNames.size()])))) {
                                throw new IdentitySCIMException("Given SCIM user Id and name not matching..");
                            }
                        }
                    }
                }
            }
            //we do not update Identity_SCIM DB here since it is updated in SCIMUserOperationListener's methods.

            //update name if it is changed
            if (!(oldGroup.getDisplayName().equalsIgnoreCase(newGroup.getDisplayName()))) {
                //update group name in carbon UM
                carbonUM.updateRoleName(oldGroup.getDisplayName(),
                        newGroup.getDisplayName());

                updated = true;
            }

            //find out added members and deleted members..
            List<String> oldMembers = oldGroup.getMembersWithDisplayName();
            List<String> newMembers = newGroup.getMembersWithDisplayName();
            if (newMembers != null) {

                List<String> addedMembers = new ArrayList<>();
                List<String> deletedMembers = new ArrayList<>();

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
                        addedMembers.add(newMember);
                    }
                }

                if (CollectionUtils.isNotEmpty(addedMembers) || CollectionUtils.isNotEmpty(deletedMembers)) {
                    carbonUM.updateUserListOfRole(newGroup.getDisplayName(),
                            deletedMembers.toArray(new String[deletedMembers.size()]),
                            addedMembers.toArray(new String[addedMembers.size()]));
                    updated = true;
                }
            }
            if (updated) {
                log.info("Group: " + newGroup.getDisplayName() + " is updated through SCIM.");
            } else {
                log.warn("There is no updated field in the group: " + oldGroup.getDisplayName() +
                        ". Therefore ignoring the provisioning.");
            }

        } catch (UserStoreException | IdentitySCIMException e) {
            throw new CharonException(e.getMessage(), e);
        } catch (IdentityApplicationManagementException e){
            throw new CharonException("Error retrieving User Store name. ", e);
        } catch (BadRequestException | CharonException e) {
            throw new CharonException("Error in updating the group", e);

        }

        return newGroup;
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

            //skip simple type addresses claim because it is complex with sub types in the schema
            if (attributes.containsKey(SCIMConstants.UserSchemaConstants.ADDRESSES_URI)) {
                attributes.remove(SCIMConstants.UserSchemaConstants.ADDRESSES_URI);
            }

            // Add username with domain name
            attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, userName);

            //get groups of user and add it as groups attribute
            String[] roles = carbonUM.getRoleListOfUser(userName);
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

                if (SCIMCommonUtils.isFilteringEnhancementsEnabled()) {
                    if (!StringUtils.contains(role, CarbonConstants.DOMAIN_SEPARATOR)) {
                        role = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME + CarbonConstants.DOMAIN_SEPARATOR + role;
                    }
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
                    //skip simple type addresses claim because it is complex with sub types in the schema
                    if (attributes.containsKey(SCIMConstants.UserSchemaConstants.ADDRESSES_URI)) {
                        attributes.remove(SCIMConstants.UserSchemaConstants.ADDRESSES_URI);
                    }

                    // Add username with domain name
                    attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, userName);

                    //get groups of user and add it as groups attribute
                    List<String> roleList = usersRoles.get(userName);
                    String[] roles = new String[0];
                    if (CollectionUtils.isNotEmpty(roleList)) {
                        roles = roleList.toArray(new String[0]);
                    }

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

                        if (SCIMCommonUtils.isFilteringEnhancementsEnabled()) {
                            if (!StringUtils.contains(role, CarbonConstants.DOMAIN_SEPARATOR)) {
                                role = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME + CarbonConstants.DOMAIN_SEPARATOR + role;
                            }
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
        group.setDisplayName(groupName);
        String[] userNames = carbonUM.getUserListOfRole(groupName);

        //get the ids of the users and set them in the group with id + display name
        if (userNames != null && userNames.length != 0) {
            for (String userName : userNames) {
                String userId = carbonUM.getUserClaimValue(userName, SCIMConstants.CommonSchemaConstants.ID_URI, null);
                group.setMember(userId, userName);
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

    private String[] paginateUsers(String[] users, int limit, int offset) {

        if (offset <= 0) {
            offset = 1;
        }

        if (limit <= 0) { // if limit is minus or zero
            if (users == null) { // if users String array is null
                return new String[0];
            } else {
                // This is to support backward compatibility.
                Arrays.sort(users);
                return users;
            }
        }

        if (users == null) {
            return new String[0];
        } else if (offset > users.length) {
            return new String[0];
        } else if (users.length < limit + offset) {
            Arrays.sort(users);
            limit = users.length - offset + 1;
            return Arrays.copyOfRange(users, offset - 1, limit + offset - 1);
        } else {
            Arrays.sort(users);
            return Arrays.copyOfRange(users, offset - 1, limit + offset - 1);
        }
    }

    /**
     * check whether the filtering is supported
     * @param filterOperation operator use for filtering
     * @return boolean to check whether operator is supported
     */
    private boolean isNotFilteringSupported(String filterOperation) {

        return !filterOperation.equalsIgnoreCase(SCIMCommonConstants.EQ)
                && !filterOperation.equalsIgnoreCase(SCIMCommonConstants.CO)
                && !filterOperation.equalsIgnoreCase(SCIMCommonConstants.SW)
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
     * get the search value after appending the delimiters
     * @param filterOperation operator value
     * @param attributeValue search value
     * @param delimiter delimiter for based on search type
     * @return search attribute
     */
    private String getSearchAttribute(String filterOperation, String attributeValue, String delimiter) {

        String searchAttribute = null;
        if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.CO)) {
            String[] attributeItems = attributeValue.split(CarbonConstants.DOMAIN_SEPARATOR);
            if(attributeItems.length == 2) {
                searchAttribute = attributeItems[0] + CarbonConstants.DOMAIN_SEPARATOR +
                        delimiter + attributeItems[1] + delimiter;
            } else {
                searchAttribute = delimiter + attributeValue + delimiter;
            }
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.SW)) {
            searchAttribute = attributeValue + delimiter;
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EW)) {
            searchAttribute = delimiter + attributeValue;
        } else if (filterOperation.equalsIgnoreCase(SCIMCommonConstants.EQ)) {
            searchAttribute = attributeValue;
        }
        return searchAttribute;
    }

    /**
     * get list of roles that matches the search criteria
     * @param filterOperation operator value
     * @param attributeValue search value
     * @return list of role names
     * @throws org.wso2.carbon.user.core
    .UserStoreException
     */
    private String[] getRoleNames(String filterOperation, String attributeValue) throws org.wso2.carbon.user.core
            .UserStoreException {

        String searchAttribute = getSearchAttribute(filterOperation, attributeValue, FILTERING_DELIMITER);
        return ((AbstractUserStoreManager) carbonUM).getRoleNames(searchAttribute, MAX_ITEM_LIMIT_UNLIMITED, true,
                true, true);
    }

    /**
     * get list of user that matches the search criteria
     * @param attributeName field name for search
     * @param filterOperation operator
     * @param attributeValue search value
     * @return list of users
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private String[] getUserNames(String attributeName, String filterOperation, String attributeValue)
            throws org.wso2.carbon.user.core.UserStoreException {

        String searchAttribute = getSearchAttribute(filterOperation, attributeValue, FILTERING_DELIMITER);
        String attributeNameInLocalDialect = SCIMCommonUtils.getSCIMtoLocalMappings().get(attributeName);
        if (StringUtils.isBlank(attributeNameInLocalDialect)) {
            attributeNameInLocalDialect = attributeName;
        }
        return carbonUM.getUserList(attributeNameInLocalDialect, searchAttribute, UserCoreConstants.DEFAULT_PROFILE);
    }

    /**
     * get the list of groups that matches the search criteria
     * @param attributeName attribute which is used to search
     * @param filterOperation operator value
     * @param attributeValue search value
     * @return list of user groups
     * @throws org.wso2.carbon.user.core.UserStoreException
     * @throws IdentitySCIMException
     */
    private String[] getGroupList(String attributeName, String filterOperation, String attributeValue)
            throws org.wso2.carbon.user.core.UserStoreException, IdentitySCIMException {

        String[] userRoleList;
        if (attributeName.equals(SCIMConstants.GroupSchemaConstants.DISPLAY_URI)
                || attributeName.equals(SCIMConstants.GroupSchemaConstants.VALUE_URI)) {
            String[] userList;
            if (attributeName.equals(SCIMConstants.GroupSchemaConstants.DISPLAY_URI)) {
                userList = getUserNames(SCIMConstants.UserSchemaConstants.USER_NAME_URI, filterOperation, attributeValue);
            } else {
                userList = getUserNames(SCIMConstants.CommonSchemaConstants.ID_URI, filterOperation, attributeValue);
            }
            Set<String> fullRoleList = new HashSet<>();
            List<String> currentRoleList;

            if (userList != null) {
                for (String userName : userList) {
                    String[] roles = carbonUM.getRoleListOfUser(userName);
                    currentRoleList = Arrays.asList(roles);
                    fullRoleList.addAll(currentRoleList);
                }
            }

            userRoleList = fullRoleList.toArray(new String[fullRoleList.size()]);

        } else if (attributeName.equals(SCIMConstants.GroupSchemaConstants.DISPLAY_NAME_URI)) {
            userRoleList = getRoleNames(filterOperation, attributeValue);
        } else {
            userRoleList = getGroupNamesFromDB(attributeName, filterOperation, attributeValue);
        }

        return userRoleList;
    }

    /**
     * return when search using meta data; list of groups
     * @param attributeName attribute which is used to search
     * @param filterOperation operator value
     * @param attributeValue search value
     * @return list of groups
     * @throws org.wso2.carbon.user.core.UserStoreException
     * @throws IdentitySCIMException
     */
    private String[] getGroupNamesFromDB(String attributeName, String filterOperation, String attributeValue)
            throws org.wso2.carbon.user.core.UserStoreException, IdentitySCIMException {

        String searchAttribute = getSearchAttribute(filterOperation, attributeValue, SQL_FILTERING_DELIMITER);
        SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
        return groupHandler.getGroupListFromAttributeName(attributeName, searchAttribute);
    }


    private boolean isPaginatedUserStoreAvailable() {

        String enablePaginatedUserStore = IdentityUtil.getProperty(ENABLE_PAGINATED_USER_STORE);
        if (!StringUtils.isBlank(enablePaginatedUserStore)) {
            return Boolean.parseBoolean(enablePaginatedUserStore);
        } return false;
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
}
