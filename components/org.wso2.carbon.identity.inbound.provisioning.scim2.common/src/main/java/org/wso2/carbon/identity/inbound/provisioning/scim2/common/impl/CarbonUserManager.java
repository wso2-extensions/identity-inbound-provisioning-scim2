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

package org.wso2.carbon.identity.inbound.provisioning.scim2.common.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.SCIMClaimResolver;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.claim.MetaClaim;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.model.UserModel;
import org.wso2.carbon.identity.mgt.store.IdentityStore;
import org.wso2.charon.core.v2.attributes.Attribute;
import org.wso2.charon.core.v2.attributes.MultiValuedAttribute;
import org.wso2.charon.core.v2.attributes.SimpleAttribute;
import org.wso2.charon.core.v2.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon.core.v2.exceptions.BadRequestException;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.exceptions.ConflictException;
import org.wso2.charon.core.v2.exceptions.NotFoundException;
import org.wso2.charon.core.v2.exceptions.NotImplementedException;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.objects.Group;
import org.wso2.charon.core.v2.objects.User;
import org.wso2.charon.core.v2.schema.SCIMConstants;
import org.wso2.charon.core.v2.utils.codeutils.ExpressionNode;
import org.wso2.charon.core.v2.utils.codeutils.Node;
import org.wso2.charon.core.v2.utils.codeutils.SearchRequest;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * This class is to deal with the carbon user core API. This uses identityStore defined API for
 * user, group based identity provisioning operations.
 */

public class CarbonUserManager implements UserManager {

    private static Logger log = LoggerFactory.getLogger(CarbonUserManager.class);

    IdentityStore identityStore = null;

    public CarbonUserManager(IdentityStore identityStore) {
        this.identityStore = identityStore;
    }

    @Override
    public User createUser(User user, Map<String, Boolean> requiredAttributes) throws CharonException,
            ConflictException, BadRequestException {
        try {

            if (log.isDebugEnabled()) {
                log.debug("Creating user: " + user.toString());
            }
            //get the groups attribute as we are going to explicitly store the info of the user's groups
            MultiValuedAttribute groupsAttribute = (MultiValuedAttribute) (
                    user.getAttribute(SCIMConstants.UserSchemaConstants.GROUPS));

            Map<String, String> claimsMap = SCIMClaimResolver.getClaimsMap(user);

            //create user model as that is what need to send to identity store api.
            UserModel userModel = getUserModelFromClaims(claimsMap);

            //TODO : get the domain of the user store and call that method instead of this method.
            //add the user.
            org.wso2.carbon.identity.mgt.bean.User userStoreUser = identityStore.addUser(userModel);

            // list to store the group ids which will be used to create the group attribute in scim user.
            List<String> groupIds = new ArrayList<>();

            if (groupsAttribute != null) {
                List<Attribute> subValues = groupsAttribute.getAttributeValues();

                if (subValues != null && subValues.size() != 0) {
                    for (Attribute subValue : subValues) {
                        SimpleAttribute valueAttribute =
                            (SimpleAttribute) ((subValue)).getSubAttribute(SCIMConstants.CommonSchemaConstants.VALUE);
                        groupIds.add((String) valueAttribute.getValue());
                    }
                }
            }
            //need to add users groups if it is available in the request
            if (groupIds.size() != 0) {
                //now add the user's groups explicitly.
                identityStore.updateGroupsOfUser(userStoreUser.getUniqueUserId(), groupIds);
            }
            log.info("User: " + user.getUserName() + " is created through SCIM.");
            //get the user again from the user store and send it to client.
            return this.getUser(userStoreUser.getUniqueUserId(), requiredAttributes);

        } catch (IdentityStoreException e) {
            String errMsg = "User : " + user.getUserName() + " already exists.";
            throw new ConflictException(errMsg);
        } catch (NotFoundException e) {
           throw new CharonException("Error in retrieving the user from the user store.", e);
        }
    }

    @Override
    public User getUser(String userId, Map<String, Boolean> requiredAttributes) throws CharonException,
            BadRequestException, NotFoundException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving user: " + userId);
        }
        try {
            org.wso2.carbon.identity.mgt.bean.User userStoreUser = identityStore.getUser(userId);

            //TODO:We need to pass the scim claim dialect for this method
            List<Claim> claimList = userStoreUser.getClaims();

            User scimUser = getSCIMUser(userStoreUser, claimList);

            log.info("User: " + scimUser.getUserName() + " is retrieved through SCIM.");

            return scimUser;

        } catch (IdentityStoreException e) {
            throw new CharonException("Error in getting user from the userid :" + userId, e);
        } catch (UserNotFoundException e) {
            throw new NotFoundException("User not found with the given userid :" + userId);
        }

    }

    @Override
    public void deleteUser(String userId) throws NotFoundException, CharonException, NotImplementedException,
            BadRequestException {

        if (log.isDebugEnabled()) {
            log.debug("Deleting user: " + userId);
        }
        try {
            //TODO : think of adding the domain.
            identityStore.deleteUser(userId);
            log.info("User with the id : " + userId + " is deleted through SCIM.");

        } catch (UserNotFoundException e) {
            throw new NotFoundException("User with the user id : " + userId + " does not exists.");

        } catch (IdentityStoreException e) {
           throw new CharonException ("Error in deleting the user with the id: " + userId);

        }
    }

    @Override
    public List<Object> listUsersWithGET(Node rootNode, int startIndex, int count, String sortBy,
                                         String sortOrder, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {

        //check if it is a pagination only request.
        if (count != 0 && sortOrder == null && sortBy == null && rootNode == null) {
            return listWithPagination(startIndex, count);

        // check if it is a pagination and filter combination.
        } else if (count != 0 && sortOrder == null && sortBy == null && rootNode != null) {
            return listWithPaginationAndFilter(rootNode, startIndex, count);

        // if the user has only mentioned the filter string.
        } else if (rootNode != null) {
            //TODO : we need to read the count and start index from the config file.
            return listWithPaginationAndFilter(rootNode, 1, 100);

        // if user has not mentioned any parameters, perform default listing.
        } else {
            return listWithPagination(1, 100);
        }

    }

    @Override
    public List<Object> listUsersWithPost(SearchRequest searchRequest, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {
        // this is identical to getUsersWithGet.
        return listUsersWithGET(searchRequest.getFilter(), searchRequest.getStartIndex(), searchRequest.getCount(),
                searchRequest.getSortBy(), searchRequest.getSortOder(), requiredAttributes);
    }

    @Override
    public User updateUser(User user, Map<String, Boolean> requiredAttributes) throws NotImplementedException,
            CharonException, BadRequestException, NotFoundException {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Updating user: " + user.toString());
            }
            //get the claims map from the new scim user object.
            Map<String, String> claims = SCIMClaimResolver.getClaimsMap(user);
            //get the claim list to be updated.
            List<Claim> claimList = getUserModelFromClaims(claims).getClaims();
            //set user updated claim values
            identityStore.updateUserClaims(user.getId(), claimList);

            log.info("User: " + user.getUserName() + " updated updated through SCIM.");
            //get the updated user from the user core and sent it to client.
            return this.getUser(user.getId(), requiredAttributes);

        } catch (UserNotFoundException e) {
            throw new NotFoundException("No such user with the user id : " + user.getId());
        } catch (IdentityStoreException e) {
            throw new CharonException("Error in updating the user", e);
        }
    }

    @Override
    public User getMe(String s, Map<String, Boolean> requiredAttributes) throws CharonException, BadRequestException,
            NotFoundException {
        return null;
    }

    @Override
    public User createMe(User user, Map<String, Boolean> requiredAttributes) throws CharonException,
            ConflictException, BadRequestException {
        return null;
    }

    @Override
    public void deleteMe(String s) throws NotFoundException, CharonException, NotImplementedException,
            BadRequestException {

    }

    @Override
    public User updateMe(User user, Map<String, Boolean> requiredAttributes) throws NotImplementedException,
            CharonException, BadRequestException {
        return null;
    }

    @Override
    public Group createGroup(Group group, Map<String, Boolean> requiredAttributes) throws CharonException,
            ConflictException, NotImplementedException, BadRequestException {
        return null;
    }

    @Override
    public Group getGroup(String s, Map<String, Boolean> requiredAttributes) throws NotImplementedException,
            BadRequestException, CharonException {
        return null;
    }

    @Override
    public void deleteGroup(String s) throws NotFoundException, CharonException, NotImplementedException,
            BadRequestException {

    }

    @Override
    public List<Object> listGroupsWithGET(Node node, int i, int i1, String s, String s1, Map<String, Boolean>
            requiredAttributes) throws CharonException, NotImplementedException, BadRequestException {
        return null;
    }

    @Override
    public Group updateGroup(Group group, Group group1, Map<String, Boolean> requiredAttributes) throws
            NotImplementedException, BadRequestException, CharonException {
        return null;
    }

    @Override
    public List<Object> listGroupsWithPost(SearchRequest searchRequest, Map<String, Boolean> requiredAttributes)
            throws NotImplementedException, BadRequestException, CharonException {
        return null;
    }

    /*
     * This method is to get the user model from the claims.
     * @param claims
     * @return
     */
    private UserModel getUserModelFromClaims(Map<String, String> claims) {

        UserModel userModel = new UserModel();

        List<Claim> claimList = new ArrayList<>();

        for (Entry<String, String> claim : claims.entrySet()) {
            //create claims for all entries and add it to claim list
            Claim newClaim = new Claim();
            newClaim.setClaimUri(claim.getKey());
            newClaim.setValue(claim.getValue());
            //add the right claim dialect for the claim.
            if (claim.getKey().contains(SCIMCommonConstants.USER_DIALECT)) {
                //claim dialect is the scim user dialect.
                newClaim.setDialectUri(SCIMCommonConstants.USER_DIALECT);

            } else if (claim.getKey().contains(SCIMCommonConstants.CORE_DIALECT)) {
                //claim dialect is the scim core dialect.
                newClaim.setDialectUri(SCIMCommonConstants.CORE_DIALECT);

            } else {
                //claim dialect is the scim extended user dialect.
                newClaim.setDialectUri(SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema().getURI());
            }
            claimList.add(newClaim);
        }
        //se the claim to user model.
        userModel.setClaims(claimList);
        return userModel;
    }

    /*
     * This method is to get the scim user from the claims.
     * @param userStoreUser
     * @param claimURIList
     * @return
     * @throws CharonException
     */
    private User getSCIMUser(org.wso2.carbon.identity.mgt.bean.User userStoreUser,
                             List<Claim> claimURIList) throws CharonException {


        //get a claim string list
        List<MetaClaim> claimURIs = new ArrayList<>();
        for (Claim claim : claimURIList) {
            MetaClaim metaClaim = new MetaClaim(claim.getDialectUri(), claim.getClaimUri());
            claimURIs.add(metaClaim);
        }
        //map to keep the claim, value  pair.
        Map<String, String> attributeMap = new HashMap<>();

        try {
            //obtain user claim values
            List<Claim> attributes = userStoreUser.getClaims(claimURIs);

            for (Claim claim : attributes) {
                attributeMap.put(claim.getClaimUri(), claim.getValue());
            }

        } catch (UserNotFoundException | IdentityStoreException e) {
            throw new CharonException("Error in getting the claims values.", e);
        }

        //get the groups of the user separately as we are going to make a scim user with the groups in it.
        try {
            List<org.wso2.carbon.identity.mgt.bean.Group> groups =
                    identityStore.getGroupsOfUser(userStoreUser.getUniqueUserId());

            //construct the SCIM Object from the attributes
            User scimUser = (User) SCIMClaimResolver.constructSCIMObjectFromAttributes(attributeMap, 1);
            //set the id of the user from the unique user id.

            for (org.wso2.carbon.identity.mgt.bean.Group group : groups) {
                if (group != null) { // can be null for non SCIM groups
                    scimUser.setGroup(null, group.getUniqueGroupId(), null);
                }
            }
            //set the id of the user from the unique user id.
            scimUser.setId(userStoreUser.getUniqueUserId());
            //set the schemas of the scim user
            scimUser.setSchemas();

            return scimUser;

        } catch (IdentityStoreException | UserNotFoundException e) {
            throw new CharonException("Error in getting the groups of the user.", e);
        } catch (BadRequestException | NotFoundException e) {
            throw new CharonException("Error in creating the scim user from the claims and the values.", e);
        }
    }

    /*
     * This method is to list the users with pagination.
     * @param startIndex
     * @param count
     * @return
     * @throws CharonException
     */
    private List<Object> listWithPagination(int startIndex, int count) throws CharonException {
        try {
            //get the user list accroding to the start index and the count values provided.
            //TODO : Add the domain of the store.
            List<org.wso2.carbon.identity.mgt.bean.User> userList = identityStore.listUsers(startIndex, count);
            List<Object> userObjectList = new ArrayList<>();
            //convert identity store users to objects.
            for (org.wso2.carbon.identity.mgt.bean.User user : userList) {
                userObjectList.add(user);
            }
            return userObjectList;

        } catch (IdentityStoreException e) {
            throw new CharonException("Error in getting the user list with start index :"
                    + startIndex + " and " + "count of :" + count);
        }
    }

    /*
     * List the users with pagination and filter (Eq filter only)
     * @param rootNode
     * @param startIndex
     * @param count
     * @return
     * @throws NotImplementedException
     * @throws CharonException
     */
    private List<Object> listWithPaginationAndFilter(Node rootNode, int startIndex, int count)
            throws NotImplementedException, CharonException {

        //Filter model simply consists of a binary tree where the terminal nodes are the filter expressions and
        //non -terminal nodes are the logical operators.
        //we currently do not support complex type filter
        //eg : userName Eq vindula AND nickName sw J
        if (rootNode.getRightNode() != null) {
            throw new NotImplementedException("Complex filters are not implemented.");
        }
        if (rootNode.getLeftNode() != null) {
            throw new NotImplementedException("Complex filters are not implemented.");
        }
        //we only support 'eq' filter
        if (((ExpressionNode) (rootNode)).getOperation().equals("EQ")) {
            //create a claim for the asked eq related attribute
            Claim filterClaim = new Claim();

            filterClaim.setValue(((ExpressionNode) (rootNode)).getValue());
            filterClaim.setClaimUri(((ExpressionNode) (rootNode)).getAttributeValue());

            //add the right claim dialect for the claim.
            if (((ExpressionNode) (rootNode)).getAttributeValue().contains(SCIMCommonConstants.USER_DIALECT)) {
                //claim dialect is the scim user dialect.
                filterClaim.setDialectUri(SCIMCommonConstants.USER_DIALECT);

            } else if (((ExpressionNode) (rootNode)).getAttributeValue().contains(SCIMCommonConstants.CORE_DIALECT)) {
                //claim dialect is the scim core dialect.
                filterClaim.setDialectUri(SCIMCommonConstants.CORE_DIALECT);

            } else {
                //claim dialect is the scim extended user dialect.
                filterClaim.setDialectUri(SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema().getURI());
            }

            try {
                List<org.wso2.carbon.identity.mgt.bean.User> userList;
                // get the user list from the user core.
                userList = identityStore.listUsers(filterClaim, startIndex, count);

                List<Object> userObjectList = new ArrayList<>();
                //convert identity store users to objects.
                for (org.wso2.carbon.identity.mgt.bean.User user : userList) {
                    userObjectList.add(user);
                }
                return userObjectList;

            } catch (IdentityStoreException e) {
                throw new CharonException("Error in getting the user list with the filter and pagination.");
            }

        } else {
            throw new NotImplementedException("Filter type :" +
                    ((ExpressionNode) (rootNode)).getOperation() + "is not supported.");
        }
    }

}

