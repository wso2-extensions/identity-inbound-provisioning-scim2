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
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.claim.ClaimMapper;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.claim.MetaClaim;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.model.GroupModel;
import org.wso2.carbon.identity.mgt.model.UserModel;
import org.wso2.carbon.identity.mgt.store.IdentityStore;
import org.wso2.charon.core.v2.attributes.Attribute;
import org.wso2.charon.core.v2.attributes.ComplexAttribute;
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
            //TODO this is a temporary method. need to remove this once the claim management is completed.
            userModel = ClaimMapper.getInstance().convertMetaToWso2Dialect(userModel);

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
            //TODO this is a temporary method. need to remove this once the claim management is completed.
            claimList = ClaimMapper.getInstance().convertToScimDialect(claimList);

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
            throw new CharonException("Error in deleting the user with the id: " + userId, e);

        }
    }

    @Override
    public List<Object> listUsersWithGET(Node rootNode, int startIndex, int count, String sortBy,
                                         String sortOrder, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {

        // check if it is a pagination and filter combination.
        if (sortOrder == null && sortBy == null && rootNode != null) {

            return listUsersWithPaginationAndFilter(rootNode, startIndex, count);

        } //check if it is a pagination only request.
        if (sortOrder == null && sortBy == null && rootNode == null) {
            return listUsersWithPagination(startIndex, count);

        } else {
            throw new NotImplementedException("Sorting is not supported.");
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
            //TODO this is a temporary method. need to remove this once the claim management is completed.
            claimList = ClaimMapper.getInstance().convertMetaToWso2Dialect(claimList);
            //set user updated claim values
            identityStore.updateUserClaims(user.getId(), claimList);

            log.info("User: " + user.getUserName() + " updated through SCIM.");
            //get the updated user from the user core and sent it to client.
            return this.getUser(user.getId(), requiredAttributes);

        } catch (UserNotFoundException | NotFoundException e) {
            throw new NotFoundException("No such user with the user id : " + user.getId());
        } catch (IdentityStoreException e) {
            throw new CharonException("Error in updating the user", e);
        }
    }

    @Override
    public User getMe(String userId, Map<String, Boolean> requiredAttributes)
            throws CharonException, BadRequestException, NotFoundException {
        //redirect to getUser;
        return getUser(userId, requiredAttributes);
    }

    @Override
    public User createMe(User user, Map<String, Boolean> requiredAttributes) throws CharonException,
            ConflictException, BadRequestException {
        //redirect to createUser
        return createUser(user, requiredAttributes);
    }

    @Override
    public void deleteMe(String userID) throws NotFoundException, CharonException, NotImplementedException,
            BadRequestException {
        //redirect to deleteUser
        deleteUser(userID);
    }

    @Override
    public User updateMe(User user, Map<String, Boolean> requiredAttributes) throws NotImplementedException,
            CharonException, BadRequestException, NotFoundException {
        //redirect to updateUser
        return updateUser(user, requiredAttributes);
    }

    @Override
    public Group createGroup(Group group, Map<String, Boolean> requiredAttributes) throws CharonException,
            ConflictException, NotImplementedException, BadRequestException {

        if (log.isDebugEnabled()) {
            log.debug("Creating group: " + group.toString());
        }
        //get the claim, value pair from the group object.
        Map<String, String> claimsMap = SCIMClaimResolver.getClaimsMap(group);

        //create group model as that is what need to send to identity store api.
        GroupModel groupModel = getGroupModelFromClaims(claimsMap);
        //TODO this is a temporary method. need to remove this once the claim management is completed.
        groupModel = ClaimMapper.getInstance().convertMetaToWso2Dialect(groupModel);

        org.wso2.carbon.identity.mgt.bean.Group userStoreGroup = null;
        try {
            //TODO : get the domain of the user store and call that method instead of this method.
            //add the group.
            userStoreGroup = identityStore.addGroup(groupModel);

        } catch (IdentityStoreException e) {
            throw new CharonException("Error in creating the group.", e);
        }
        // list to store the user ids which will be used to create the group's members.
        List<String> userIds = new ArrayList<>();

        MultiValuedAttribute membersAttribute = (MultiValuedAttribute)
                group.getAttribute(SCIMConstants.GroupSchemaConstants.MEMBERS);
        //add the member ids to userIds list
        if (membersAttribute != null) {
            List<Attribute> membersValues = membersAttribute.getAttributeValues();
            for (Attribute attribute : membersValues) {
                ComplexAttribute attributeValue = (ComplexAttribute) attribute;
                SimpleAttribute valueAttribute = (SimpleAttribute)
                        attributeValue.getSubAttribute(SCIMConstants.CommonSchemaConstants.VALUE);
                userIds.add((String) valueAttribute.getValue());
            }
        }
        //add the members to the created group.
        try {
            identityStore.updateUsersOfGroup(userStoreGroup.getUniqueGroupId(), userIds);
        } catch (IdentityStoreException e) {
            throw new CharonException("Error in adding members to the group", e);
        }
        log.info("Group: " + group.getDisplayName() + " is created through SCIM.");
        //get the group again from the user store and send it to client.
        try {
            return this.getGroup(userStoreGroup.getUniqueGroupId(), requiredAttributes);
        } catch (NotFoundException e) {
            throw new CharonException("Error in retrieving the group from the user store.", e);
        }
    }

    @Override
    public Group getGroup(String groupId, Map<String, Boolean> requiredAttributes) throws NotImplementedException,
            BadRequestException, CharonException, NotFoundException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving group: " + groupId);
        }
        try {
            org.wso2.carbon.identity.mgt.bean.Group userStoreGroup = identityStore.getGroup(groupId);

            //TODO:We need to pass the scim claim dialect for this method
            List<Claim> claimList = userStoreGroup.getClaims();
            //TODO this is a temporary method. need to remove this once the claim management is completed.
            claimList = ClaimMapper.getInstance().convertGroupToScimDialect(claimList);

            Group scimGroup = getSCIMGroup(userStoreGroup, claimList);

            log.info("Group: " + scimGroup.getDisplayName() + " is retrieved through SCIM.");

            return scimGroup;

        } catch (IdentityStoreException e) {
           throw new CharonException("Error in getting the group : " + groupId, e);
        } catch (GroupNotFoundException e) {
            throw new NotFoundException("Group with the id :" + groupId + " does not exists.");
        }
    }

    @Override
    public void deleteGroup(String groupId) throws NotFoundException, CharonException, NotImplementedException,
            BadRequestException {

        if (log.isDebugEnabled()) {
            log.debug("Deleting Group: " + groupId);
        }
        try {
            //TODO : think of adding the domain.
            identityStore.deleteGroup(groupId);

            log.info("User with the id : " + groupId + " is deleted through SCIM.");

        } catch (GroupNotFoundException e) {
            throw new NotFoundException("Group with the group id : " + groupId + " does not exists.");

        } catch (IdentityStoreException e) {
            throw new CharonException("Error in deleting the group with the id: " + groupId, e);

        }

    }

    @Override
    public List<Object> listGroupsWithGET(Node rootNode, int startIndex, int count, String sortBy,
                                          String sortOrder, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {

        // check if it is a pagination and filter combination.
        if (sortOrder == null && sortBy == null && rootNode != null) {

            return listGroupsWithPaginationAndFilter(rootNode, startIndex, count);

        } //check if it is a pagination only request.
        if (sortOrder == null && sortBy == null && rootNode == null) {
            return listGroupsWithPagination(startIndex, count);

        } else {
            throw new NotImplementedException("Sorting is not supported.");
        }
    }

    @Override
    public Group updateGroup(Group oldGroup, Group newGroup, Map<String, Boolean> requiredAttributes) throws
            NotImplementedException, BadRequestException, CharonException, NotFoundException {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Updating group: " + oldGroup.toString());
            }
            //get the claims map from the new scim user object.
            Map<String, String> claims = SCIMClaimResolver.getClaimsMap(newGroup);
            //get the claim list to be updated.
            List<Claim> claimList = getGroupModelFromClaims(claims).getClaims();

            //TODO this is a temporary method. need to remove this once the claim management is completed.
            claimList = ClaimMapper.getInstance().convertMetaToWso2Dialect(claimList);
            //set user updated claim values
            //TODO : Give the domain name
            identityStore.updateGroupClaims(oldGroup.getId(), claimList);
            //update the member list separately.
            updateMemberList(oldGroup, newGroup);

            log.info("User: " + newGroup.getDisplayName() + " updated through SCIM.");
            //get the updated group from the user core and sent it to client.
            return this.getGroup(newGroup.getId(), requiredAttributes);

        } catch (GroupNotFoundException e) {
            throw new NotFoundException("No such group with the group id : " + oldGroup.getId());
        } catch (IdentityStoreException e) {
            throw new CharonException("Error in updating the Group", e);
        }
    }

    @Override
    public List<Object> listGroupsWithPost(SearchRequest searchRequest, Map<String, Boolean> requiredAttributes)
            throws NotImplementedException, BadRequestException, CharonException {
        // this is identical to getGroupsWithGet.
        return listGroupsWithGET(searchRequest.getFilter(), searchRequest.getStartIndex(), searchRequest.getCount(),
                searchRequest.getSortBy(), searchRequest.getSortOder(), requiredAttributes);
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
     * This method is to get the group model from the claims.
     * @param claimsMap
     * @return
     */
    private GroupModel getGroupModelFromClaims(Map<String, String> claims) {

        GroupModel groupModel = new GroupModel();

        List<Claim> claimList = new ArrayList<>();

        for (Entry<String, String> claim : claims.entrySet()) {
            //create claims for all entries and add it to claim list
            Claim newClaim = new Claim();
            newClaim.setClaimUri(claim.getKey());
            newClaim.setValue(claim.getValue());
            //add the right claim dialect for the claim.
            if (claim.getKey().contains(SCIMCommonConstants.GROUP_DIALECT)) {
                //claim dialect is the scim group dialect.
                newClaim.setDialectUri(SCIMCommonConstants.GROUP_DIALECT);

            } else if (claim.getKey().contains(SCIMCommonConstants.CORE_DIALECT)) {
                //claim dialect is the scim core dialect.
                newClaim.setDialectUri(SCIMCommonConstants.CORE_DIALECT);

            }
            claimList.add(newClaim);
        }
        //set the claim to group model.
        groupModel.setClaims(claimList);

        return groupModel;
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

        //map to keep the claim, value  pair.
        Map<String, String> attributeMap = new HashMap<>();

        for (Claim claim : claimURIList) {
            attributeMap.put(claim.getClaimUri(), claim.getValue());
        }

        //get the groups of the user separately as we are going to make a scim user with the groups in it.
        try {
            List<org.wso2.carbon.identity.mgt.bean.Group> groups =
                    identityStore.getGroupsOfUser(userStoreUser.getUniqueUserId());

            //construct the SCIM Object from the attributes
            User scimUser = (User) SCIMClaimResolver.constructSCIMObjectFromAttributes(attributeMap, 1);
            //set each group of the user
            for (org.wso2.carbon.identity.mgt.bean.Group group : groups) {
                if (group != null) { // can be null for non SCIM groups
                    scimUser.setGroup(null, group.getUniqueGroupId(), null);
                }
            }
            //set the id of the user from the unique user id.
            scimUser.setId(userStoreUser.getUniqueUserId());
            //set the schemas of the scim user
            scimUser.setSchemas();
            //set location
            scimUser.setLocation(SCIMCommonConstants.USERS_LOCATION + "/" + userStoreUser.getUniqueUserId());

            return scimUser;

        } catch (IdentityStoreException | UserNotFoundException e) {
            throw new CharonException("Error in getting the groups of the user.", e);
        } catch (BadRequestException | NotFoundException e) {
            throw new CharonException("Error in creating the scim user from the claims and the values.", e);
        }
    }


    /*
     * This method is to get the scim group from the claims.
     * @param userStoreGroup
     * @param claimURIList
     * @return
     * @throws CharonException
     */
    private Group getSCIMGroup(org.wso2.carbon.identity.mgt.bean.Group userStoreGroup,
                             List<Claim> claimURIList) throws CharonException {

        //map to keep the claim, value  pair.
        Map<String, String> attributeMap = new HashMap<>();

        for (Claim claim : claimURIList) {
            attributeMap.put(claim.getClaimUri(), claim.getValue());
        }

        //get the members of the group separately as we are going to make a scim group with the members in it.
        try {
            //construct the SCIM Object from the attributes
            Group scimGroup = (Group) SCIMClaimResolver.constructSCIMObjectFromAttributes(attributeMap, 2);

            List<org.wso2.carbon.identity.mgt.bean.User> userList = userStoreGroup.getUsers();

            //we need a list of meta claims to get the userName of each member of the group
            List<MetaClaim> metaClaimList = new ArrayList<>();
            //set the userName claim
            metaClaimList.add(new MetaClaim(SCIMCommonConstants.USER_DIALECT,
                    SCIMConstants.UserSchemaConstants.USER_NAME_URI));

            //TODO : This is a temp method..need to get rid of this once the official claim resolver is completed.
            metaClaimList = ClaimMapper.getInstance().convertMetaToWso2Dialect(metaClaimList, null);

            //set members of the group
            for (org.wso2.carbon.identity.mgt.bean.User user : userList) {
                //get the userName of each member.
                List<Claim> claimValueList = identityStore.getUser(user.getUniqueUserId()).getClaims(metaClaimList);
                scimGroup.setMember(user.getUniqueUserId(), claimValueList.get(0).getValue());
            }
            //set the id of the user from the unique user id.
            scimGroup.setId(userStoreGroup.getUniqueGroupId());
            //set the schemas of the scim user
            scimGroup.setSchemas();
            //set the location
            scimGroup.setLocation(SCIMCommonConstants.GROUPS_LOCATION + "/" + userStoreGroup.getUniqueGroupId());

            return scimGroup;

        } catch (BadRequestException | GroupNotFoundException |
                UserNotFoundException | IdentityStoreException | NotFoundException e) {
            throw new CharonException("Error in creating the group.", e);
        }
    }

    /*
     * This method is to list the users with pagination.
     * @param startIndex
     * @param count
     * @return
     * @throws CharonException
     */
    private List<Object> listUsersWithPagination(int startIndex, int count) throws CharonException {
        try {
            //get the user list according to the start index and the count values provided.
            //TODO : Add the domain of the store.
            List<org.wso2.carbon.identity.mgt.bean.User> userList = identityStore.listUsers(startIndex, count);
            List<Object> userObjectList = new ArrayList<>();

            //we need to set the first item of the array to be the number of users in the given domain.
            //TODO : Add this value form the identity Store.
            userObjectList.add(100);
            //convert identity store users to objects.
            for (org.wso2.carbon.identity.mgt.bean.User user : userList) {
                //get the details of the users.
                //TODO:We need to pass the scim claim dialect for this method
                List<Claim> claimList = user.getClaims();
                //TODO this is a temporary method. need to remove this once the claim management is completed.
                claimList = ClaimMapper.getInstance().convertToScimDialect(claimList);

                User scimUser = getSCIMUser(user, claimList);

                userObjectList.add(scimUser);
            }
            return userObjectList;

        } catch (IdentityStoreException | UserNotFoundException e) {
            throw new CharonException("Error in getting the user list with start index :"
                    + startIndex + " and " + "count of :" + count, e);
        }
    }

    /*
     * This method is to list the groups with pagination.
     * @param startIndex
     * @param count
     * @return
     * @throws CharonException
     */
    private List<Object> listGroupsWithPagination(int startIndex, int count) throws CharonException {
        try {
            //get the group list according to the start index and the count values provided.
            //TODO : Add the domain of the store.
            List<org.wso2.carbon.identity.mgt.bean.Group> groupList = identityStore.listGroups(startIndex, count);

            List<Object> groupObjectList = new ArrayList<>();

            //we need to set the first item of the array to be the number of users in the given domain.
            //TODO : Add this value form the identity Store.
            groupObjectList.add(100);
            //convert identity store users to objects.
            for (org.wso2.carbon.identity.mgt.bean.Group group : groupList) {
                //get the details of the users.
                //TODO:We need to pass the scim claim dialect for this method
                List<Claim> claimList = group.getClaims();

                //TODO this is a temporary method. need to remove this once the claim management is completed.
                claimList = ClaimMapper.getInstance().convertToScimDialect(claimList);

                Group scimGroup = getSCIMGroup(group, claimList);

                groupObjectList.add(scimGroup);
            }
            return groupObjectList;

        } catch (IdentityStoreException | GroupNotFoundException e) {
            throw new CharonException("Error in getting the user list with start index :"
                    + startIndex + " and " + "count of :" + count, e);
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
    private List<Object> listUsersWithPaginationAndFilter(Node rootNode, int startIndex, int count)
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
        if (((ExpressionNode) (rootNode)).getOperation().equalsIgnoreCase("eq")) {
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
                //TODO : This is a temp method.. need to get rid of this after claim mapping is completed.
                filterClaim = ClaimMapper.getInstance().convertMetaToWso2Dialect(filterClaim);

                userList = identityStore.listUsers(filterClaim, startIndex, count);

                List<Object> userObjectList = new ArrayList<>();
                //we need to set the first item of the array to be the number of users in the given domain.
                //TODO : Add this value form the identity Store.
                userObjectList.add(100);
                //convert identity store users to objects.
                for (org.wso2.carbon.identity.mgt.bean.User user : userList) {
                    //get the details of the users.
                    //TODO:We need to pass the scim claim dialect for this method
                    List<Claim> claimList = user.getClaims();
                    //TODO this is a temporary method. need to remove this once the claim management is completed.
                    claimList = ClaimMapper.getInstance().convertToScimDialect(claimList);

                    User scimUser = getSCIMUser(user, claimList);

                    userObjectList.add(scimUser);
                }
                return userObjectList;

            } catch (IdentityStoreException | UserNotFoundException e) {
                throw new CharonException("Error in getting the user list with the filter and pagination.", e);
            }

        } else {
            throw new NotImplementedException("Filter type :" +
                    ((ExpressionNode) (rootNode)).getOperation() + " is not supported.");
        }
    }

    /*
     * List the groups with pagination and filter (Eq filter only)
     * @param rootNode
     * @param startIndex
     * @param count
     * @return
     * @throws NotImplementedException
     * @throws CharonException
     */
    private List<Object> listGroupsWithPaginationAndFilter(Node rootNode, int startIndex, int count)
            throws NotImplementedException, CharonException {

        //Filter model simply consists of a binary tree where the terminal nodes are the filter expressions and
        //non -terminal nodes are the logical operators.
        //we currently do not support complex type filter
        //eg :dsiplayName Eq vTour Guide AND members.value eq 1212
        if (rootNode.getRightNode() != null) {
            throw new NotImplementedException("Complex filters are not implemented.");
        }
        if (rootNode.getLeftNode() != null) {
            throw new NotImplementedException("Complex filters are not implemented.");
        }
        //we only support 'eq' filter
        if (((ExpressionNode) (rootNode)).getOperation().equalsIgnoreCase("eq")) {
            //create a claim for the asked eq related attribute
            Claim filterClaim = new Claim();

            filterClaim.setValue(((ExpressionNode) (rootNode)).getValue());
            filterClaim.setClaimUri(((ExpressionNode) (rootNode)).getAttributeValue());

            //add the right claim dialect for the claim.
            if (((ExpressionNode) (rootNode)).getAttributeValue().contains(SCIMCommonConstants.GROUP_DIALECT)) {
                //claim dialect is the scim user dialect.
                filterClaim.setDialectUri(SCIMCommonConstants.GROUP_DIALECT);

            } else if (((ExpressionNode) (rootNode)).getAttributeValue().contains(SCIMCommonConstants.CORE_DIALECT)) {
                //claim dialect is the scim core dialect.
                filterClaim.setDialectUri(SCIMCommonConstants.CORE_DIALECT);

            }
            try {
                List<org.wso2.carbon.identity.mgt.bean.Group> groupList;
                // get the group list from the user core.
                //TODO : This is a temp method.. need to get rid of this after claim mapping is completed.
                filterClaim = ClaimMapper.getInstance().convertMetaToWso2Dialect(filterClaim);
                //TODO : add domain here.
                //get the groups list
                groupList = identityStore.listGroups(filterClaim, startIndex, count);

                List<Object> groupObjectList = new ArrayList<>();
                //we need to set the first item of the array to be the number of users in the given domain.
                //TODO : Add this value from the identity Store.
                //total results.
                groupObjectList.add(100);
                //convert identity store users to objects.
                for (org.wso2.carbon.identity.mgt.bean.Group group : groupList) {
                    //get the details of the groups.
                    //TODO:We need to pass the scim claim dialect for this method
                    List<Claim> claimList = group.getClaims();
                    //TODO this is a temporary method. need to remove this once the claim management is completed.
                    claimList = ClaimMapper.getInstance().convertToScimDialect(claimList);

                    Group scimGroup = getSCIMGroup(group, claimList);

                    groupObjectList.add(scimGroup);
                }

                return groupObjectList;

            } catch (IdentityStoreException | GroupNotFoundException e) {
                throw new CharonException("Error in getting the group list with the filter and pagination.", e);
            }

        } else {
            throw new NotImplementedException("Filter type :" +
                    ((ExpressionNode) (rootNode)).getOperation() + " is not supported.");
        }
    }


    /*
     * Update the members list of a given group
     * @param oldGroup
     * @param newGroup
     * @throws CharonException
     * @throws IdentityStoreException
     */
    private void updateMemberList(Group oldGroup, Group newGroup) throws CharonException, IdentityStoreException {
        // list to store the old user ids which will be removed from the group's members.
        List<String> oldUserIds = new ArrayList<>();
        // list to store the new user ids which will be added to the group's members.
        List<String> newUserIds = new ArrayList<>();

        MultiValuedAttribute oldMembersAttribute = (MultiValuedAttribute)
                oldGroup.getAttribute(SCIMConstants.GroupSchemaConstants.MEMBERS);
        //add the member ids to oldUserIds list
        if (oldMembersAttribute != null) {
            List<Attribute> membersValues = oldMembersAttribute.getAttributeValues();
            for (Attribute attribute : membersValues) {
                ComplexAttribute attributeValue = (ComplexAttribute) attribute;
                SimpleAttribute valueAttribute = (SimpleAttribute)
                        attributeValue.getSubAttribute(SCIMConstants.CommonSchemaConstants.VALUE);
                oldUserIds.add((String) valueAttribute.getValue());
            }
        }

        MultiValuedAttribute newMembersAttribute = (MultiValuedAttribute)
                newGroup.getAttribute(SCIMConstants.GroupSchemaConstants.MEMBERS);
        //add the member ids to newUserIds list
        if (newMembersAttribute != null) {
            List<Attribute> membersValues = newMembersAttribute.getAttributeValues();
            for (Attribute attribute : membersValues) {
                ComplexAttribute attributeValue = (ComplexAttribute) attribute;
                SimpleAttribute valueAttribute = (SimpleAttribute)
                        attributeValue.getSubAttribute(SCIMConstants.CommonSchemaConstants.VALUE);
                newUserIds.add((String) valueAttribute.getValue());
            }
        }
        //TODO : add the domain name here.
        identityStore.updateUsersOfGroup(oldGroup.getId(), newUserIds, oldUserIds);
    }

}

