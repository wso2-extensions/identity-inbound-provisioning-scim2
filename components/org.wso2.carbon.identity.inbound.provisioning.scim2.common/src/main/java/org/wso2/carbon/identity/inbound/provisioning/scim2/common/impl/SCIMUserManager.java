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
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.AttributeMapper;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.exception.ClaimManagerException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
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
import org.wso2.charon.core.v2.utils.CopyUtil;
import org.wso2.charon.core.v2.utils.codeutils.ExpressionNode;
import org.wso2.charon.core.v2.utils.codeutils.Node;
import org.wso2.charon.core.v2.utils.codeutils.SearchRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * This is the class which deals with user core APIs.
 */
public class SCIMUserManager implements UserManager {
    private static Logger log = LoggerFactory.getLogger(SCIMUserManager.class);

    IdentityStore identityStore = null;

    public SCIMUserManager(IdentityStore identityStore) {
        this.identityStore = identityStore;
    }

    @Override
    public User createUser(User user, Map<String, Boolean> requiredAttributes) throws CharonException,
            ConflictException, BadRequestException {
        try {

            if (log.isDebugEnabled()) {
                log.debug("Creating user: " + user.getUserName());
            }
            //get the groups attribute as we are going to explicitly store the info of the user's groups
            MultiValuedAttribute groupsAttribute = (MultiValuedAttribute) CopyUtil.deepCopy(
                    user.getAttribute(SCIMConstants.UserSchemaConstants.GROUPS));

            user.deleteAttribute(SCIMConstants.UserSchemaConstants.GROUPS);
            List<String> groupIds = null;
            if (groupsAttribute != null) {
                List<Attribute> subValues = groupsAttribute.getAttributeValues();
                groupIds = new ArrayList<>();
                for (Attribute subValue : subValues) {
                    SimpleAttribute valueAttribute = (SimpleAttribute)
                            ((ComplexAttribute) (subValue)).getSubAttribute(SCIMConstants.CommonSchemaConstants.VALUE);
                    groupIds.add((String) valueAttribute.getValue());
                }
            }

            Map<String, String> claimsMap = AttributeMapper.getClaimsMap(user);

            //TODO : Replay this method with getUserModelFromClaims
            UserModel userModel = demoGetUserModelFromClaims(claimsMap);

            //TODO : get the domain of the user store and call that method instead of this method.
            identityStore.addUser(userModel);

            if (groupIds != null && groupIds.size() != 0) {
                //now add the user's groups explicitly.
                identityStore.updateGroupsOfUser(user.getId(), groupIds);
            }
            //need to add users groups if it is available in the request
            log.info("User: " + user.getUserName() + " is created through SCIM.");

        } catch (IdentityStoreException e) {
            String errMsg = "User : " + user.getUserName() + " already exists.";
            throw new ConflictException(errMsg);
        }
        return user;
    }


    @Override
    public User getUser(String userId, Map<String, Boolean> requiredAttributes) throws CharonException,
            BadRequestException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving user: " + userId);
        }
        User scimUser = null;
        try {
            org.wso2.carbon.identity.mgt.bean.User userStoreUser = identityStore.getUser(userId);

            //TODO:We need to pass the claim dialect for this method
            List<Claim> claimList = userStoreUser.getClaims();

            //TODO : this method should be getSCIMUser() -this is testing only
            scimUser = this.demogetscimuser(userStoreUser, claimList);

            log.info("User: " + scimUser.getUserName() + " is retrieved through SCIM.");

        } catch (IdentityStoreException e) {
            throw new CharonException("Error in getting user from the userid :" + userId, e);
        } catch (UserNotFoundException e) {
            throw new CharonException("User not found with the given userid :" + userId, e);
        } catch (ClaimManagerException e) {
            throw new CharonException("Error in getting user claims", e);
        }
        return scimUser;
    }

    @Override
    public void deleteUser(String userId) throws NotFoundException, CharonException, NotImplementedException,
            BadRequestException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting user: " + userId);
        }
        String userName = null;
        try {
            org.wso2.carbon.identity.mgt.bean.User existingUser = identityStore.getUser(userId);

            List<String> claimList = new ArrayList<>();

            claimList.add("urn:ietf:params:scim:schemas:core:2.0:User:userName");

            List<Claim> userNames = existingUser.getClaims(claimList);

            //we assume (since id is unique per user) only one user exists for a given id
            userName = userNames.get(0).getValue();

            identityStore.deleteUser(userId);

            log.info("User: " + userName + " is deleted through SCIM.");

        } catch (UserNotFoundException | ClaimManagerException | IdentityStoreException e) {
            throw new NotFoundException("No matching user with the name: " + userName);
        }
    }

    @Override
    public List<Object> listUsersWithGET(Node rootNode, int startIndex, int count, String sortBy,
                                         String sortOrder, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {
        if (count != 0 && sortOrder == null && sortBy == null && rootNode == null) {
            return listWithPagination(startIndex, count);
        } else if (count != 0 && sortOrder == null && sortBy == null && rootNode != null) {
            if (rootNode.getRightNode() != null) {
                throw new NotImplementedException("Complex filters are not implemented.");
            }
            if (rootNode.getLeftNode() != null) {
                throw new NotImplementedException("Complex filters are not implemented.");
            }

            if (((ExpressionNode) (rootNode)).getOperation().equals("EQ")) {

                Claim filterClaim = new Claim();

                filterClaim.setValue(((ExpressionNode) (rootNode)).getValue());
                filterClaim.setClaimUri(((ExpressionNode) (rootNode)).getAttributeValue());


                List<String> list = Arrays.asList(((ExpressionNode) (rootNode)).getAttributeValue().split(":"));

                if (list.get(0).equals("urn:ietf:params:scim:schemas:core:2.0:User")) {
                    filterClaim.setDialectUri("urn:ietf:params:scim:schemas:core:2.0:User");
                } else if (list.get(0).equals("urn:ietf:params:scim:schemas:core:2.0")) {
                    filterClaim.setDialectUri("urn:ietf:params:scim:schemas:core:2.0:User");
                } else {
                    filterClaim.setDialectUri(SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema()
                            .getURI());
                }
                return listWithPaginationAndFilter(filterClaim, startIndex, count);

            } else {
                throw new CharonException("Filter type :" + ((ExpressionNode) (rootNode)).getOperation() + "does not " +
                        "supported.");
            }
        }
        return null;
    }

    private List<Object> listWithPaginationAndFilter(Claim filterClaim, int startIndex, int count) {
        return null;
    }

    private List<Object> listWithPagination(int startIndex, int count) {
        return null;
    }

    @Override
    public List<Object> listUsersWithPost(SearchRequest searchRequest, Map<String, Boolean> requiredAttributes)
            throws CharonException, NotImplementedException, BadRequestException {
        return listUsersWithGET(searchRequest.getFilter(), searchRequest.getStartIndex(), searchRequest.getCount(),
                searchRequest.getSortBy(), searchRequest.getSortOder(), requiredAttributes);
    }

    @Override
    public User updateUser(User user, Map<String, Boolean> requiredAttributes) throws NotImplementedException,
            CharonException, BadRequestException {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Updating user: " + user.getUserName());
            }

            Map<String, String> claims = AttributeMapper.getClaimsMap(user);

            List<Claim> claimList = new ArrayList<>();
            for (Entry<String, String> claim : claims.entrySet()) {
                Claim newClaim = new Claim();
                newClaim.setClaimUri(claim.getKey());
                newClaim.setValue(claims.get(claim.getKey()));
                List<String> list = Arrays.asList(claim.getKey().split(":"));

                if (list.get(0).equals("urn:ietf:params:scim:schemas:core:2.0:User")) {
                    newClaim.setDialectUri("urn:ietf:params:scim:schemas:core:2.0:User");
                } else if (list.get(0).equals("urn:ietf:params:scim:schemas:core:2.0")) {
                    newClaim.setDialectUri("urn:ietf:params:scim:schemas:core:2.0:User");
                } else {
                    newClaim.setDialectUri(SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema().getURI());
                }
                claimList.add(newClaim);
            }
            //set user claim values
            identityStore.updateUserClaims(user.getUserName(), claimList);

            log.info("User: " + user.getUserName() + " updated updated through SCIM.");
            return user;
        } catch (IdentityStoreException e) {
            throw new CharonException("Error in updading the user.");
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

    private UserModel demoGetUserModelFromClaims(Map<String, String> claims) {
        UserModel userModel = new UserModel();
        List<Claim> claimList = new ArrayList<>();
        for (Entry<String, String> claim : claims.entrySet()) {
            if (claim.getKey().equals("urn:ietf:params:scim:schemas:core:2.0:User:userName")) {
                Claim newClaim = new Claim();
                newClaim.setClaimUri("http://wso2.org/claims/username");
                newClaim.setValue(claim.getValue());
                newClaim.setDialectUri("http://wso2.org/claims");
                claimList.add(newClaim);

            } else if (claim.getKey().equals("urn:ietf:params:scim:schemas:core:2.0:User:name.givenName")) {
                Claim newClaim = new Claim();
                newClaim.setClaimUri("http://wso2.org/claims/firstName");
                newClaim.setValue(claim.getValue());
                newClaim.setDialectUri("http://wso2.org/claims");
                claimList.add(newClaim);
            }
        }
        userModel.setClaims(claimList);
        return userModel;
    }

/*
    private UserModel getUserModelFromClaims(Map<String, String> claims) {
        UserModel userModel = new UserModel();
        List<Claim> claimList = new ArrayList<>();
        for (Entry<String, String> claim : claims.entrySet()) {
            Claim newClaim = new Claim();
            newClaim.setClaimUri(claim.getKey());
            newClaim.setValue(claim.getValue());
            //TODO check the logic
            List<String> list = Arrays.asList(claim.getKey().split(":"));

            if (list.get(7).equals("User")) {
                newClaim.setDialectUri("urn:ietf:params:scim:schemas:core:2.0:User");
            } else if (list.get(6).equals("2.0")) {
                newClaim.setDialectUri("urn:ietf:params:scim:schemas:core:2.0:User");
            } else {
                newClaim.setDialectUri(SCIMUserSchemaExtensionBuilder.getInstance().getExtensionSchema().getURI());
            }
            claimList.add(newClaim);
        }
        userModel.setClaims(claimList);
        return userModel;
    }
*/

/*
    private User getSCIMUser(org.wso2.carbon.identity.mgt.bean.User userStoreUser,
                             List<Claim> claimURIList) throws CharonException {
        try {
            User scimUser = null;

            List<String> claimURIs = new ArrayList<>();
            for (Claim claim : claimURIList) {
                claimURIs.add(claim.getClaimUri());
            }

            //obtain user claim values
            List<Claim> attributes = userStoreUser.getClaims(claimURIs);
            Map<String, String> attributeMap = new HashMap<>();

            for (Claim claim : attributes) {
                attributeMap.put(claim.getClaimUri(), claim.getValue());
            }

            List<org.wso2.carbon.identity.mgt.bean.Group> groups = identityStore.getGroupsOfUser(userStoreUser
                    .getUserId());

            //construct the SCIM Object from the attributes
            scimUser = (User) AttributeMapper.constructSCIMObjectFromAttributes(attributeMap, 1);

            for (org.wso2.carbon.identity.mgt.bean.Group group : groups) {
                if (group != null) { // can be null for non SCIM groups
                    scimUser.setGroup(null, group.getGroupId(), null);
                }
            }
            //set the schemas of the scim user
            scimUser.setSchemas();

            return scimUser;
        } catch (BadRequestException | IdentityStoreException | CharonException |
                ClaimManagerException | NotFoundException e) {
            throw new CharonException("Error in getting the user.");
        }

    }
*/
    //TODO : This method is for demo purpose only
    private User demogetscimuser(org.wso2.carbon.identity.mgt.bean.User userStoreUser,
                                 List<Claim> claimURIList) throws CharonException {
        try {
            User scimUser = null;

            List<String> claimURIs = new ArrayList<>();
            for (Claim claim : claimURIList) {
                claimURIs.add(claim.getClaimUri());
            }

            //obtain user claim values
            List<Claim> attributes = userStoreUser.getClaims(claimURIs);
            Map<String, String> attributeMap = new HashMap<>();

            for (Claim claim : attributes) {
                if (claim.getClaimUri().equals("http://wso2.org/claims/username")) {
                    attributeMap.put("urn:ietf:params:scim:schemas:core:2.0:User:userName", claim.getValue());
                }
            }

            //construct the SCIM Object from the attributes
            scimUser = (User) AttributeMapper.constructSCIMObjectFromAttributes(attributeMap, 1);
            //set the schemas of the scim user
            scimUser.setSchemas();

            return scimUser;
        } catch (BadRequestException | IdentityStoreException | CharonException |
                ClaimManagerException | NotFoundException e) {
            throw new CharonException("Error in getting the user.");
        }

    }

}

