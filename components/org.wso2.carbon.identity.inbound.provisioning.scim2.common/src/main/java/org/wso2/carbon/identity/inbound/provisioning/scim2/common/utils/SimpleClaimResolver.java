package org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils;

import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.claim.MetaClaim;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.model.UserModel;
import org.wso2.charon.core.v2.exceptions.BadRequestException;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.exceptions.NotFoundException;
import org.wso2.charon.core.v2.objects.User;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is to mock the claim mapping need to be happened between user core and the SCIM API layer.
 */

//TODO : This class need to be removed after having the official claim resolver.
public class SimpleClaimResolver {

    /*
     * This method is to get the demo user from the user core.
     * @param userStoreUser
     * @param claimURIList
     * @return
     * @throws CharonException
     */
    public static User demoGetScimUser(org.wso2.carbon.identity.mgt.bean.User userStoreUser,
                                       List<Claim> claimURIList) throws CharonException {
        try {
            User scimUser = null;

            List<MetaClaim> claimURIs = new ArrayList<>();
            for (Claim claim : claimURIList) {
                MetaClaim metaClaim = new MetaClaim();
                metaClaim.setClaimUri(claim.getClaimUri());
                metaClaim.setDialectUri(claim.getDialectUri());
                claimURIs.add(metaClaim);
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
            scimUser = (User) SCIMClaimResolver.constructSCIMObjectFromAttributes(attributeMap, 1);
            //set the schemas of the scim user
            scimUser.setSchemas();

            return scimUser;
        } catch (BadRequestException | IdentityStoreException | CharonException | NotFoundException e) {
            throw new CharonException("Error in getting the user.");
        } catch (UserNotFoundException e) {
            throw new CharonException("User does not exits.");
        }
    }

    /*
     * This method is to create the demo user model from claims and their values.
     * @param claims
     * @return
     */
    public static UserModel demoGetUserModelFromClaims(Map<String, String> claims) {
        UserModel userModel = new UserModel();
        List<Claim> claimList = new ArrayList<>();
        for (Map.Entry<String, String> claim : claims.entrySet()) {
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
}
