package org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.claim;

/**
 * This is a util class to convert the claims between wso2 dialect and scim dialect.
 * This should be removed once the claim management is properly implemented.
 */
public class MappedClaim {
    private String wso2Claim;
    private String scimClaim;

    public String getScimClaim() {
        return scimClaim;
    }

    public void setScimClaim(String attribute) {
        this.scimClaim = attribute;
    }

    public String getWso2Claim() {
        return wso2Claim;
    }

    public void setClaimUri(String claimUri) {
        this.wso2Claim = claimUri;
    }
}
