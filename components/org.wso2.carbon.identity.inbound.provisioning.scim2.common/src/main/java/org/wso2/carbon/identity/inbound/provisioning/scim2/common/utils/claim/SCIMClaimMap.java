package org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.claim;

import java.util.List;

/**
 * This is a util class to convert the claims between wso2 dialect and scim dialect.
 * This should be removed once the claim management is properly implemented.
 */
public class SCIMClaimMap {
    private List<MappedClaim> claims;

    public List<MappedClaim> getClaims() {
        return claims;
    }

    public void setClaims(List<MappedClaim> claims) {
        this.claims = claims;
    }
}
