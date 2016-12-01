package org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.claim;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.model.UserModel;
import org.wso2.carbon.identity.mgt.util.IdentityMgtConstants;
import org.wso2.charon.core.v2.schema.SCIMConstants;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This is a util class to convert the claims between wso2 dialect and scim dialect.
 * This should be removed once the claim management is properly implemented.
 */
public class ClaimMapper {

    private static Logger log = LoggerFactory.getLogger(ClaimMapper.class);

    public static final String CARBON_HOME = "carbon.home";
    private SCIMClaimMap configEntry;
    private Map<String, String> wso2Map = new HashMap<>();
    private Map<String, String> scimMap = new HashMap<>();
    private static ClaimMapper instance = new ClaimMapper();

    public static ClaimMapper getInstance() {
        return instance;
    }

    private ClaimMapper() {
        init();
    }

    public void init() {
        Path path = Paths.get(System.getProperty(CARBON_HOME), "conf", "identity", "scim-claim-mapper.yml");


        if (Files.exists(path)) {
            try {
                Reader in = new InputStreamReader(Files.newInputStream(path), StandardCharsets.UTF_8);
                Yaml yaml = new Yaml();
                yaml.setBeanAccess(BeanAccess.FIELD);
                configEntry = yaml.loadAs(in, SCIMClaimMap.class);
            } catch (IOException e) {
                log.error("Error while reading claim mapping.");
            }
        } else {
            log.error("Error while reading claim mapping.");
        }

        for (MappedClaim mappedClaim : configEntry.getClaims()) {
            scimMap.put(mappedClaim.getScimClaim(), mappedClaim.getWso2Claim());
            wso2Map.put(mappedClaim.getWso2Claim(), mappedClaim.getScimClaim());
        }
    }


    public List<Claim> convertToScimDialect(List<Claim> claimList) {
        List<Claim> convertedClaims = new ArrayList<>();
        for (Claim claim : claimList) {
            String uri = wso2Map.get(claim.getClaimUri());
            if (uri != null) {
                Claim newClaim = new Claim(SCIMConstants.USER_CORE_SCHEMA_URI, uri, claim.getValue());
                convertedClaims.add(newClaim);
            }
        }
        return convertedClaims;

    }

    public UserModel convertToWso2Dialect(UserModel userModel) {
        UserModel newUserModel = new UserModel();
        List<Claim> convertedClaims = new ArrayList<>();
        for (Claim claim : userModel.getClaims()) {
            String uri = scimMap.get(claim.getClaimUri());
            if (uri != null) {
                Claim newClaim = new Claim(IdentityMgtConstants.CLAIM_ROOT_DIALECT, uri, claim.getValue());
                convertedClaims.add(newClaim);
            }
        }
        newUserModel.setClaims(convertedClaims);
        newUserModel.setCredentials(userModel.getCredentials());
        return newUserModel;

    }

    public List<Claim> convertToWso2Dialect(List<Claim> claimList) {
        List<Claim> convertedClaims = new ArrayList<>();
        for (Claim claim : claimList) {
            String uri = scimMap.get(claim.getClaimUri());
            if (uri != null) {
                Claim newClaim = new Claim(IdentityMgtConstants.CLAIM_ROOT_DIALECT, uri, claim.getValue());
                convertedClaims.add(newClaim);
            }
        }
        return convertedClaims;

    }
}
