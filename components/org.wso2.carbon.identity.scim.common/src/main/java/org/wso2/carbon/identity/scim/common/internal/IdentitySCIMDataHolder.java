package org.wso2.carbon.identity.scim.common.internal;

import org.wso2.carbon.identity.mgt.service.RealmService;

public class IdentitySCIMDataHolder {

    private static volatile IdentitySCIMDataHolder identitySCIMDataHolder;

    private RealmService realmService;

    public static IdentitySCIMDataHolder getInstance() {
        if (identitySCIMDataHolder == null) {
            synchronized (IdentitySCIMDataHolder.class) {
                if (identitySCIMDataHolder == null) {
                    identitySCIMDataHolder = new IdentitySCIMDataHolder();
                    return identitySCIMDataHolder;
                } else {
                    return identitySCIMDataHolder;
                }
            }
        } else {
            return identitySCIMDataHolder;
        }
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }
}
