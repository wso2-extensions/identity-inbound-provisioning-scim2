package org.wso2.carbon.identity.scim.common.internal;


import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.mgt.service.RealmService;


public class IdentitySCIMManagementComponent {

    @Reference(
            name = "identityCoreInitializedEventService",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unRegisterRealmService"
    )
    protected void registerRealmService(RealmService realmService) {
        IdentitySCIMDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unRegisterRealmService(RealmService realmService ) {
        //do nothing
    }


}
