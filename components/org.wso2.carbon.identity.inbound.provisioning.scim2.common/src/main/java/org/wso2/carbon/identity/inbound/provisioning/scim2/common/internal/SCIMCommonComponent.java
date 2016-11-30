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

package org.wso2.carbon.identity.inbound.provisioning.scim2.common.internal;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.inbound.provisioning.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.mgt.service.RealmService;

/**
 * SCIM Common Component which captures the realmService.
 */
@Component(
        name = "identity.scim.common",
        immediate = true,
        property = {"componentName=wso2-carbon-identity-mgt"}
)
public class SCIMCommonComponent {
    private static Logger logger = LoggerFactory.getLogger(SCIMCommonComponent.class);

    @Activate
    protected void activate(ComponentContext ctx) {

        SCIMCommonUtils.init();

        if (logger.isDebugEnabled()) {
            logger.debug("SCIM Common component activated successfully.");
        }

    }
//TODO : remove this
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

    protected void unRegisterRealmService(RealmService realmService) {
        IdentitySCIMDataHolder.getInstance().setRealmService(null);
    }
}
