/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.protocol.endpoints.DefaultResourceURLBuilder;

/**
 * Class responsible for constructing SCIM2 resource endpoints with tenant context.
 */
public class IdentityResourceURLBuilder extends DefaultResourceURLBuilder {

    private static final Log log = LogFactory.getLog(IdentityResourceURLBuilder.class);

    @Override
    public String build(String resource) throws NotFoundException {

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            try {
                String scimURL = ServiceURLBuilder.create().addPath(SCIMCommonConstants.SCIM2_ENDPOINT).build()
                        .getAbsolutePublicURL();
                return scimURL + resource;
            } catch (URLBuilderException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error occurred while building the SCIM2 endpoint with tenant " +
                            "qualified URL.", e);
                }
                // Fallback to super class build method during error scenarios.
                return super.build(resource);
            }
        } else {
            return super.build(resource);
        }
    }
}
