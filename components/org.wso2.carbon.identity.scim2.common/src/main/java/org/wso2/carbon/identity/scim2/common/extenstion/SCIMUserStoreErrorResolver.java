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

package org.wso2.carbon.identity.scim2.common.extenstion;

import org.wso2.carbon.user.api.UserStoreException;

/**
 * This extension point can be used to define how internal errors should be mapped to relevant API errors.
 */
public interface SCIMUserStoreErrorResolver {

    /**
     * Resolve a given user store exception to a proper Charon Exception with status code. implementation should
     * return null if the implementing class does not know or does not wish to translate the exception, so that
     * any other translator can get chance to do the resolving. The default resolver will resolve an exception
     * ultimately if no custom resolver resolves it.
     *
     * @param e User store exception thrown.
     * @return Resolved charon exception with proper http status code, NULL if the impl doesn't know how to resolve.
     */
    SCIMUserStoreException resolve(UserStoreException e);

    /**
     * Provide an order value for the implementation. Should be a positive integer.
     * implementation with the highest order get picked first.
     *
     * @return Order of the impl.
     */
    int getOrder();
}
