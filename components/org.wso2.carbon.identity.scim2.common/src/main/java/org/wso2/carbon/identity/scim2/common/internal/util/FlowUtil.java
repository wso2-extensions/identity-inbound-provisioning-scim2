/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.internal.util;

import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;

/**
 * Utility class for handling flow-related operations.
 */
public class FlowUtil {

    /**
     * Enters a flow with the specified flow name and initiating persona.
     *
     * @param flowName The name of the flow to enter.
     */
    public static void enterFlow(Flow.Name flowName) {

        Flow.InitiatingPersona initiatingPersona = getFlowInitiatingPersona();

        Flow flow;
        if (Flow.isCredentialFlow(flowName)) {
            flow = new Flow.CredentialFlowBuilder()
                    .name(flowName)
                    .initiatingPersona(initiatingPersona)
                    .credentialType(Flow.CredentialType.PASSWORD)
                    .build();
        } else {
            flow = new Flow.Builder()
                    .name(flowName)
                    .initiatingPersona(initiatingPersona)
                    .build();
        }
        IdentityContext.getThreadLocalIdentityContext().enterFlow(flow);
    }

    private static Flow.InitiatingPersona getFlowInitiatingPersona() {

        Flow existingFlow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        if (existingFlow != null) {
            return existingFlow.getInitiatingPersona();
        } else if (IdentityContext.getThreadLocalIdentityContext().isApplicationActor()) {
            return Flow.InitiatingPersona.APPLICATION;
        } else if (IdentityContext.getThreadLocalIdentityContext().isUserActor()) {
            return Flow.InitiatingPersona.ADMIN;
        }
        return null;
    }
}
