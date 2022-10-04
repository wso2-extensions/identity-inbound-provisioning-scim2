## Welcome to the WSO2 Identity Server (IS) identity-inbound-provisioning-scim2.

WSO2 IS is one of the best Identity Servers, which enables you to offload your identity and user entitlement management burden totally from your application. It comes with many features, supports many industry standards and most importantly it allows you to extent it according to your security requirements. This repo contains Authenticators written to work with different third party systems.

With WSO2 IS, there are lot of provisioning capabilities available. There are 3 major concepts as Inbound, outbound provisioning and Just-In-Time provisioning. Inbound provisioning means , provisioning users and groups from an external system to IS. Outbound provisioning means , provisioning users from IS to other external systems. JIT provisioning means , once a user tries to login from an external IDP, a user can be created on the fly in IS with JIT. Repos under this account holds such components invlove in communicating with external systems.

## Building from the source

If you want to build **identity-inbound-provisioning-scim2** from the source code:

1. Install Java 11 (or Java 17)
2. Install Apache Maven 3.x.x (https://maven.apache.org/download.cgi#)
3. Get a clone or download the source from this repository (https://github.com/wso2-extensions/identity-inbound-provisioning-scim2)
4. Run the Maven command ``mvn clean install`` from the ``identity-inbound-provisioning-scim2`` directory.