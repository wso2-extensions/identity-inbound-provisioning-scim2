package org.wso2.carbon.identity.scim2.common.listener;

import org.apache.xpath.operations.Bool;
import org.mockito.Mock;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.scim2.common.group.SCIMGroupHandler;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.Permission;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.tenant.Tenant;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class SCIMUserOperationListenerTest {


    String userName ="admin";
    Object credentials = new Object();
    String [] roleList={"admin","internal/everyone","director","manager"};
    String profile="basic";
    Map<String,String> claims;


    @Mock
    UserStoreManager userStoreManager;

    @BeforeMethod
    public void setUp() throws Exception {
        claims = new HashMap<>();
        claims.put("http://wso2.org/claims/lastname","wije");
        claims.put("http://wso2.org/claims/address","100,Colombo,Sri Lanka");
        claims.put("http://wso2.org/claims/country","Sri Lanka");
        claims.put("http://wso2.org/claims/dob","02121994");
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testGetExecutionOrderId() throws Exception {


    }

    @Test
    public void testDoPreAuthenticate() throws Exception {

        Object obj = new Object();
        Assert.assertTrue(new SCIMUserOperationListener().doPreAuthenticate(userName,obj,userStoreManager));
    }

    @Test
    public void testDoPostAuthenticate() throws Exception {

        Assert.assertTrue(new SCIMUserOperationListener().doPostAuthenticate(userName,true,userStoreManager));
        Assert.assertTrue(new SCIMUserOperationListener().doPostAuthenticate(userName,false,userStoreManager));
    }

    @Test
    public void testDoPreAddUser() throws Exception {

    }

    @Test
    public void testDoPostAddUser() throws Exception {

        Assert.assertTrue(new SCIMUserOperationListener().doPostAddUser(userName,credentials,roleList,claims,profile,userStoreManager));
    }

    @Test
    public void testDoPreUpdateCredential() throws Exception {

    }

    @Test
    public void testDoPostUpdateCredential() throws Exception {
    }

    @Test
    public void testDoPreUpdateCredentialByAdmin() throws Exception {
    }

    @Test
    public void testDoPostUpdateCredentialByAdmin() throws Exception {
    }

    @Test
    public void testDoPreDeleteUser() throws Exception {
    }

    @Test
    public void testDoPostDeleteUser() throws Exception {
    }

    @Test
    public void testDoPreSetUserClaimValue() throws Exception {
    }

    @Test
    public void testDoPostSetUserClaimValue() throws Exception {
        Assert.assertTrue(new SCIMUserOperationListener().doPostSetUserClaimValue("Chiran",userStoreManager));
    }

    @Test
    public void testDoPreSetUserClaimValues() throws Exception {
    }

    @Test
    public void testDoPostSetUserClaimValues() throws Exception {
        Assert.assertTrue(new SCIMUserOperationListener().doPostSetUserClaimValues(userName,claims,profile,userStoreManager));
    }

    @Test
    public void testDoPreDeleteUserClaimValues() throws Exception {
    }

    @Test
    public void testDoPostDeleteUserClaimValues() throws Exception {
    }

    @Test
    public void testDoPreDeleteUserClaimValue() throws Exception {
    }

    @Test
    public void testDoPostDeleteUserClaimValue() throws Exception {
    }

    @Test
    public void testDoPreAddRole() throws Exception {

    }

    @Test
    public void testDoPostAddRole() throws Exception {
    }

    @Test
    public void testDoPreDeleteRole() throws Exception {
    }

    @Test
    public void testDoPostDeleteRole() throws Exception {
        Assert.assertTrue(new SCIMUserOperationListener().doPostDeleteRole("manager",userStoreManager));
    }

    @Test
    public void testDoPreUpdateRoleName() throws Exception {
        Assert.assertTrue(new SCIMUserOperationListener().doPreUpdateRoleName("director","manager",userStoreManager));
    }

    @Test
    public void testDoPostUpdateRoleName() throws Exception {

    }

    @Test
    public void testDoPreUpdateUserListOfRole() throws Exception {
    }

    @Test
    public void testDoPostUpdateUserListOfRole() throws Exception {
    }

    @Test
    public void testDoPreUpdateRoleListOfUser() throws Exception {
    }

    @Test
    public void testDoPostUpdateRoleListOfUser() throws Exception {
    }

    @Test
    public void testGetSCIMAttributes() throws Exception {
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}