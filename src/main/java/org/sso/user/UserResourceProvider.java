package org.sso.user;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.*;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.persistence.EntityManager;
import javax.ws.rs.*;


public class UserResourceProvider implements RealmResourceProvider {
    private final KeycloakSession session;
    private final RealmModel realm;
    private final AuthenticationManager.AuthResult auth;
    private final  EntityManager em;

    public UserResourceProvider(KeycloakSession session) {
        this.session = session;
        this.auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        this.realm = session.getContext().getRealm();
        this.em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }


    protected PasswordHashProvider getHashProvider(PasswordPolicy policy) {
        PasswordHashProvider hash = this.session.getProvider(PasswordHashProvider.class, policy.getHashAlgorithm());
        if (hash == null) {
            return this.session.getProvider(PasswordHashProvider.class, "pbkdf2-sha256");
        } else {
            return hash;
        }
    }

    public PasswordCredentialModel createCredential(RealmModel realm,String password) {
        PasswordPolicy policy = realm.getPasswordPolicy();
        PasswordHashProvider hash = this.getHashProvider(policy);
        if (hash == null) {
            return null;
        } else {
            PasswordCredentialModel credentialModel = hash.encodedCredential(password, policy.getHashIterations());
            credentialModel.setCreatedDate(Time.currentTimeMillis());
            return credentialModel;
        }
    }




    // /auth/realms/buzz-sso/user-extend-api-credential/user-reset-pwd
    /**
     *  user reset password by raw password and new password
     * @param authorization from header, accessToken
     * @param userId        userId
     * @param oldPassword   raw password ,if encoded use decode,default no encode
     * @param newPassword   new password ,if encoded use decode,default no encode
     */
    @POST
    @NoCache
    @Path("user-reset-pwd")
    public void userPasswordReset(@HeaderParam("Authorization") String authorization,
                           @FormParam("userId") String userId,
                           @FormParam("oldPassword")String oldPassword,
                           @FormParam("newPassword")String newPassword){
        checkRealmAdmin();
        UserCredentialModel userCredentialModel = UserCredentialModel.password(oldPassword);
        UserProvider userProvider = session.getProvider(UserProvider.class);
        PasswordCredentialProvider passwordCredentialProvider = new PasswordCredentialProvider(session);
        UserModel user = userProvider.getUserById(realm,userId);
        if(session.userCredentialManager().isValid(realm,user,userCredentialModel)){
            PasswordCredentialModel newModel =  createCredential(realm,newPassword );
            passwordCredentialProvider.createCredential(realm,user,newModel);
        }else{
           throw new ForbiddenException("raw password is not correct");
        }
    }


    private void checkRealmAdmin() {
        if (auth == null) {
            throw new NotAuthorizedException("no auth or not logon");
        }
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

}
