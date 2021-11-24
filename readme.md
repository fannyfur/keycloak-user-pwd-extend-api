# keycloak-user-pwd-extend-api

Keycloak 用户修改密码,使用原始密码和新密码

Keycloak 15.0.1 测试通过

```bash
# build from source
mvn clean package

# copy jar to ${keycloak}/standalone/deployments
```

# request url：/auth/realms/{your realm}/user-extend-api-credential/user-reset-pwd;method:post


```
     // import maven 
    <dependency>
      <groupId>org.keycloak</groupId>
      <artifactId>keycloak-model-infinispan</artifactId>
      <version>${version.keycloak}</version>
      <scope>compile</scope>
    </dependency>
    
    manifestEntries add dependencies org.keycloak.keycloak-model-infinispan
    
     //how to use cache
     InfinispanConnectionProvider provider = session.getProvider(InfinispanConnectionProvider.class);
     //cache level for realm 
     provider.getCache(InfinispanConnectionProvider.REALM_CACHE_NAME).put("","");
     //cache level for user
     provider.getCache(InfinispanConnectionProvider.USER_CACHE_NAME).put("","");
     //cache level for keys
     provider.getCache(InfinispanConnectionProvider.KEYS_CACHE_NAME).put("","");
     //cache level for session
     provider.getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME).put("","");
     //remote cache : 
     provider.getRemoteCache()
```