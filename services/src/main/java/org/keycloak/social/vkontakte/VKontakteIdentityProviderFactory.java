package org.keycloak.social.vkontakte;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class VKontakteIdentityProviderFactory extends
    AbstractIdentityProviderFactory<VKontakteIdentityProvider> implements
    SocialIdentityProviderFactory<VKontakteIdentityProvider> {


  static final String PROVIDER_ID = "vkontakte";
  private static final String PROVIDER_NAME = "VKontakte";

  public String getName() {
    return PROVIDER_NAME;
  }

  public VKontakteIdentityProvider create(KeycloakSession keycloakSession,
      IdentityProviderModel identityProviderModel) {
    return new VKontakteIdentityProvider(keycloakSession,
        new VKontakteIdentityProviderConfig(identityProviderModel));
  }

  public String getId() {
    return PROVIDER_ID;
  }
}
