package org.keycloak.social.vkontakte;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

public class VKontakteUserAttributeMapper extends AbstractJsonUserAttributeMapper {

  private static final String MAPPER_ID = "vkontakte-user-attribute-mapper";
  private static final String[] PROVIDER = {VKontakteIdentityProviderFactory.PROVIDER_ID};

  public String[] getCompatibleProviders() {
    return PROVIDER;
  }

  public String getId() {
    return MAPPER_ID;
  }

}
