package org.keycloak.social.vkontakte;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

public class VKontakteIdentityProvider extends
    AbstractOAuth2IdentityProvider<VKontakteIdentityProviderConfig> implements
    SocialIdentityProvider<VKontakteIdentityProviderConfig> {

  public static final String API_VERSION = "5.92";
  public static final String API_VERSION_PARAM = "?v=" + API_VERSION;

  public VKontakteIdentityProvider(KeycloakSession session,
      VKontakteIdentityProviderConfig config) {
    super(session, config);
    config.setAuthorizationUrl("https://oauth.vk.com/authorize" + API_VERSION_PARAM);
    config.setTokenUrl("https://oauth.vk.com/access_token" + API_VERSION_PARAM);
    config.setUserInfoUrl("https://api.vk.com/method/users.get" + API_VERSION_PARAM);
  }

  @Override
  protected String getDefaultScopes() {
    return "email offline";
  }

  @Override
  protected boolean supportsExternalExchange() {
    return true;
  }

  @Override
  protected String getProfileEndpointForValidation(EventBuilder event) {
    return getConfig().getUserInfoUrl();
  }

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event,
      JsonNode profile) {
    JsonNode node = profile.get("response").get(0);
    BrokeredIdentityContext user = new BrokeredIdentityContext(
        getJsonProperty(node, "id"));

    user.setUsername(getJsonProperty(node, "screen_name"));
    user.setFirstName(getJsonProperty(node, "first_name"));
    user.setLastName(getJsonProperty(node, "last_name"));
    user.setIdpConfig(getConfig());
    user.setIdp(this);

    AbstractJsonUserAttributeMapper
        .storeUserProfileForMapper(user, node, getConfig().getAlias());
    return user;
  }

  @Override
  protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
    try {
      JsonNode profile = SimpleHttp.doGet(getConfig().getUserInfoUrl(), session)
          .param("v", API_VERSION)
          .param("fields", "screen_name")
          .param("access_token", accessToken).asJson();

      return extractIdentityFromProfile(null, profile);
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not obtain user profile from paypal.", e);
    }
  }

  @Override
  protected SimpleHttp buildUserInfoRequest(String subjectToken, String userInfoUrl) {
    return SimpleHttp.doGet(userInfoUrl, session).param("v", API_VERSION)
        .header("Authorization", "Bearer " + subjectToken);
  }

  @Override
  public BrokeredIdentityContext getFederatedIdentity(String response) {
    String accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());

    if (accessToken == null) {
      throw new IdentityBrokerException(
          "No access token available in OAuth server response: " + response);
    }

    BrokeredIdentityContext context = doGetFederatedIdentity(accessToken);
    JsonNode node = null;
    try {
      node = mapper.readTree(response);
      //context.setBrokerUserId(getJsonProperty(node, "user_id"));
      context.setEmail(getJsonProperty(node, "email"));
    } catch (IOException e) {
      throw new IdentityBrokerException(
          "Could not get user_id or  e-mail address from response: " + response);
    }
    context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
    return context;
  }
}
