package org.hspconsortium.platform.api.oauth2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;

@Configuration
@EnableResourceServer
public class OAuth2ResourceConfig extends ResourceServerConfigurerAdapter {

    private static final String SECURITY_MODE_OPEN = "open";

    private static final String SECURITY_MODE_SECURED = "secured";

    @Value("${hspc.platform.api.security.mode}")
    private String securityMode;

    @Bean
    public AccessTokenConverter accessTokenConverter() {
        return new ScopeAsStringAccessTokenConverter();
    }

    @Bean
    public RemoteTokenServices remoteTokenServices(
            final @Value("${hspc.platform.authorization.tokenCheckUrl}") String tokenCheckUrl,
            final @Value("${hspc.platform.api.oauth2.clientId}") String clientId,
            final @Value("${hspc.platform.api.oauth2.clientSecret}") String clientSecret) {
        final RemoteTokenServices remoteTokenServices = new RemoteTokenServices();
        remoteTokenServices.setCheckTokenEndpointUrl(tokenCheckUrl);
        remoteTokenServices.setClientId(clientId);
        remoteTokenServices.setClientSecret(clientSecret);
        remoteTokenServices.setAccessTokenConverter(accessTokenConverter());
        return remoteTokenServices;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public CorsFilter corsFilter() {
        return new CorsFilter();
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        switch (securityMode) {
            case (SECURITY_MODE_OPEN):
                http
                        .addFilterBefore(corsFilter(), ChannelProcessingFilter.class)
                        .authorizeRequests()
                        .anyRequest().permitAll();
                break;
            case (SECURITY_MODE_SECURED):
                http
                        .addFilterBefore(corsFilter(), ChannelProcessingFilter.class)
                        .authorizeRequests()
                        .antMatchers(
                                "/", "/health").permitAll()
                        .requestMatchers(
                                // conformance statement
                                new RegexRequestMatcher("\\/data\\/metadata", "GET"),
                                // SMART endpoints
                                new RegexRequestMatcher("\\/data\\/_services\\/smart\\/.*", "GET"),
                                new RegexRequestMatcher("\\/data\\/_services\\/smart\\/.*", "POST"),
                                // terminology proxy
                                new RegexRequestMatcher("\\/terminology\\/.*", "GET"),
                                // federated query (used for a HIMMS demo)
                                new RegexRequestMatcher("\\/federated\\/.*", "GET")
                        ).permitAll()
                        .requestMatchers(
                                // multitenant conformance statement
                                // for example, /team1/data/metadata
                                new RegexRequestMatcher("\\/\\w+\\/data\\/metadata", "GET"),
                                // multitenant SMART endpoints
                                // for example, /team1/data/_services/smart/Launch
                                new RegexRequestMatcher("\\/\\w+\\/data\\/_services\\/smart\\/.*", "GET"),
                                new RegexRequestMatcher("\\/\\w+\\/data\\/_services\\/smart\\/.*", "POST")
                        ).permitAll()
                        // This level of security says that any other requests (all requests for FHIR resources)
                        // must be authenticated.  It does not determine if the user has access to the specific
                        // data according to scope and user role. That more granular level of provisioning should
                        // be handled by an interceptor
                        .anyRequest().authenticated();
                break;
            default:
                throw new RuntimeException("Security mode must be either open or secured");
        }
    }
}