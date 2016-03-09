package org.hspconsortium.platform.api.oauth2;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class ScopeAsStringAccessTokenConverter extends DefaultAccessTokenConverter {

    @Override
    @SuppressWarnings("unchecked")
    public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
        Map<String, ?> newMap = (Map<String, ?>)(ScopeAsStringAccessTokenConverter.convertScopeStringToCollection(map));
        return super.extractAuthentication(newMap);
    }

    @SuppressWarnings("unchecked")
    public static Map convertScopeStringToCollection(Map map) {
        Object scopeObj = map.get(SCOPE);
        if (scopeObj != null && scopeObj instanceof String) {
            Map newMap = new HashMap<>(map);
            String scopeStr = (String) scopeObj;
            Collection<String> scopeCollection = Arrays.asList(scopeStr.split(" "));
            newMap.put(SCOPE, scopeCollection);
            return newMap;
        } else {
            return map;
        }
    }
}
