package ru.rtln.common.security.keycloak.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;
import ru.rtln.common.model.ErrorModel;
import ru.rtln.common.model.SuccessModel;
import ru.rtln.common.security.model.AuthenticatedUserModel;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.SET_COOKIE;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

public class AuthenticationProviderFilter extends OncePerRequestFilter {
    private final RestTemplate authRestTemplate;
    private final String apiKeyHeaderName;
    private final String authSecretKeyValue;

    public AuthenticationProviderFilter(RestTemplate authRestTemplate, String apiKeyHeaderName, String authSecretKeyValue) {
        this.authRestTemplate = authRestTemplate;
        this.apiKeyHeaderName = apiKeyHeaderName;
        this.authSecretKeyValue = authSecretKeyValue;
    }

    @Override
    public void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        var cookies = getCookies(request);
        var accessToken = getTokenCookie(request, "access_token");
        var refreshToken = getTokenCookie(request, "refresh_token");
        if (cookies == null || accessToken == null && refreshToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            ResponseEntity<SuccessModel<TokenIntrospectModel>> refreshResponse = validateToken(cookies);
            var refreshResponseStatusCode = refreshResponse.getStatusCode();
            var refreshResponseBody = refreshResponse.getBody();

            if (refreshResponseStatusCode != OK || refreshResponseBody == null || refreshResponseBody.getData() == null) {
                filterChain.doFilter(request, response);
                return;
            }

            Optional.ofNullable(refreshResponse.getHeaders().get(SET_COOKIE))
                    .ifPresent(authCookies -> authCookies.forEach(cookie -> response.addHeader(SET_COOKIE, cookie)));

            var userModel = new AuthenticatedUserModel();

            if (refreshResponseBody.getData().getAttributes() == null) {
                filterChain.doFilter(request, response);
                return;
            }
            userModel.setId(refreshResponseBody.getData().getAttributes().userId());
            userModel.setCity(refreshResponseBody.getData().getAttributes().city());
            userModel.setPermissions(refreshResponseBody.getData().getAttributes().permissions());
            var authenticationToken = constructToken(userModel);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        } catch (Exception e) {
            logger.error(e);
            response.setStatus(SC_UNAUTHORIZED);
            response.setContentType(APPLICATION_JSON_VALUE);
            ErrorModel error = new ErrorModel(
                    SC_UNAUTHORIZED,
                    e.getClass().getSimpleName(),
                    "Exception occurred in authentication filter"
            );
            response.getWriter().write(new ObjectMapper().writeValueAsString(error));
            return;
        }
        filterChain.doFilter(request, response);
    }

    private Cookie[] getCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            return request.getCookies();
        }
        return generateCookiesFromHeader(request);
    }

    private Cookie getTokenCookie(HttpServletRequest request, String tokenName) {
        Cookie tokenCookie = WebUtils.getCookie(request, tokenName);
        if (tokenCookie != null) return tokenCookie;
        return generateCookieFromHeader(request.getHeader(AUTHORIZATION), tokenName);
    }

    private Cookie[] generateCookiesFromHeader(HttpServletRequest request) {
        String headerValue = request.getHeader(AUTHORIZATION);

        if (headerValue == null) return null;

        List<Cookie> authorizationCookies = new ArrayList<>(2);

        Cookie accessToken = generateCookieFromHeader(headerValue, "access_token");
        Cookie refreshToken = generateCookieFromHeader(headerValue, "refresh_token");
        if (accessToken != null) authorizationCookies.add(accessToken);
        if (refreshToken != null) authorizationCookies.add(refreshToken);

        return authorizationCookies.toArray(new Cookie[0]);
    }

    private Cookie generateCookieFromHeader(String headerValue, String tokenName) {
        if (headerValue == null || tokenName == null) return null;
        String token = extractToken(headerValue, tokenName);
        return token == null ? null : new Cookie(tokenName, token);
    }

    private String extractToken(String headerValue, String tokenName) {
        Pattern pattern = Pattern.compile(tokenName + "=([a-zA-Z0-9._-]+);", CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(headerValue);
        return matcher.find() ? matcher.group(1) : null;
    }

    private ResponseEntity<SuccessModel<TokenIntrospectModel>> validateToken(Cookie[] cookies) {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        Arrays.asList(cookies).forEach(cookie -> headers.add("Cookie", cookie.getName() + "=" + cookie.getValue()));
        headers.add(apiKeyHeaderName, authSecretKeyValue);

        var validateTokenRequest = new HttpEntity<>(null, headers);
        var typeReference = new ParameterizedTypeReference<SuccessModel<TokenIntrospectModel>>() {
        };
        return authRestTemplate.exchange("/api/auth/internal/refresh",
                POST,
                validateTokenRequest,
                typeReference
        );
    }

    private UsernamePasswordAuthenticationToken constructToken(AuthenticatedUserModel userModel) {
        List<SimpleGrantedAuthority> permissions = Optional.of(userModel.getPermissions())
                .orElseGet(ArrayList::new).stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
        return new UsernamePasswordAuthenticationToken(userModel, null, permissions);
    }
}