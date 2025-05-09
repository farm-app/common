package ru.rtln.common.security.secret.key;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import ru.rtln.common.model.ErrorModel;

import java.io.IOException;

import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

public class SecretKeyAuthenticationFilter extends GenericFilterBean {
    private final String apiKeyHeaderName;
    private final String serviceSecretKeyValue;

    public SecretKeyAuthenticationFilter(String apiKeyHeaderName,
                                         String serviceSecretKeyValue) {
        this.apiKeyHeaderName = apiKeyHeaderName;
        this.serviceSecretKeyValue = serviceSecretKeyValue;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        try {
            String apiKey = ((HttpServletRequest) request).getHeader(apiKeyHeaderName);
            if (apiKey == null || !apiKey.equals(serviceSecretKeyValue)) {
                filterChain.doFilter(request, response);
                return;
            }
            Authentication authentication = new ApiKeyAuthenticationToken(apiKey, AuthorityUtils.NO_AUTHORITIES);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            e.printStackTrace();
            ((HttpServletResponse) response).setStatus(SC_UNAUTHORIZED);
            response.setContentType(APPLICATION_JSON_VALUE);
            ErrorModel error = new ErrorModel(SC_UNAUTHORIZED, e.getClass().getSimpleName(), "Exception occurred in secret key authentication filter");
            response.getWriter().write(new ObjectMapper().writeValueAsString(error));
            return;
        }
        filterChain.doFilter(request, response);
    }
}
