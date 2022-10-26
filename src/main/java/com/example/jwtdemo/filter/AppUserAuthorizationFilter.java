package com.example.jwtdemo.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.*;
import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.*;

@Slf4j
public class AppUserAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // check if this is not login path
        if(request.getServletPath().equals("/api/login")){
            filterChain.doFilter(request,response);
        }else {/* else : check if this has an authorization and then set the user as the logged*/

            String authorizationHeader=request.getHeader(AUTHORIZATION);
            // Token is valid
            if(authorizationHeader !=null && authorizationHeader.startsWith("Bearer ")){
                try {
                    // get token
                    String token=authorizationHeader.substring(7);
                    // verify the token
                    Algorithm algorithm=Algorithm.HMAC256("jwtdemo".getBytes());
                    // create the verifier
                    JWTVerifier verifier= JWT.require(algorithm).build();
                    // decode the token, conversion the username, roles
                    DecodedJWT decodedJWT=verifier.verify(token);
                    String username=decodedJWT.getSubject();
                    String[] roles=decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<SimpleGrantedAuthority> authorities=new ArrayList<>();
                    stream(roles).forEach(
                            role->{
                                authorities.add(new SimpleGrantedAuthority(role));
                            });
                    UsernamePasswordAuthenticationToken authenticationToken=
                            new UsernamePasswordAuthenticationToken(username,null,authorities);
                    // Tell the spring security about username, roles
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    // let the request continue course
                    filterChain.doFilter(request,response);
                }catch (Exception e){
                    log.error("Error logging in:{}", e.getMessage());
                    response.setHeader("error: ",e.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    //response.sendError(FORBIDDEN.value());
                    Map<String, String> error=new HashMap<>();
                    error.put("error_message",e.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(),error);
                }

            }else {
                filterChain.doFilter(request,response);
            }
        }

    }

}
