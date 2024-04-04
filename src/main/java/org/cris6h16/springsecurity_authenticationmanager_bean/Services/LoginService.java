package org.cris6h16.springsecurity_authenticationmanager_bean.Services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class LoginService {
    private final AuthenticationManager authenticationManager;

    public LoginService(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    public ResponseEntity<LoginData> login(LoginData loginData) {
        try {

        Authentication authenticationRequest =
                UsernamePasswordAuthenticationToken.unauthenticated(loginData.username(), loginData.password());
        Authentication authenticationResponse =
                this.authenticationManager.authenticate(authenticationRequest);

//            System.out.println(authenticationResponse.getCredentials());
//        authenticationResponse.getPrincipal();
//        authenticationResponse.getAuthorities();
//        authenticationResponse.getDetails();
//        authenticationResponse.getCredentials();
//        authenticationResponse.getName();

        } catch (BadCredentialsException e) { // --> RuntimeException
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(loginData);
    }




    public ResponseEntity<?> testResponse(){
        return ResponseEntity.ok("Hello World");
    }
    public record LoginData(String username, String password) {
    }
}
