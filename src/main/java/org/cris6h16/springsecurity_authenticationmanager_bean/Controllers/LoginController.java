package org.cris6h16.springsecurity_authenticationmanager_bean.Controllers;

import org.cris6h16.springsecurity_authenticationmanager_bean.Services.LoginService;
import org.cris6h16.springsecurity_authenticationmanager_bean.Services.LoginService.LoginData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {
//    @Autowired // difficult to mock, more limited control, etc
    LoginService loginService;

    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @PostMapping("/login")
    @ResponseBody
    public ResponseEntity<?> login(@RequestBody LoginData loginRequest) {
       return loginService.login(loginRequest);
//       return loginService.testResponse();
    }


}
