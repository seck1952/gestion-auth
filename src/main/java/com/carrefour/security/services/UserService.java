package com.carrefour.security.services;

import com.carrefour.security.entity.User;
import com.carrefour.security.entity.auth.ChangePasswordRequest;
import com.carrefour.security.repository.UserRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void changePassword(ChangePasswordRequest changePasswordRequest, Principal connectUser){
       var user = (User) ((UsernamePasswordAuthenticationToken) connectUser).getPrincipal();

       // check if current password is correct
        if (!passwordEncoder.matches(changePasswordRequest.getCurrentPassword(), user.getPassword())){
            throw new IllegalStateException("Wrong password");
        }

        // check if two new password are the same
        if (changePasswordRequest.getNewPassword().equals(changePasswordRequest.getConfirmationPassword())) {
            throw new IllegalStateException("password are not the same");
        }

        // update password

        user.setPassword(passwordEncoder.encode(changePasswordRequest.getNewPassword()));

        userRepository.save(user);


    }
}
