package com.jo.trainrecallbackend.controllers;

import com.jo.trainrecallbackend.payload.response.MessageResponse;
import com.jo.trainrecallbackend.repositories.UserRepository;
import com.jo.trainrecallbackend.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin("https://test.herokuapp.com")
@RestController
@RequestMapping("/api/authority-access")
public class AuthorityAccessController {
    @Autowired
    UserRepository userRepository;

    @CrossOrigin("*")
    @DeleteMapping("/delete")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser() {

        UserDetailsImpl userDetails =
                (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Long userId = userDetails.getId();

        userRepository.deleteById(userId);

        return ResponseEntity.ok(new MessageResponse("User deleted successfully."));
    }
}
