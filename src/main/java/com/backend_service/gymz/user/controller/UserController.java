package com.backend_service.gymz.user.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.backend_service.gymz.common.model.ResponseData;
import com.backend_service.gymz.user.dto.Request.user.UserCreateRequest;
import com.backend_service.gymz.user.dto.Request.user.UserPasswordRequest;
import com.backend_service.gymz.user.dto.Request.user.UserUpdateRequest;
import com.backend_service.gymz.user.dto.Response.user.UserPageResponse;
import com.backend_service.gymz.user.dto.Response.user.UserResponse;
import com.backend_service.gymz.user.service.UserService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/v1/user")
@Tag(name = "User Controller")
@Slf4j(topic = "USER-CONTROLLER")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @Operation(summary = "Create user")
    @PostMapping
    @PreAuthorize("hasAuthority('USER:CREATE:ALL') or hasAuthority('USER:CREATE:SELF')")
    public ResponseData<Object> createUser(@Valid @RequestBody UserCreateRequest req) {
        log.info("Creating user", req);

        Object data = userService.save(req);

        return new ResponseData<>(HttpStatus.OK.value(), "create user", data);

    }

    @Operation(summary = "Get user list")
    @GetMapping("/list")
    @PreAuthorize("hasAuthority('USER:READ:ALL')")
    public ResponseData<UserPageResponse> getList(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "10") int size,
        @RequestParam(defaultValue = "id") String sortBy,
        @RequestParam(defaultValue = "ASC") String direction,
        @RequestParam(defaultValue = "false") boolean ignoreCase){

        log.info("Get user list");

        UserPageResponse data = userService.findAllUsers(page, size, sortBy, direction, ignoreCase);
        return new ResponseData<>(HttpStatus.OK.value(), "user list", data);
    }

    @Operation(summary = "Get user by Id")
    @GetMapping("/{userID}")
    @PreAuthorize("hasAuthority('USER:READ:SELF') or hasAuthority('USER:READ:ALL')")
    public ResponseData<UserResponse> getUserById(@PathVariable Long userID) {

        log.info("Get user by id :{id}", userID);

        UserResponse data = userService.findById(userID);

        return new ResponseData<>(HttpStatus.OK.value(), "user list", data);
    }

    @Operation(summary = "Update user")
    @PutMapping
    @PreAuthorize("hasAuthority('USER:UPDATE:SELF') or hasAuthority('USER:UPDATE:ALL')")
    public ResponseData<UserResponse> updateUser(@RequestBody UserUpdateRequest request) {

        log.info("Updating user with id: {}", request.getId());
        UserResponse data = userService.update(request);

        return new ResponseData<>(HttpStatus.OK.value(), "User updated successfully", data);
    }

    @Operation(summary = "Delete user")
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasAuthority('USER:DELETE:ALL') or hasRole('OWNER')")
    public ResponseData<UserResponse> deleteUser(@PathVariable Long userId) {
        log.info("Deleting user with id: {}", userId);

        UserResponse data = userService.deleteById(userId);

        return new ResponseData<>(HttpStatus.OK.value(), "User deleted successfully", data);
    }

    @Operation(summary = "Change Password", description = "API change password for user to database")
    @PatchMapping("/change-pwd")
    @PreAuthorize("hasAuthority('USER:UPDATE:SELF') or hasAuthority('USER:UPDATE:ALL')")
    public ResponseData<UserResponse> changePassword(@RequestBody @Valid UserPasswordRequest request) {
        
        log.info("Changing password for user with id: {}", request.getId());

        UserResponse data = userService.changePwd(request);

        return new ResponseData<>(HttpStatus.OK.value(), "Password updated successfully", data);
    }

}
