package com.backend_service.gymz.user.service.impl;

import java.util.List;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend_service.gymz.common.exception.ResourceNotFoundException;
import com.backend_service.gymz.user.common.enums.user.UserStatus;
import com.backend_service.gymz.user.dto.Request.user.AddressRequest;
import com.backend_service.gymz.user.dto.Request.user.UserCreateRequest;
import com.backend_service.gymz.user.dto.Request.user.UserPasswordRequest;
import com.backend_service.gymz.user.dto.Request.user.UserUpdateRequest;
import com.backend_service.gymz.user.dto.Response.user.UserPageResponse;
import com.backend_service.gymz.user.dto.Response.user.UserResponse;
import com.backend_service.gymz.user.model.AddressEntity;
import com.backend_service.gymz.user.model.Role;
import com.backend_service.gymz.user.model.UserEntity;
import com.backend_service.gymz.user.model.UserHasRole;
import com.backend_service.gymz.user.repository.RoleRepository;
import com.backend_service.gymz.user.repository.UserRepository;
import com.backend_service.gymz.user.service.UserService;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = "USER-SERVICE")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public UserResponse save(UserCreateRequest req) {
        log.info("Saving user: {}", req);

        UserEntity user = buildUserEntity(req);
        log.info("Built UserEntity: {}", user);

        addAddressesToUser(user, req.getAddresses());
        log.info("Added addresses to user: {}", user.getAddresses());

        if (req.getRoleIds() != null && !req.getRoleIds().isEmpty()) {
            assignRolesToUser(user, req.getRoleIds());
            log.info("Assigned roles to user: {}", req.getRoleIds());
        }

        UserEntity savedUser = userRepository.save(user);
        log.info("Successfully created user with id: {}", savedUser.getId());

        return mapToUserResponse(savedUser);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public UserResponse update(UserUpdateRequest req) {
        log.info("Updating user with id: {}", req.getId());

        UserEntity user = getUserEntity(req.getId());
        updateUserEntity(user, req);

        if (req.getAddresses() != null) {
            user.getAddresses().clear();
            addAddressesToUser(user, req.getAddresses());
            log.info("Updated addresses for user: {}", user.getAddresses());
        }

        if (req.getRoleIds() != null) {
            user.getUserRoles().clear();
            assignRolesToUser(user, req.getRoleIds());
            log.info("Updated roles for user: {}", req.getRoleIds());
        }

        UserEntity updatedUser = userRepository.save(user);
        log.info("Successfully updated user with id: {}", updatedUser.getId());

        return mapToUserResponse(updatedUser);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public UserResponse changePwd(UserPasswordRequest req) {
        log.info("Changing password for user with id: {}", req.getId());

        UserEntity user = getUserEntity(req.getId());
        if (req.getPassword().equals(req.getConfirmPassword())) {
            user.setPassword(passwordEncoder.encode(req.getPassword()));
        }

        UserEntity updatedUser = userRepository.save(user);
        log.info("Successfully changed password for user with id: {}", updatedUser.getId());

        return mapToUserResponse(updatedUser);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public UserResponse deleteById(Long id) {
        log.info("Deleting user with id: {}", id);

        UserEntity user = getUserEntity(id);
        user.setStatus(UserStatus.INACTIVE);

        UserEntity deletedUser = userRepository.save(user);
        log.info("Successfully deleted user with id: {}", id);

        return mapToUserResponse(deletedUser);
    }

    @Override
    public UserPageResponse findAllUsers(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        log.info("Getting all users with paging");

        Pageable pageable = buildPageable(page, size, sortBy, direction, ignoreCase);
        Page<UserEntity> userEntities = userRepository.findAll(pageable);

        List<UserResponse> userList = userEntities.getContent().stream()
            .map(this::mapToUserResponse)
            .toList();

        return buildUserPageResponse(userEntities, userList);
    }

    @Override
    public UserResponse findById(Long id) {
        log.info("Finding user by id: {}", id);

        UserEntity userEntity = getUserEntity(id);
        UserResponse response = mapToUserResponse(userEntity);
        log.info("Successfully found user with id: {}", response.getId());
        
        return response;
    }

    // Helper methods
    private UserEntity getUserEntity(Long id) {
        return userRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));
    }

    private UserEntity buildUserEntity(UserCreateRequest req) {
        UserEntity user = new UserEntity();
        user.setFirstName(req.getFirstName());
        user.setLastName(req.getLastName());
        user.setGender(req.getGender());
        user.setDateOfBirth(req.getDateOfBirth());
        user.setPhoneNumber(req.getPhoneNumber());
        user.setUsername(req.getUsername());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setEmail(req.getEmail());
        user.setUserType(req.getUserType());
        user.setStatus(UserStatus.ACTIVE);
        return user;
    }

    private void updateUserEntity(UserEntity user, UserUpdateRequest req) {
        user.setFirstName(req.getFirstName());
        user.setLastName(req.getLastName());
        user.setGender(req.getGender());
        user.setDateOfBirth(req.getDateOfBirth());
        user.setPhoneNumber(req.getPhoneNumber());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setEmail(req.getEmail());
    }

    private void addAddressesToUser(UserEntity user, List<AddressRequest> addressRequests) {
        if (addressRequests == null) return;
        for (AddressRequest a : addressRequests) {
            AddressEntity address = new AddressEntity();
            address.setStreet(a.getStreet());
            address.setCity(a.getCity());
            address.setAddressType(a.getAddressType());
            user.saveAddress(address);
        }
    }

    private void assignRolesToUser(UserEntity user, List<Integer> roleIds) {
        List<Role> roles = roleRepository.findAllById(roleIds);
        for (Role role : roles) {
            UserHasRole userHasRole = new UserHasRole();
            userHasRole.setUser(user);
            userHasRole.setRole(role);
            user.getUserRoles().add(userHasRole);
        }
    }

    private UserResponse mapToUserResponse(UserEntity entity) {
        return UserResponse.builder()
            .id(entity.getId())
            .firstName(entity.getFirstName())
            .lastName(entity.getLastName())
            .gender(entity.getGender())
            .dateOfBirth(entity.getDateOfBirth())
            .username(entity.getUsername())
            .phoneNumber(entity.getPhoneNumber())
            .email(entity.getEmail())
            .build();
    }

    private Pageable buildPageable(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        Sort.Order order = new Sort.Order(Sort.Direction.fromString(direction), sortBy);
        if (ignoreCase) order = order.ignoreCase();
        Sort sort = Sort.by(order);
        return PageRequest.of(page, size, sort);
    }

    private UserPageResponse buildUserPageResponse(Page<UserEntity> userEntities, List<UserResponse> userList) {
        UserPageResponse response = new UserPageResponse();
        response.setPageNumber(userEntities.getNumber());
        response.setPageSize(userEntities.getSize());
        response.setTotalElements(userEntities.getTotalElements());
        response.setTotalPages(userEntities.getTotalPages());
        response.setUsers(userList);
        return response;
    }
}
