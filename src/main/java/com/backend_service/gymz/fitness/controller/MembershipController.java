package com.backend_service.gymz.fitness.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.backend_service.gymz.common.model.ResponseData;
import com.backend_service.gymz.fitness.dto.request.membership.MembershipCreateRequest;
import com.backend_service.gymz.fitness.dto.request.membership.MembershipUpdateRequest;
import com.backend_service.gymz.fitness.dto.response.membership.MembershipPageResponse;
import com.backend_service.gymz.fitness.dto.response.membership.MembershipResponse;
import com.backend_service.gymz.fitness.service.MembershipService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/v1/membership")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Membership Management")
public class MembershipController {

    private final MembershipService membershipService;

    @PostMapping
    @Operation(summary = "Create new membership")
    // Only owner and manager can create memberships
    @PreAuthorize("hasAuthority('MEMBERSHIP:CREATE:ALL')")
    public ResponseData<MembershipResponse> createMembership(@Valid @RequestBody MembershipCreateRequest request) {
        log.info("Received request to create membership: {}", request.getName());
        
        MembershipResponse response = membershipService.save(request);
        log.info("Successfully created membership with id: {}", response.getId());
        
        return new ResponseData<>(HttpStatus.CREATED.value(), "Membership created successfully", response);
    }

    // @GetMapping("/{id}")
    // @Operation(summary = "Get membership by ID")
    // // All roles can view membership details
    // @PreAuthorize("hasAuthority('MEMBERSHIP:READ:ALL')")
    // public ResponseData<MembershipResponse> getMembership(@PathVariable Long id) {
    //     log.info("Received request to get membership with id: {}", id);
        
    //     MembershipResponse response = membershipService.findById(id);
    //     log.info("Successfully retrieved membership: {}", response.getName());
        
    //     return new ResponseData<>(HttpStatus.OK.value(), "Membership retrieved successfully", response);
    // }

    @GetMapping
    @Operation(summary = "Get all memberships")
    // All roles can view the list of memberships
    // @PreAuthorize("hasAuthority('MEMBERSHIP:READ:ALL')")
    @PreAuthorize("hasRole('ROLE_OWNER')")

    public ResponseData<MembershipPageResponse> getAllMemberships(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "10") int size,
        @RequestParam(defaultValue = "id") String sortBy,
        @RequestParam(defaultValue = "ASC") String direction,
        @RequestParam(defaultValue = "false") boolean ignoreCase
    ) {
        log.info("Received request to get all memberships");
        
        MembershipPageResponse response = membershipService.findAll(page, size, sortBy, direction, ignoreCase);
        log.info("Successfully retrieved {} memberships");
        
        return new ResponseData<>(HttpStatus.OK.value(), "Memberships retrieved successfully", response);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update membership")
    // Only owner and manager can update memberships
    @PreAuthorize("hasAuthority('MEMBERSHIP:UPDATE:ALL')")
    public ResponseData<MembershipResponse> updateMembership(@PathVariable Long id, @Valid @RequestBody MembershipUpdateRequest request) {
        log.info("Received request to update membership with id: {}", id);
        
        request.setId(id);
        MembershipResponse response = membershipService.update(request);
        log.info("Successfully updated membership with id: {}", id);
        
        return new ResponseData<>(HttpStatus.OK.value(), "Membership updated successfully", response);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete membership by ID")
    // Only owner and manager can delete memberships
    @PreAuthorize("hasAuthority('MEMBERSHIP:DELETE:ALL')")
    public ResponseData<Void> deleteMembership(@PathVariable Long id) {
        log.info("Received request to delete membership with id: {}", id);
        
        membershipService.deleteById(id);
        log.info("Successfully deleted membership with id: {}", id);
        
        return new ResponseData<>(HttpStatus.OK.value(), "Membership deleted successfully");
    }
}
