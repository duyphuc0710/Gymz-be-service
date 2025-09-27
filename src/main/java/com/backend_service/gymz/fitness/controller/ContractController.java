package com.backend_service.gymz.fitness.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import com.backend_service.gymz.common.model.ResponseData;
import com.backend_service.gymz.fitness.dto.request.contract.ContractCreateRequest;
import com.backend_service.gymz.fitness.dto.response.contract.ContractPageResponse;
import com.backend_service.gymz.fitness.dto.response.contract.ContractResponse;
import com.backend_service.gymz.fitness.service.ContractService;
import com.backend_service.gymz.user.model.UserEntity;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/v1/contract")
@Tag(name = "Contract Controller")
@RequiredArgsConstructor
@Slf4j(topic = "CONTRACT-CONTROLLER")
public class ContractController {
    private final ContractService contractService;

    @PostMapping
    // @PreAuthorize("hasAuthority('CONTRACT:CREATE:ALL')")
    @PreAuthorize("hasRole('OWNER')")
    @Operation(summary = "Create new contract")
    public ResponseData<ContractResponse> createContract(@Valid @RequestBody ContractCreateRequest req) {
        log.info("Creating contract: {}", req);
        ContractResponse data = contractService.save(req);
        return new ResponseData<>(HttpStatus.CREATED.value(), "Contract created successfully", data);
    }

    @GetMapping
    @Operation(summary = "Get list of all contracts")
    @PreAuthorize("hasAuthority('CONTRACT:READ:ALL')")
    public ResponseData<ContractPageResponse> getAllContracts(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "10") int size,
        @RequestParam(defaultValue = "id") String sortBy,
        @RequestParam(defaultValue = "ASC") String direction,
        @RequestParam(defaultValue = "false") boolean ignoreCase) {

        log.info("Fetching all contracts");
        ContractPageResponse data = contractService.findAll(page, size, sortBy, direction, ignoreCase);
        return new ResponseData<>(HttpStatus.OK.value(), "Contracts retrieved successfully", data);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('CONTRACT:READ:ALL')")
    @Operation(summary = "Get contract by ID")
    public ResponseData<ContractResponse> getContractById(@PathVariable Long id) {
        log.info("Fetching contract by ID: {}", id);
        ContractResponse data = contractService.findById(id);
        return new ResponseData<>(HttpStatus.OK.value(), "Contract retrieved successfully", data);
    }

    @GetMapping("/me")
    @Operation(summary = "Get contracts of logged-in user")
    @PreAuthorize("hasAuthority('CONTRACT:READ:SELF')")
    public ResponseData<?> getMyContracts(
            @AuthenticationPrincipal UserEntity user) {
                
        Long userId = user.getId();
        log.info("Fetching contracts for logged-in user: {}", userId);
        var data = contractService.findContractsByUserId(userId);
        return new ResponseData<>(HttpStatus.OK.value(), "Contracts retrieved successfully", data);
    }


    @PutMapping("/{id}")
    @Operation(summary = "Update contract by ID")
    @PreAuthorize("hasAuthority('CONTRACT:UPDATE:ALL')")
    // @PreAuthorize("hasAuthority('CONTRACT:UPDATE:ALL') or hasAuthority('CONTRACT:UPDATE:SELF')")
    public ResponseData<ContractResponse> updateContract(
        @PathVariable Long id,
        @Valid @RequestBody ContractCreateRequest req) {

        log.info("Updating contract with ID: {}", id);
        ContractResponse data = contractService.update(id, req);
        return new ResponseData<>(HttpStatus.OK.value(), "Contract updated successfully", data);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete contract by ID")
    @PreAuthorize("hasAuthority('CONTRACT:DELETE:ALL')")
    public ResponseData<Void> deleteContract(@PathVariable Long id) {
        log.info("Deleting contract with ID: {}", id);
        contractService.deleteById(id);
        return new ResponseData<>(HttpStatus.NO_CONTENT.value(), "Contract deleted successfully");
    }
}
