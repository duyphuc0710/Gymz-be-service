package com.backend_service.gymz.fitness.service.impl;

import java.math.BigDecimal;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend_service.gymz.common.exception.BusinessException;
import com.backend_service.gymz.common.exception.ResourceNotFoundException;
import com.backend_service.gymz.fitness.dto.request.contract.ContractCreateRequest;
import com.backend_service.gymz.fitness.dto.response.contract.ContractPageResponse;
import com.backend_service.gymz.fitness.dto.response.contract.ContractResponse;
import com.backend_service.gymz.fitness.model.ContractEntity;
import com.backend_service.gymz.fitness.repository.ContractRepository;
import com.backend_service.gymz.fitness.service.ContractService;
import com.backend_service.gymz.user.model.UserEntity;
import com.backend_service.gymz.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = "CONTRACT-SERVICE")
@RequiredArgsConstructor
@Transactional
public class ContractServiceImpl implements ContractService {
    private final ContractRepository contractRepository;
    private final UserRepository userRepository;


    @Override
    public ContractResponse save(ContractCreateRequest request) {
        log.info("Creating new contract with id: {}", request);
       
        UserEntity customer = userRepository.findById(request.getCustomer())
            .orElseThrow(() -> {
                log.error("Customer not found with id: {}", request.getCustomer());
                return new ResourceNotFoundException("Customer not found");
            });
        log.debug("Found customer: {} with id: {}", customer.getUsername(), customer.getId());
        

        UserEntity pt = userRepository.findById(request.getPt())
            .orElseThrow(() -> {
                log.error("PT not found with id: {}", request.getPt());
                return new ResourceNotFoundException("PT not found");
            });
        log.debug("Found customer: {} with id: {}", customer.getUsername(), customer.getId());

        ContractEntity contract = new ContractEntity();
        contract.setName(request.getName());
        contract.setCustomer(customer);
        contract.setPt(pt);
        contract.setDuration(request.getDuration());
        contract.setStartDate(new Date());
        Calendar cal = Calendar.getInstance();
        cal.setTime(contract.getStartDate());
        cal.add(Calendar.MONTH, contract.getDuration()); 
        contract.setEndDate(cal.getTime());

        contract.setMoney(request.getMoney() != null ? request.getMoney() : BigDecimal.ZERO);
        
        ContractEntity savedContract = contractRepository.save(contract);
        log.info("Successfully created contract with id: {}", savedContract.getId());
        return convertToResponse(savedContract);
    }

    @Override
    public ContractResponse findById(Long id) {
        log.info("Finding contract by id: {}", id);
        ContractEntity contract = getContractEntity(id);

        ContractResponse response = convertToResponse(contract);
        log.info("Successfully found contract: {}", response.getName());
        return response;
    }

    @Override
    public List<ContractResponse> findContractsByUserId(Long userId) {
        log.info("Finding contracts for userId: {}", userId);
        List<ContractEntity> contracts = contractRepository.findByCustomer_IdOrPt_Id(userId, userId);
        return contracts.stream()
                .map(this::convertToResponse)
                .toList();
    }

    @Override
    public ContractPageResponse findAll(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        log.info("Getting all contracts");
        Pageable pageable = buildPageable(page, size, sortBy, direction, ignoreCase);
        Page<ContractEntity> contractPage = contractRepository.findAll(pageable);

        List<ContractResponse> contractResponses = contractPage.getContent().stream()
            .map(this::convertToResponse)
            .toList();

        ContractPageResponse response = new ContractPageResponse();
        response.setPageNumber(contractPage.getNumber());
        response.setPageSize(contractPage.getSize());
        response.setTotalElements(contractPage.getTotalElements());
        response.setTotalPages(contractPage.getTotalPages());
        response.setContracts(contractResponses);

        log.info("Successfully retrieved {} contracts", contractResponses.size());
        return buildContractPageResponse(contractPage, contractResponses);
    }

 

    @Override
    public ContractResponse update(Long id, ContractCreateRequest request) {
        log.info("Updating contract with id: {}", id);
        ContractEntity contract = getContractEntity(id);
        contract.setName(request.getName());
        contract.setCustomer(userRepository.findById(request.getCustomer())
            .orElseThrow(() -> new ResourceNotFoundException("Customer not found")));
        contract.setPt(userRepository.findById(request.getPt())
            .orElseThrow(() -> new ResourceNotFoundException("PT not found")));
        contract.setDuration(request.getDuration());
        contract.setStartDate(new Date());
        Calendar cal = Calendar.getInstance();
        cal.setTime(contract.getStartDate());
        cal.add(Calendar.MONTH, contract.getDuration());
        contract.setEndDate(cal.getTime());
        contract.setMoney(request.getMoney() != null ? request.getMoney() : BigDecimal.ZERO);
        ContractEntity updatedContract = contractRepository.save(contract);
        log.info("Successfully updated contract with id: {}", updatedContract.getId());
        return convertToResponse(updatedContract);
    }

    @Override
    public void deleteById(Long id) {
        log.info("Deleting contract with id: {}", id);
        ContractEntity contract = getContractEntity(id);
        contractRepository.delete(contract);
        log.info("Successfully deleted contract with id: {}", id);
    }

    @Override
    public boolean existsByName(String name) {
        log.info("Checking if contract exists by name: {}", name);
        return contractRepository.existsByName(name);
    }

    @Override
    public boolean existsByNameAndIdNot(String name, Long id) {
        log.info("Checking if contract exists by name: {} and id not: {}", name, id);
        return contractRepository.existsByNameAndIdNot(name, id);
    }

    // Method helper
    private ContractResponse convertToResponse(ContractEntity contract) {
        ContractResponse response = new ContractResponse();
        response.setName(contract.getName());
        response.setCustomer(contract.getCustomer().getId());
        response.setPt(contract.getPt().getId());
        response.setStartDate(contract.getStartDate());
        response.setDuration(contract.getDuration());
        response.setEndDate(contract.getEndDate());
        response.setMoney(contract.getMoney());

        return response;
    }

    private ContractEntity getContractEntity(Long id) {
        return contractRepository.findById(id)
            .orElseThrow(() -> new BusinessException("Contract not found with ID: " + id));
    }

    private Pageable buildPageable(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        Sort.Order order = new Sort.Order(Sort.Direction.fromString(direction), sortBy);
        if (ignoreCase) order = order.ignoreCase();
        Sort sort = Sort.by(order);
        return PageRequest.of(page, size, sort);
    }

    private ContractPageResponse buildContractPageResponse(Page<ContractEntity> contractPage,
        List<ContractResponse> contractResponses) {
        ContractPageResponse response = new ContractPageResponse();
        response.setPageNumber(contractPage.getNumber());
        response.setPageSize(contractPage.getSize());
        response.setTotalElements(contractPage.getTotalElements());
        response.setTotalPages(contractPage.getTotalPages());
        response.setContracts(contractResponses);
        return response;
    }

}
