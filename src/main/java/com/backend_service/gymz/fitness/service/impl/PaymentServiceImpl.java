package com.backend_service.gymz.fitness.service.impl;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.backend_service.gymz.common.exception.ResourceNotFoundException;
import com.backend_service.gymz.fitness.common.enums.payment.PaymentStatus;
import com.backend_service.gymz.fitness.dto.request.payment.PaymentCreateRequest;
import com.backend_service.gymz.fitness.dto.request.payment.PaymentUpdateRequest;
import com.backend_service.gymz.fitness.dto.response.payment.PaymentPageResponse;
import com.backend_service.gymz.fitness.dto.response.payment.PaymentResponse;
import com.backend_service.gymz.fitness.model.ContractEntity;
import com.backend_service.gymz.fitness.model.MembershipRecord;
import com.backend_service.gymz.fitness.model.PaymentEntity;
import com.backend_service.gymz.fitness.repository.ContractRepository;
import com.backend_service.gymz.fitness.repository.MembershipRecordRepository;
import com.backend_service.gymz.fitness.repository.PaymentRepository;
import com.backend_service.gymz.fitness.service.PaymentService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = "PAYMENT-SERVICE")
@RequiredArgsConstructor
public class PaymentServiceImpl implements PaymentService {
    private final PaymentRepository paymentRepository;
    private final MembershipRecordRepository membershipRecordRepository;
    private final ContractRepository contractRepository;

    @Override
    public PaymentResponse save(PaymentCreateRequest request) {
        log.info("Creating new payment with request: {}", request);

        if ((request.getMembershipId() != null && request.getContractId() != null) ||
                (request.getMembershipId() == null && request.getContractId() == null)) {
            throw new IllegalArgumentException(
                    "Payment must be linked to either membership or contract, not both or neither.");
        }

        MembershipRecord membership = null;
        ContractEntity contract = null;

        if (request.getMembershipId() != null) {
            membership = membershipRecordRepository.findById(request.getMembershipId())
                    .orElseThrow(() -> new ResourceNotFoundException("Membership not found"));
        }

        if (request.getContractId() != null) {
            contract = contractRepository.findById(request.getContractId())
                    .orElseThrow(() -> new ResourceNotFoundException("Contract not found"));
        }

        PaymentEntity payment = new PaymentEntity();
        payment.setMembership(membership);
        payment.setContract(contract);

        // payment.setMoney(request.getMoney());
        BigDecimal moneyValue;
        if (membership != null) {
            moneyValue = membership.getPackageInfo().getPrice();
        } else if (contract != null) {
            moneyValue = contract.getMoney();
        } else {
            moneyValue = BigDecimal.ZERO;
        }
        payment.setMoney(moneyValue);

        payment.setMethod(request.getMethod());
        payment.setStatus(request.getStatus());
        payment.setDescription(request.getDescription());

        PaymentEntity savedPayment = paymentRepository.save(payment);

        PaymentResponse convertToResponse = convertToResponse(savedPayment);

        // if (membership != null) {
        //     convertToResponse.setCustomerId(membership.getCustomer().getId());
        // } else {
        //     convertToResponse.setCustomerId(contract.getCustomer().getId());
        // }

        if (membership != null && membership.getCustomer() != null) {
            convertToResponse.setCustomerId(membership.getCustomer().getId());
        } else if (contract != null && contract.getCustomer() != null) {
            convertToResponse.setCustomerId(contract.getCustomer().getId());
        } else {
            convertToResponse.setCustomerId(null);
        }

        log.info("Successfully created payment with id: {}", savedPayment.getId());

        return convertToResponse;
    }

    @Override
    public PaymentResponse findById(Long id) {
        log.info("Finding payment by id: {}", id);
        PaymentEntity payment = getPaymentEntity(id);
        PaymentResponse response = convertToResponse(payment);
        log.info("Successfully found payment with id: {}", response.getId());
        return response;
    }

    @Override
    public PaymentResponse update(PaymentUpdateRequest request) {
        log.info("Updating payment with id: {}", request.getId());
        PaymentEntity payment = getPaymentEntity(request.getId());

        boolean hasMembership = request.getMembershipId() != null;
        boolean hasContract = request.getContractId() != null;

        if (hasMembership && hasContract) {
            throw new IllegalArgumentException("Payment must be linked to either membership or contract, not both.");
        }
        if (!hasMembership && !hasContract) {
            throw new IllegalArgumentException("Payment must be linked to either membership or contract.");
        }

        if (hasMembership) {
            MembershipRecord membership = membershipRecordRepository.findById(request.getMembershipId())
                    .orElseThrow(() -> new ResourceNotFoundException("Membership not found"));
            payment.setMembership(membership);
            payment.setContract(null);
        } else {
            ContractEntity contract = contractRepository.findById(request.getContractId())
                    .orElseThrow(() -> new ResourceNotFoundException("Contract not found"));
            payment.setContract(contract);
            payment.setMembership(null);
        }

        if (request.getMoney() != null)
            payment.setMoney(request.getMoney());
        if (request.getMethod() != null)
            payment.setMethod(request.getMethod());
        if (request.getStatus() != null)
            payment.setStatus(request.getStatus());
        if (request.getDescription() != null)
            payment.setDescription(request.getDescription());

        PaymentEntity savedPayment = paymentRepository.save(payment);

        log.info("Successfully updated payment with id: {}", savedPayment.getId());

        PaymentResponse convertToResponse = convertToResponse(savedPayment);

        convertToResponse.setCustomerId(
                savedPayment.getContract() != null
                        ? savedPayment.getContract().getCustomer().getId()
                        : savedPayment.getMembership() != null
                                ? savedPayment.getMembership().getCustomer().getId()
                                : null);

        return convertToResponse;
    }

    @Override
    public void deleteById(Long id) {
        log.info("Deleting payment with id: {}", id);
        PaymentEntity payment = getPaymentEntity(id);

        if (payment.getMembership() != null && membershipRecordRepository.existsById(payment.getMembership().getId())) {
            throw new IllegalArgumentException(
                    "Cannot delete payment: there are users currently using this membership");
        }

        // paymentRepository.deleteById(id);

        if (payment.getStatus() == PaymentStatus.REFUNDED) {
            log.warn("Payment with id {} is already cancelled.", id);
            return;
        }

        payment.setStatus(PaymentStatus.REFUNDED);
        paymentRepository.save(payment);
        log.info("Successfully deleted payment with id: {}", id);
    }

    // private PaymentResponse convertToResponse(PaymentEntity payment) {
    //     PaymentResponse response = new PaymentResponse();
    //     response.setId(payment.getId());
    //     response.setMembershipId(payment.getMembership().getId());
    //     response.setContractId(payment.getContract().getId());
    //     // response.setCustomerId(payment.getContract().getCustomer().getId());

    //     response.setCustomerId(
    //             payment.getContract() != null
    //                     ? payment.getContract().getCustomer().getId()
    //                     : payment.getMembership() != null
    //                             ? payment.getMembership().getCustomer().getId()
    //                             : null);

    //     response.setMoney(payment.getMoney());
    //     response.setMethod(payment.getMethod());
    //     response.setStatus(payment.getStatus());
    //     response.setDescription(payment.getDescription());
    //     return response;
    // }

    private PaymentEntity getPaymentEntity(Long id) {
        return paymentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Payment not found with id: " + id));
    }

    private PaymentResponse convertToResponse(PaymentEntity payment) {
    PaymentResponse response = new PaymentResponse();
    response.setId(payment.getId());

    // Set membershipId if membership is not null
    if (payment.getMembership() != null) {
        response.setMembershipId(payment.getMembership().getId());
    } else {
        response.setMembershipId(null);
    }

    // Set contractId if contract is not null
    if (payment.getContract() != null) {
        response.setContractId(payment.getContract().getId());
    } else {
        response.setContractId(null);
    }

    // Set customerId: ưu tiên contract, nếu không thì membership, nếu cả hai null thì null
    if (payment.getContract() != null && payment.getContract().getCustomer() != null) {
        response.setCustomerId(payment.getContract().getCustomer().getId());
    } else if (payment.getMembership() != null && payment.getMembership().getCustomer() != null) {
        response.setCustomerId(payment.getMembership().getCustomer().getId());
    } else {
        response.setCustomerId(null);
    }

    response.setMoney(payment.getMoney());
    response.setMethod(payment.getMethod());
    response.setStatus(payment.getStatus());
    response.setDescription(payment.getDescription());
    return response;
}

    @Override
    public PaymentPageResponse findAll(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        log.info("Getting payments with paging");

        Pageable pageable = buildPageable(page, size, sortBy, direction, ignoreCase);
        Page<PaymentEntity> paymentPage = paymentRepository.findAll(pageable);

        List<PaymentResponse> paymentResponses = paymentPage.getContent().stream()
            .map(this::convertToResponse)
            .toList();

        return buildPaymentPageResponse(paymentPage, paymentResponses);
    }

    // @Override
    // public List<PaymentResponse> findPaymentByUserId(Long userId) {
    //     log.info("Find payments for userId: {}", userId);

    //     List<PaymentEntity> payments = paymentRepository.findByMembership_IdOrContract_Id(userId, userId);


    //     return payments.stream().map(this::convertToResponse).toList();
                   
    // }

    @Override
public List<PaymentResponse> findPaymentByUserId(Long userId) {
    log.info("Find payments for userId: {}", userId);

    List<PaymentEntity> payments = paymentRepository.findByMembership_Customer_IdOrContract_Customer_Id(userId, userId);
    log.info("Payments size: {}", payments.size());
    for (PaymentEntity payment : payments) {
        log.info("Payment id: {}, contractId: {}, membershipId: {}",
            payment.getId(),
            payment.getContract() != null ? payment.getContract().getId() : null,
            payment.getMembership() != null ? payment.getMembership().getId() : null);
    }

    return payments.stream().map(this::convertToResponse).toList();
}

    // Method helper
    private Pageable buildPageable(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        Sort.Order order = new Sort.Order(Sort.Direction.fromString(direction), sortBy);
        if (ignoreCase) order = order.ignoreCase();
        Sort sort = Sort.by(order);
        return PageRequest.of(page, size, sort);
    }

    private PaymentPageResponse buildPaymentPageResponse(Page<PaymentEntity> paymentPage, List<PaymentResponse> paymentResponses) {
        PaymentPageResponse response = new PaymentPageResponse();
        response.setPageNumber(paymentPage.getNumber());
        response.setPageSize(paymentPage.getSize());
        response.setTotalElements(paymentPage.getTotalElements());
        response.setTotalPages(paymentPage.getTotalPages());
        response.setPayments(paymentResponses);
        return response;
    }
}
