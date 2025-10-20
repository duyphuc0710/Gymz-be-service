package com.backend_service.gymz.fitness.service.impl;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.backend_service.gymz.common.exception.ResourceNotFoundException;
import com.backend_service.gymz.fitness.common.enums.membership.MembershipRecordStatus;
import com.backend_service.gymz.fitness.dto.request.membership.MembershipRecordCreateRequest;
import com.backend_service.gymz.fitness.dto.request.membership.MembershipRecordUpdateRequest;
import com.backend_service.gymz.fitness.dto.response.membership.MembershipRecordPageResponse;
import com.backend_service.gymz.fitness.dto.response.membership.MembershipRecordResponse;
import com.backend_service.gymz.fitness.model.MembershipEntity;
import com.backend_service.gymz.fitness.model.MembershipRecord;
import com.backend_service.gymz.fitness.repository.MembershipRecordRepository;
import com.backend_service.gymz.fitness.repository.MembershipRepository;
import com.backend_service.gymz.fitness.service.MembershipRecordService;
import com.backend_service.gymz.user.model.UserEntity;
import com.backend_service.gymz.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = "MEMBERSHIP-RECORD-SERVICE")
@RequiredArgsConstructor
public class MembershipRecordServiceImpl implements MembershipRecordService {
    private final UserRepository userRepository;
    private final MembershipRepository membershipRepository;
    private final MembershipRecordRepository membershipRecordRepository;

    @Override
    public MembershipRecordResponse save(MembershipRecordCreateRequest request) {
       log.info("Creating new membership for user id: {}", request.getCustomer());
        
        UserEntity customer = userRepository.findById(request.getCustomer())
                .orElseThrow(() -> new ResourceNotFoundException("User id not found"));

        MembershipEntity membership = membershipRepository.findById(request.getPackageInfo())
                .orElseThrow(() -> new ResourceNotFoundException("Membership package not found"));
        
        MembershipRecord membershipRecord = new MembershipRecord();
        membershipRecord.setCustomer(customer);
        membershipRecord.setPackageInfo(membership);
        membershipRecord.setStartDate(new Date());
        Calendar cal = Calendar.getInstance();
        cal.setTime(membershipRecord.getStartDate());
        cal.add(Calendar.MONTH, membershipRecord.getPackageInfo().getDuration()); 
        membershipRecord.setEndDate(cal.getTime());
        membershipRecord.setStatus(MembershipRecordStatus.ACTIVE);

        MembershipRecord savedMembership = membershipRecordRepository.save(membershipRecord);
        log.info("Successfully created membership with id: {}", savedMembership.getId());
       
        return convertToResponse(savedMembership);


    }
    @Override
    public MembershipRecordResponse findById(Long id) {
        log.info("Finding membership record by id: {}", id);
        MembershipRecord membership = getMembershipRecord(id);
        MembershipRecordResponse response = convertToResponse(membership);
        log.info("Successfully found membership record: {}", response.getId());
        return response;
    }
  
    @Override
    public MembershipRecordResponse update(MembershipRecordUpdateRequest request) {
        log.info("Updating membership record with id: {}", request.getId());
        UserEntity customer = userRepository.findById(request.getCustomer())
                .orElseThrow(() -> new ResourceNotFoundException("User id not found"));

        MembershipEntity existMembership = membershipRepository.findById(request.getPackageInfo())
                .orElseThrow(() -> new ResourceNotFoundException("Membership package not found"));
        
        MembershipRecord membership = getMembershipRecord(request.getId());

        membership.setCustomer(customer);
        membership.setPackageInfo(existMembership);
        membership.setStartDate(request.getStartDate());
        Calendar cal = Calendar.getInstance();
        cal.setTime(membership.getStartDate());
        cal.add(Calendar.MONTH, membership.getPackageInfo().getDuration()); 
        membership.setEndDate(cal.getTime());
        membership.setStatus(request.getStatus());

        MembershipRecord updatedMembership = membershipRecordRepository.save(membership);
        log.info("Successfully updated membership record with id: {}", updatedMembership.getId());
        
        return convertToResponse(updatedMembership);
    }
    @Override
    public void deleteById(Long id) {
        log.info("Deleting membership record with id: {}", id);
        MembershipRecord membership = getMembershipRecord(id);
       
        membership.setStatus(MembershipRecordStatus.CANCELLED);
        membershipRecordRepository.save(membership);

        log.info("Successfully cancelled membership record with id: {}", id);
    }
    @Override
    public MembershipRecordPageResponse findAll(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        log.info("Getting membership records with paging");

        Pageable pageable = buildPageable(page, size, sortBy, direction, ignoreCase);
        Page<MembershipRecord> membershipPage = membershipRecordRepository.findAll(pageable);

        List<MembershipRecordResponse> membershipResponses = membershipPage.getContent().stream()
            .map(this::convertToResponse)
            .toList();

        return buildMembershipRecordPageResponse(membershipPage, membershipResponses);
    }

    // Method helper
    private Pageable buildPageable(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        Sort.Order order = new Sort.Order(Sort.Direction.fromString(direction), sortBy);
        if (ignoreCase) order = order.ignoreCase();
        Sort sort = Sort.by(order);
        return PageRequest.of(page, size, sort);
    }

    private MembershipRecordPageResponse buildMembershipRecordPageResponse(Page<MembershipRecord> membershipPage, List<MembershipRecordResponse> membershipResponses) {
        MembershipRecordPageResponse response = new MembershipRecordPageResponse();
        response.setPageNumber(membershipPage.getNumber());
        response.setPageSize(membershipPage.getSize());
        response.setTotalElements(membershipPage.getTotalElements());
        response.setTotalPages(membershipPage.getTotalPages());
        response.setMembershipRecords(membershipResponses);
        return response;
    }

    private MembershipRecord getMembershipRecord(Long id) {
        return membershipRecordRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Membership", "id", id));
    }

    private MembershipRecordResponse convertToResponse(MembershipRecord membership) {
        MembershipRecordResponse response = new MembershipRecordResponse();
        response.setId(membership.getId());
        response.setCustomer(membership.getCustomer().getId());
        response.setPackageInfo(membership.getPackageInfo().getId());
        response.setStartDate(membership.getStartDate());
        response.setEndDate(membership.getEndDate());
        response.setStatus(membership.getStatus());

        return response;
    }
  
    
}
