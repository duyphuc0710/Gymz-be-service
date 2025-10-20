package com.backend_service.gymz.fitness.service.impl;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend_service.gymz.common.exception.BusinessException;
import com.backend_service.gymz.common.exception.DuplicateResourceException;
import com.backend_service.gymz.common.exception.ResourceNotFoundException;
import com.backend_service.gymz.fitness.common.enums.membership.MembershipStatus;
import com.backend_service.gymz.fitness.dto.request.membership.MembershipCreateRequest;
import com.backend_service.gymz.fitness.dto.request.membership.MembershipUpdateRequest;
import com.backend_service.gymz.fitness.dto.response.membership.MembershipPageResponse;
import com.backend_service.gymz.fitness.dto.response.membership.MembershipResponse;
import com.backend_service.gymz.fitness.model.MembershipEntity;
import com.backend_service.gymz.fitness.repository.MembershipRecordRepository;
import com.backend_service.gymz.fitness.repository.MembershipRepository;
import com.backend_service.gymz.fitness.service.MembershipService;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.PageRequest;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = "MEMBERSHIP-SERVICE")
@RequiredArgsConstructor
@Transactional
public class MembershipServiceImpl implements MembershipService {

    private final MembershipRepository membershipRepository;
    private final MembershipRecordRepository membershipRecordRepository;

    @Override
    public MembershipResponse save(MembershipCreateRequest request) {
        log.info("Creating new membership with name: {}", request.getName());
        if (membershipRepository.existsByName(request.getName())) {
            throw new DuplicateResourceException("Membership", "name", request.getName());
        }
       
        MembershipEntity membership = new MembershipEntity();
        membership.setName(request.getName());
        membership.setDuration(request.getDuration());
        membership.setPrice(request.getPrice());
        membership.setDescription(request.getDescription());
        membership.setStatus(MembershipStatus.ACTIVE);
        MembershipEntity savedMembership = membershipRepository.save(membership);
        log.info("Successfully created membership with id: {}", savedMembership.getId());
        return convertToResponse(savedMembership);
    }

    @Override
    public MembershipResponse findById(Long id) {
        log.info("Finding membership by id: {}", id);
        MembershipEntity membership = getMembershipEntity(id);
        MembershipResponse response = convertToResponse(membership);
        log.info("Successfully found membership: {}", response.getName());
        return response;
    }

    @Override
    public MembershipResponse update(MembershipUpdateRequest request) {
        log.info("Updating membership with id: {}", request.getId());
        MembershipEntity membership = getMembershipEntity(request.getId());

        membership.setName(request.getName());
        membership.setDuration(request.getDuration());
        membership.setPrice(request.getPrice());
        membership.setDescription(request.getDescription());      
        membership.setStatus(request.getStatus());
        
        MembershipEntity savedMembership = membershipRepository.save(membership);
        log.info("Successfully updated membership: {}", savedMembership.getName());
        return convertToResponse(savedMembership);
    }

    @Override
    public void deleteById(Long id) {
        log.info("Deleting membership with id: {}", id);
        
        if (membershipRecordRepository.existsByPackageInfo_Id(id)) {
            throw new BusinessException("Cannot delete membership: there are users currently using this membership");
        }
        membershipRepository.deleteById(id);
        log.info("Successfully deleted membership with id: {}", id);
    }

    @Override
    public MembershipPageResponse findAll(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        log.info("Getting memberships with paging");

        Pageable pageable = buildPageable(page, size, sortBy, direction, ignoreCase);
        Page<MembershipEntity> membershipPage = membershipRepository.findAll(pageable);

        List<MembershipResponse> membershipResponses = membershipPage.getContent().stream()
            .map(this::convertToResponse)
            .toList();

        return buildMembershipPageResponse(membershipPage, membershipResponses);
    }

    // Method helper
    private Pageable buildPageable(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        Sort.Order order = new Sort.Order(Sort.Direction.fromString(direction), sortBy);
        if (ignoreCase) order = order.ignoreCase();
        Sort sort = Sort.by(order);
        return PageRequest.of(page, size, sort);
    }

    private MembershipPageResponse buildMembershipPageResponse(Page<MembershipEntity> membershipPage, List<MembershipResponse> membershipResponses) {
        MembershipPageResponse response = new MembershipPageResponse();
        response.setPageNumber(membershipPage.getNumber());
        response.setPageSize(membershipPage.getSize());
        response.setTotalElements(membershipPage.getTotalElements());
        response.setTotalPages(membershipPage.getTotalPages());
        response.setMemberships(membershipResponses);
        return response;
    }

    private MembershipResponse convertToResponse(MembershipEntity membership) {
        MembershipResponse response = new MembershipResponse();
        response.setId(membership.getId());
        response.setName(membership.getName());
        response.setDuration(membership.getDuration());
        response.setPrice(membership.getPrice());
        response.setDescription(membership.getDescription());
        response.setStatus(membership.getStatus());
        return response;
    }

    private MembershipEntity getMembershipEntity(Long id) {
        return membershipRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Membership", "id", id));
    }
}
