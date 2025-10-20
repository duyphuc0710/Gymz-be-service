package com.backend_service.gymz.fitness.service.impl;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend_service.gymz.common.exception.BusinessException;
import com.backend_service.gymz.common.exception.ResourceNotFoundException;
import com.backend_service.gymz.fitness.common.enums.equipment.EquipmentStatus;
import com.backend_service.gymz.fitness.dto.request.equipment.EquipmentCreateRequest;
import com.backend_service.gymz.fitness.dto.request.equipment.EquipmentUpdateRequest;
import com.backend_service.gymz.fitness.dto.response.equipment.EquipmentPageReponse;
import com.backend_service.gymz.fitness.dto.response.equipment.EquipmentResponse;
import com.backend_service.gymz.fitness.model.EquipmentEntity;
import com.backend_service.gymz.fitness.repository.EquipmentRepository;
import com.backend_service.gymz.fitness.service.EquipmentService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = "EQUIPMENT-SERVICE")
@RequiredArgsConstructor
@Transactional
public class EquipmentServiceImpl implements EquipmentService {

    private final EquipmentRepository equipmentRepository;

    @Override
    public EquipmentResponse createEquipment(EquipmentCreateRequest request) {
        log.info("Creating equipment with request: {}", request);
        // Business validation: Không cho phép tạo equipment với status RETIRED
        if (EquipmentStatus.RETIRED.equals(request.getStatus())) {
            throw new BusinessException("Cannot create equipment with RETIRED status");
        }
        EquipmentEntity equipment = new EquipmentEntity();
        equipment.setName(request.getName());
        equipment.setType(request.getType());
        equipment.setBrand(request.getBrand());
        equipment.setPurchaseDate(request.getPurchaseDate());
        equipment.setStatus(request.getStatus());
        equipment.setDescription(request.getDescription());
        equipmentRepository.save(equipment);
        log.info("Equipment created with ID: {}", equipment.getId());
        return convertToResponse(equipment);
    }

    @Override
    public EquipmentResponse updateEquipment(Long id, EquipmentUpdateRequest request) {
        log.info("Updating equipment with ID: {} and request: {}", id, request);
        EquipmentEntity equipment = getEquipmentEntity(id);
        // Business validation: Không cho phép chuyển sang RETIRED nếu đã là RETIRED
        if (EquipmentStatus.RETIRED.equals(equipment.getStatus()) && EquipmentStatus.RETIRED.equals(request.getStatus())) {
            throw new BusinessException("Equipment is already retired");
        }
        equipment.setName(request.getName());
        equipment.setType(request.getType());
        equipment.setBrand(request.getBrand());
        equipment.setPurchaseDate(request.getPurchaseDate());
        equipment.setStatus(request.getStatus());
        equipment.setDescription(request.getDescription());
        equipmentRepository.save(equipment);
        log.info("Equipment updated with ID: {}", equipment.getId());
        return convertToResponse(equipment);
    }

    @Override
    public EquipmentResponse getEquipmentById(Long id) {
        log.info("Finding equipment by ID: {}", id);
        return convertToResponse(getEquipmentEntity(id));
    }

    
    public List<EquipmentResponse> getAllEquipment() {
        log.info("Getting all equipment");

        List<EquipmentEntity> equipmentList = equipmentRepository.findAll();

        return equipmentList.stream()
                .map(this::convertToResponse)
                .toList();
    }

    @Override
    public void deleteById(Long id) {
        log.info("Deleting equipment ID: {}", id);
        EquipmentEntity equipment = getEquipmentEntity(id);
        if (EquipmentStatus.RETIRED.equals(equipment.getStatus())) {
            throw new BusinessException("Equipment is already retired");
        }
        equipment.setStatus(EquipmentStatus.RETIRED);
        equipmentRepository.save(equipment);
        log.info("Equipment marked as retired: {}", id);
    }

    @Override
    public List<EquipmentResponse> getEquipmentByStatus(EquipmentStatus status) {
        log.info("Getting equipment by status: {}", status);
        return equipmentRepository.findByStatus(status)
            .stream()
            .map(this::convertToResponse)
            .toList();
    }

    @Override
    public List<EquipmentResponse> getEquipmentByType(String type) {
        log.info("Getting equipment by type: {}", type);
        return equipmentRepository.findByType(type)
            .stream()
            .map(this::convertToResponse)
            .toList();
    }

    @Override
    public EquipmentPageReponse getAllEquipment(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        log.info("Getting equipment with paging");

        Pageable pageable = buildPageable(page, size, sortBy, direction, ignoreCase);
        Page<EquipmentEntity> equipmentPage = equipmentRepository.findAll(pageable);

        List<EquipmentResponse> equipmentResponses = equipmentPage.getContent().stream()
            .map(this::convertToResponse)
            .toList();

        return buildEquipmentPageResponse(equipmentPage, equipmentResponses);
    }

    // Method helper
    private Pageable buildPageable(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        Sort.Order order = new Sort.Order(Sort.Direction.fromString(direction), sortBy);
        if (ignoreCase) order = order.ignoreCase();
        Sort sort = Sort.by(order);
        return PageRequest.of(page, size, sort);
    }

    private EquipmentPageReponse buildEquipmentPageResponse(Page<EquipmentEntity> equipmentPage, List<EquipmentResponse> equipmentResponses) {
        EquipmentPageReponse response = new EquipmentPageReponse();
        response.setPageNumber(equipmentPage.getNumber());
        response.setPageSize(equipmentPage.getSize());
        response.setTotalElements(equipmentPage.getTotalElements());
        response.setTotalPages(equipmentPage.getTotalPages());
        response.setEquipments(equipmentResponses);
        return response;
    }

    // @Override
    // public EquipmentResponse changeEquipmentStatus(Long id, EquipmentStatus newStatus) {
    //     log.info("Changing equipment {} status to {}", id, newStatus);

    //     Equipment equipment = getEquipmentEntity(id);
    //     EquipmentStatus oldStatus = equipment.getStatus();
        
    //     equipment.setStatus(newStatus);
    //     Equipment updated = equipmentRepository.save(equipment);

    //     log.info("Equipment {} status: {} → {}", id, oldStatus, newStatus);
    //     return convertToResponse(updated);
    // }

    // @Override
    // public EquipmentResponse markForMaintenance(Long id) {
    //     return changeEquipmentStatus(id, EquipmentStatus.MAINTENANCE);
    // }

    // @Override
    // public EquipmentResponse markAsFixed(Long id) {
    //     return changeEquipmentStatus(id, EquipmentStatus.ACTIVE);
    // }

    // @Override
    // public EquipmentResponse retireEquipment(Long id) {
    //     return changeEquipmentStatus(id, EquipmentStatus.RETIRED);
    // }

    // @Override
    // public EquipmentResponse reportBrokenEquipment(Long id, String reason) {
    // // Business workflow: User báo cáo equipment hỏng
    // Equipment equipment = getEquipmentEntity(id);

    // if (equipment.getStatus() == EquipmentStatus.RETIRED) {
    // throw new BusinessException("Cannot report retired equipment");
    // }

    // equipment.setStatus(EquipmentStatus.BROKEN);
    // // Log reason for maintenance team
    // return convertToResponse(equipmentRepository.save(equipment));
    // }

    private EquipmentResponse convertToResponse(EquipmentEntity equipment) {
        return EquipmentResponse.builder()
                .id(equipment.getId())
                .name(equipment.getName())
                .type(equipment.getType())
                .brand(equipment.getBrand())
                .purchaseDate(equipment.getPurchaseDate())
                .status(equipment.getStatus())
                .description(equipment.getDescription())
                .build();
    }

    private EquipmentEntity getEquipmentEntity(Long id) {
        return equipmentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Equipment", "id", id));
    }

}
