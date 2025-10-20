package com.backend_service.gymz.fitness.service.impl;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend_service.gymz.common.exception.ResourceNotFoundException;
import com.backend_service.gymz.fitness.dto.request.workSchedule.WorkScheduleCreateRequest;
import com.backend_service.gymz.fitness.dto.request.workSchedule.WorkScheduleUpdateRequest;
import com.backend_service.gymz.fitness.dto.response.workSchedule.WorkSchedulePageResponse;
import com.backend_service.gymz.fitness.dto.response.workSchedule.WorkScheduleResponse;
import com.backend_service.gymz.fitness.model.WorkScheduleEntity;
import com.backend_service.gymz.fitness.repository.WorkScheduleRepository;
import com.backend_service.gymz.fitness.service.WorkScheduleService;
import com.backend_service.gymz.user.model.UserEntity;
import com.backend_service.gymz.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = "WORK-SCHEDULE-SERVICE")
@RequiredArgsConstructor
@Transactional
public class WorkScheduleServiceImpl implements WorkScheduleService {

    private final WorkScheduleRepository workScheduleRepository;
    private final UserRepository userRepository;

    /**
     * Business logic for creating a new work schedule
     * 1. Validate employee exists
     * 2. Create WorkSchedule entity from request DTO
     * 3. Save to database
     * 4. Convert entity to response DTO
     */
    @Override
    public WorkScheduleResponse save(WorkScheduleCreateRequest request) {
        log.info("Creating work schedule for employee ID: {}", request.getEmployeeId());
        
        // Step 1: Validate employee exists
        UserEntity employee = userRepository.findById(request.getEmployeeId())
            .orElseThrow(() -> {
                log.error("Employee not found with ID: {}", request.getEmployeeId());
                return new RuntimeException("Employee not found");
            });
        
        log.debug("Found employee: {} for work schedule", employee.getUsername());
        
        // Step 2: Create WorkSchedule entity from request DTO
        WorkScheduleEntity workSchedule = new WorkScheduleEntity();
        workSchedule.setEmployee(employee);
        workSchedule.setWorkDate(request.getWorkDate());
        workSchedule.setStartTime(request.getStartTime());
        workSchedule.setEndTime(request.getEndTime());
        workSchedule.setShift(request.getShift());
        
        // Step 3: Save to database
        WorkScheduleEntity savedSchedule = workScheduleRepository.save(workSchedule);
        log.info("Successfully created work schedule with ID: {}", savedSchedule.getId());
        
        // Step 4: Convert entity to response DTO
        return convertToResponse(savedSchedule);
    }

    /**
     * Business logic for finding work schedule by ID
     * 1. Find WorkSchedule with fetch employee to avoid N+1 query
     * 2. Convert entity to response DTO
     */
    @Override
    @Transactional(readOnly = true)
    public WorkScheduleResponse findById(Long id) {
        log.info("Finding work schedule with ID: {}", id);
        
        // Use query with JOIN FETCH to load employee as well
        WorkScheduleEntity workSchedule = workScheduleRepository.findByIdWithEmployee(id);
        if (workSchedule == null) {
            log.error("Work schedule not found with ID: {}", id);
            throw new RuntimeException("Work schedule not found");
        }
        
        log.debug("Found work schedule for employee: {}", workSchedule.getEmployee().getUsername());
        return convertToResponse(workSchedule);
    }

    /**
     * Business logic for getting all work schedules with paging
     * 1. Create Pageable object from parameters
     * 2. Fetch paged data from repository
     * 3. Convert entity list to response DTOs
     * 4. Build and return WorkSchedulePageResponse
     */
    @Override
    @Transactional(readOnly = true)
    public WorkSchedulePageResponse findAll(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        log.info("Getting work schedules with paging");

        Pageable pageable = buildPageable(page, size, sortBy, direction, ignoreCase);
        Page<WorkScheduleEntity> workSchedulePage = workScheduleRepository.findAll(pageable);

        List<WorkScheduleResponse> workScheduleResponses = workSchedulePage.getContent().stream()
            .map(this::convertToResponse)
            .toList();

        return buildWorkSchedulePageResponse(workSchedulePage, workScheduleResponses);
    }


    @Override
    @Transactional(readOnly = true)
    public List<WorkScheduleResponse> findByUserId(Long id) {
        log.info("Finding work schedule with ID: {}", id);
        
        // Use query with JOIN FETCH to load employee as well
        List<WorkScheduleEntity> workSchedule = workScheduleRepository.findByEmployee_Id(id);
        if (workSchedule == null) {
            log.error("Work schedule not found with ID: {}", id);
            throw new ResourceNotFoundException("Work schedule not found");
        }
        
        return workSchedule.stream().map(this::convertToResponse).toList();
    }


    /**
     * Business logic for updating work schedule
     * 1. Validate WorkSchedule and Employee exist
     * 2. Update information from request DTO
     * 3. Save changes to database
     * 4. Convert entity to response DTO
     */
    @Override
    public WorkScheduleResponse update(Long id, WorkScheduleUpdateRequest request) {
        log.info("Updating work schedule with ID: {}", id);
        
        // Step 1: Find WorkSchedule to update
        WorkScheduleEntity existingSchedule = workScheduleRepository.findByIdWithEmployee(id);
        if (existingSchedule == null) {
            log.error("Work schedule not found with ID: {}", id);
            throw new RuntimeException("Work schedule not found");
        }
        
        // Validate new employee if changed
        UserEntity employee = userRepository.findById(request.getEmployeeId())
            .orElseThrow(() -> {
                log.error("Employee not found with ID: {}", request.getEmployeeId());
                return new RuntimeException("Employee not found");
            });
        
        // Step 2: Update information from request DTO
        log.debug("Updating work schedule fields for ID: {}", id);
        existingSchedule.setEmployee(employee);
        existingSchedule.setWorkDate(request.getWorkDate());
        existingSchedule.setStartTime(request.getStartTime());
        existingSchedule.setEndTime(request.getEndTime());
        existingSchedule.setShift(request.getShift());
        
        // Step 3: Save changes to database
        WorkScheduleEntity updatedSchedule = workScheduleRepository.save(existingSchedule);
        log.info("Successfully updated work schedule with ID: {}", id);
        
        // Step 4: Convert entity to response DTO
        return convertToResponse(updatedSchedule);
    }

    /**
     * Business logic for deleting work schedule
     * 1. Validate WorkSchedule exists
     * 2. Delete from database
     */
    @Override
    public void deleteById(Long id) {
        log.info("Deleting work schedule with ID: {}", id);
        
        // Check if WorkSchedule exists
        if (!workScheduleRepository.existsById(id)) {
            log.error("Work schedule not found for deletion with ID: {}", id);
            throw new RuntimeException("Work schedule not found");
        }
        
        // Delete WorkSchedule
        workScheduleRepository.deleteById(id);
        log.info("Successfully deleted work schedule with ID: {}", id);
    }

    /**
     * Utility method: Convert WorkSchedule entity to WorkScheduleResponse DTO
     * Including information from Employee entity
     */
    private WorkScheduleResponse convertToResponse(WorkScheduleEntity workSchedule) {
        log.debug("Converting work schedule to response for ID: {}", workSchedule.getId());
        
        return WorkScheduleResponse.builder()
            .id(workSchedule.getId())
            .employeeId(workSchedule.getEmployee().getId())
            .employeeName(workSchedule.getEmployee().getFirstName() + " " + workSchedule.getEmployee().getLastName())
            .employeeUsername(workSchedule.getEmployee().getUsername())
            .workDate(workSchedule.getWorkDate())
            .startTime(workSchedule.getStartTime())
            .endTime(workSchedule.getEndTime())
            .shift(workSchedule.getShift())
            .build();
    }

    // Method helper
    private Pageable buildPageable(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        Sort.Order order = new Sort.Order(Sort.Direction.fromString(direction), sortBy);
        if (ignoreCase) order = order.ignoreCase();
        Sort sort = Sort.by(order);
        return PageRequest.of(page, size, sort);
    }

    private WorkSchedulePageResponse buildWorkSchedulePageResponse(Page<WorkScheduleEntity> workSchedulePage, List<WorkScheduleResponse> workScheduleResponses) {
        WorkSchedulePageResponse response = new WorkSchedulePageResponse();
        response.setPageNumber(workSchedulePage.getNumber());
        response.setPageSize(workSchedulePage.getSize());
        response.setTotalElements(workSchedulePage.getTotalElements());
        response.setTotalPages(workSchedulePage.getTotalPages());
        response.setWorkSchedules(workScheduleResponses);
        return response;
    }
}
