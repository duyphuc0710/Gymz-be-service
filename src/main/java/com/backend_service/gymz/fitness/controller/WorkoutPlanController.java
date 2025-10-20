package com.backend_service.gymz.fitness.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
import com.backend_service.gymz.fitness.dto.request.workoutProgram.WorkoutPlanCreateRequest;
import com.backend_service.gymz.fitness.dto.response.workoutProgram.WorkoutProgramPageResponse;
import com.backend_service.gymz.fitness.dto.response.workoutProgram.WorkoutProgramResponse;
import com.backend_service.gymz.fitness.service.WorkoutPlanService;
import com.backend_service.gymz.user.model.UserEntity;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/v1/workout-plans")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Workout Plan Management")
public class WorkoutPlanController {

    private final WorkoutPlanService workoutPlanService;

    @PostMapping
    // Only owner and pt can create workout plans
    @PreAuthorize("hasAuthority('WORKOUT_PLAN:CREATE:SELF') or hasAuthority('WORKOUT_PLAN:CREATE:ALL')")
    @Operation(summary = "Create new workout plan")
    public ResponseData<WorkoutProgramResponse> createWorkoutPlan(
            @Valid @RequestBody WorkoutPlanCreateRequest request) {
        log.info("Received request to create workout plan: {}", request.getName());

        WorkoutProgramResponse response = workoutPlanService.save(request);
        log.info("Successfully created workout plan with id: {}", response.getId());

        return new ResponseData<>(HttpStatus.CREATED.value(), "Workout plan created successfully", response);
    }

    @GetMapping("/{id}")
    // All roles can view workout plan by ID
    @PreAuthorize("hasAuthority('WORKOUT_PLAN:READ:ALL') or hasAuthority('WORKOUT_PLAN:READ:SELF')")
    @Operation(summary = "Get workout plan by ID")
    public ResponseData<WorkoutProgramResponse> getWorkoutPlan(@PathVariable Long id) {
        log.info("Received request to get workout plan with id: {}", id);

        WorkoutProgramResponse response = workoutPlanService.findById(id);
        log.info("Successfully retrieved workout plan: {}", response.getName());

        return new ResponseData<>(HttpStatus.OK.value(), "Workout plan retrieved successfully", response);
    }

    @GetMapping
    // All roles can view the list of workout plans
    @PreAuthorize("hasRole('ROLE_OWNER')")
    @Operation(summary = "Get all workout plans")
    public ResponseData<WorkoutProgramPageResponse> getAllWorkoutPlans(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "10") int size,
        @RequestParam(defaultValue = "id") String sortBy,
        @RequestParam(defaultValue = "ASC") String direction,
        @RequestParam(defaultValue = "false") boolean ignoreCase
    ) {
        log.info("Received request to get all workout plans");

        WorkoutProgramPageResponse response = workoutPlanService.findAll(page, size, sortBy, direction, ignoreCase);
        log.info("Successfully retrieved {} workout plans");

        return new ResponseData<>(HttpStatus.OK.value(), "Workout plans retrieved successfully", response);
    }

    @GetMapping("/me")
    @Operation(summary = "Get work-plan of logged-in user")
    @PreAuthorize("hasAuthority('WORKOUT_PLAN:READ:SELF')")
    public ResponseData<?> getMyWorkoutPlan(@AuthenticationPrincipal UserEntity user) {
                
        Long userId = user.getId();
        log.info("Fetching work-plan for logged-in user: {}", userId);
        List<WorkoutProgramResponse> data = workoutPlanService.findWorkPlansByUserId(userId);
        return new ResponseData<>(HttpStatus.OK.value(), "Workout plans retrieved successfully", data);
    }

    @PutMapping("/{id}")
    // Only owner and pt can update workout plans
    @PreAuthorize("hasAuthority('WORKOUT_PLAN:UPDATE:SELF') or hasAuthority('WORKOUT_PLAN:UPDATE:ALL')")
    @Operation(summary = "Update workout plan")
    public ResponseData<WorkoutProgramResponse> updateWorkoutPlan(@PathVariable Long id,
            @Valid @RequestBody WorkoutPlanCreateRequest request) {
        log.info("Received request to update workout plan with id: {}", id);

        WorkoutProgramResponse response = workoutPlanService.update(id, request);
        log.info("Successfully updated workout plan with id: {}", id);

        return new ResponseData<>(HttpStatus.OK.value(), "Workout plan updated successfully", response);
    }

    @DeleteMapping("/{id}")
    // Only owner and pt can delete workout plans
    @PreAuthorize("hasAuthority('WORKOUT_PLAN:DELETE:SELF') or hasAuthority('WORKOUT_PLAN:DELETE:ALL')")
    @Operation(summary = "Delete workout plan by ID")
    public ResponseData<Void> deleteWorkoutPlan(@PathVariable Long id) {
        log.info("Received request to delete workout plan with id: {}", id);

        workoutPlanService.deleteById(id);
        log.info("Successfully deleted workout plan with id: {}", id);

        return new ResponseData<>(HttpStatus.OK.value(), "Workout plan deleted successfully");
    }
}
