package com.backend_service.gymz.fitness.service.impl;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend_service.gymz.common.exception.ResourceNotFoundException;
import com.backend_service.gymz.fitness.dto.request.workoutProgram.ExerciseProgramData;
import com.backend_service.gymz.fitness.dto.request.workoutProgram.WorkoutPlanCreateRequest;
import com.backend_service.gymz.fitness.dto.response.workoutProgram.ExerciseProgramResponse;
import com.backend_service.gymz.fitness.dto.response.workoutProgram.WorkoutProgramPageResponse;
import com.backend_service.gymz.fitness.dto.response.workoutProgram.WorkoutProgramResponse;
import com.backend_service.gymz.fitness.model.ContractEntity;
import com.backend_service.gymz.fitness.model.ExerciseEntity;
import com.backend_service.gymz.fitness.model.WorkoutPlanEntity;
import com.backend_service.gymz.fitness.model.WorkoutPlanExercise;
import com.backend_service.gymz.fitness.repository.ContractRepository;
import com.backend_service.gymz.fitness.repository.ExerciseRepository;
import com.backend_service.gymz.fitness.repository.WorkoutPlanRepository;
import com.backend_service.gymz.fitness.service.WorkoutPlanService;
import com.backend_service.gymz.user.model.UserEntity;
import com.backend_service.gymz.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = "WORKOUT-PLAN-SERVICE")
@RequiredArgsConstructor
@Transactional
public class WorkoutPlanServiceImpl implements WorkoutPlanService {

    private final WorkoutPlanRepository workoutPlanRepository;
    private final ExerciseRepository exerciseRepository;
    private final ContractRepository contractRepository;
    private final UserRepository userRepository;

    @Override
    public WorkoutProgramResponse save(WorkoutPlanCreateRequest req) {
        log.info("Creating workout plan with name: {}", req.getName());
        
        UserEntity customer = userRepository.findById(req.getCustomerId())
            .orElseThrow(() -> {
                log.error("Customer not found with id: {}", req.getCustomerId());
                return new ResourceNotFoundException("Customer not found");
            });
        
        log.debug("Found customer: {} with id: {}", customer.getUsername(), customer.getId());

        ContractEntity contract = contractRepository.findById(req.getContract())
            .orElseThrow(() -> {
                log.error("Contract not found with id: {}", req.getContract());
                return new ResourceNotFoundException("Contract not found" + req.getContract());
            });

        WorkoutPlanEntity workoutPlan = new WorkoutPlanEntity();
        workoutPlan.setName(req.getName());
        workoutPlan.setDescription(req.getDescription());
        workoutPlan.setDuration(req.getDuration());
        workoutPlan.setCustomer(customer);
        workoutPlan.setContract(contract);

        if (req.getExercises() != null && !req.getExercises().isEmpty()) {
            log.info("Adding {} exercises to workout plan", req.getExercises().size());
            
            for (ExerciseProgramData exerciseData : req.getExercises()) {
                ExerciseEntity exercise = exerciseRepository.findById(exerciseData.getExerciseId())
                    .orElseThrow(() -> {
                        log.error("Exercise not found with id: {}", exerciseData.getExerciseId());
                        return new ResourceNotFoundException("Exercise not found: " + exerciseData.getExerciseId());
                    });

                log.debug("Adding exercise: {} to workout plan", exercise.getName());

                WorkoutPlanExercise workoutPlanExercise = new WorkoutPlanExercise();
                workoutPlanExercise.setProgram(workoutPlan);
                workoutPlanExercise.setExercise(exercise);
                workoutPlanExercise.setSets(exerciseData.getSets());
                workoutPlanExercise.setReps(exerciseData.getReps());
                workoutPlanExercise.setWeight(exerciseData.getWeight());
                workoutPlanExercise.setRestTime(exerciseData.getRestTime());
                workoutPlanExercise.setOrderIndex(exerciseData.getOrderIndex());
                workoutPlanExercise.setDescription(exerciseData.getDescription());

                workoutPlan.getProgramExercises().add(workoutPlanExercise);
            }
        } else {
            log.warn("No exercises provided for workout plan: {}", req.getName());
        }

        WorkoutPlanEntity savedPlan = workoutPlanRepository.save(workoutPlan);
        log.info("Successfully created workout plan with id: {}", savedPlan.getId());
        
        return convertToResponse(savedPlan);
    }

    @Override
    @Transactional(readOnly = true)
    public WorkoutProgramResponse findById(Long id) {
        log.info("Finding workout plan with id: {}", id);
        
        WorkoutPlanEntity workoutPlan = workoutPlanRepository.findByIdWithExercises(id)
            .orElseThrow(() -> {
                log.error("WorkoutPlan not found with id: {}", id);
                return new ResourceNotFoundException("WorkoutPlan not found with id: " + id);
            });
        
        return convertToResponse(workoutPlan);
    }

    @Override
    @Transactional(readOnly = true)
    public WorkoutProgramPageResponse findAll(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        log.info("Getting workout plans with paging");

        Pageable pageable = buildPageable(page, size, sortBy, direction, ignoreCase);
        Page<WorkoutPlanEntity> workoutPlanPage = workoutPlanRepository.findAll(pageable);

        List<WorkoutProgramResponse> workoutProgramResponses = workoutPlanPage.getContent().stream()
            .map(this::convertToResponse)
            .toList();

        return buildWorkoutProgramPageResponse(workoutPlanPage, workoutProgramResponses);
    }

    @Override
    @Transactional(readOnly = true)
    public List<WorkoutProgramResponse> findWorkPlansByUserId(Long userId){
        log.info("Finding workout plans for userId: {}", userId);
        
        List<WorkoutPlanEntity> workoutPlans = workoutPlanRepository.findByCustomer_Id(userId);

        return workoutPlans.stream().map(this::convertToResponse).toList();
    }

    @Override
    public WorkoutProgramResponse update(Long id, WorkoutPlanCreateRequest req) {
        log.info("Updating workout plan with id: {}", id);
        
        WorkoutPlanEntity existingPlan = workoutPlanRepository.findByIdWithExercises(id)
            .orElseThrow(() -> {
                log.error("WorkoutPlan not found with id: {}", id);
                return new ResourceNotFoundException("WorkoutPlan not found");
            });

        UserEntity customer = userRepository.findById(req.getCustomerId())
            .orElseThrow(() -> {
                log.error("Customer not found with id: {}", req.getCustomerId());
                return new RuntimeException("Customer not found");
            });

        log.debug("Updating workout plan basic info for id: {}", id);
        existingPlan.setName(req.getName());
        existingPlan.setDescription(req.getDescription());
        existingPlan.setDuration(req.getDuration());
        existingPlan.setCustomer(customer);

        existingPlan.getProgramExercises().clear();

        if (req.getExercises() != null && !req.getExercises().isEmpty()) {
            log.info("Adding {} new exercises to workout plan", req.getExercises().size());
            
            for (ExerciseProgramData exerciseData : req.getExercises()) {
                ExerciseEntity exercise = exerciseRepository.findById(exerciseData.getExerciseId())
                    .orElseThrow(() -> {
                        log.error("Exercise not found with id: {}", exerciseData.getExerciseId());
                        return new ResourceNotFoundException("Exercise not found: " + exerciseData.getExerciseId());
                    });

                WorkoutPlanExercise workoutPlanExercise = new WorkoutPlanExercise();
                workoutPlanExercise.setProgram(existingPlan);
                workoutPlanExercise.setExercise(exercise);
                workoutPlanExercise.setSets(exerciseData.getSets());
                workoutPlanExercise.setReps(exerciseData.getReps());
                workoutPlanExercise.setWeight(exerciseData.getWeight());
                workoutPlanExercise.setRestTime(exerciseData.getRestTime());
                workoutPlanExercise.setOrderIndex(exerciseData.getOrderIndex());
                workoutPlanExercise.setDescription(exerciseData.getDescription());

                existingPlan.getProgramExercises().add(workoutPlanExercise);
            }
        } else {
            log.warn("No exercises provided for workout plan update: {}", req.getName());
        }

        WorkoutPlanEntity updatedPlan = workoutPlanRepository.save(existingPlan);
        log.info("Successfully updated workout plan with id: {}", id);
        
        return convertToResponse(updatedPlan);
    }

    @Override
    public void deleteById(Long id) {
        log.info("Deleting workout plan with id: {}", id);
        
        if (!workoutPlanRepository.existsById(id)) {
            log.error("WorkoutPlan not found for deletion with id: {}", id);
            throw new ResourceNotFoundException("WorkoutPlan not found");
        }
        
        workoutPlanRepository.deleteById(id);
        log.info("Successfully deleted workout plan with id: {}", id);
    }

    private WorkoutProgramResponse convertToResponse(WorkoutPlanEntity workoutPlan) {
        log.debug("Converting workout plan to response: {}", workoutPlan.getName());
        
        List<ExerciseProgramResponse> exerciseResponses = workoutPlan.getProgramExercises().stream()
            .map(this::convertToExerciseResponse)
            .collect(Collectors.toList());

        return WorkoutProgramResponse.builder()
            .id(workoutPlan.getId())
            .name(workoutPlan.getName())
            .customerId(workoutPlan.getCustomer().getId())
            .customerName(workoutPlan.getCustomer().getUsername())
            .duration(workoutPlan.getDuration())
            .description(workoutPlan.getDescription())
            .exercises(exerciseResponses)
            .build();
    }

    private ExerciseProgramResponse convertToExerciseResponse(WorkoutPlanExercise workoutPlanExercise) {
        log.debug("Converting exercise to response: {}", workoutPlanExercise.getExercise().getName());
        
        return ExerciseProgramResponse.builder()
            .exerciseId(workoutPlanExercise.getExercise().getId())
            .exerciseName(workoutPlanExercise.getExercise().getName())
            .exerciseDescription(workoutPlanExercise.getExercise().getDescription())
            .sets(workoutPlanExercise.getSets())
            .reps(workoutPlanExercise.getReps())
            .weight(workoutPlanExercise.getWeight())
            .restTime(workoutPlanExercise.getRestTime())
            .orderIndex(workoutPlanExercise.getOrderIndex())
            .description(workoutPlanExercise.getDescription())
            .build();
    }

    // Method helper
    private Pageable buildPageable(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        Sort.Order order = new Sort.Order(Sort.Direction.fromString(direction), sortBy);
        if (ignoreCase) order = order.ignoreCase();
        Sort sort = Sort.by(order);
        return PageRequest.of(page, size, sort);
    }

    private WorkoutProgramPageResponse buildWorkoutProgramPageResponse(Page<WorkoutPlanEntity> workoutPlanPage, List<WorkoutProgramResponse> workoutProgramResponses) {
        WorkoutProgramPageResponse response = new WorkoutProgramPageResponse();
        response.setPageNumber(workoutPlanPage.getNumber());
        response.setPageSize(workoutPlanPage.getSize());
        response.setTotalElements(workoutPlanPage.getTotalElements());
        response.setTotalPages(workoutPlanPage.getTotalPages());
        response.setWorkoutPrograms(workoutProgramResponses);
        return response;
    }
}
