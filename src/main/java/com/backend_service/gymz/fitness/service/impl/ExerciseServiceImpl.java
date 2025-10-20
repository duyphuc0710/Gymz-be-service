package com.backend_service.gymz.fitness.service.impl;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.backend_service.gymz.fitness.dto.request.exercise.ExerciseCreateRequest;
import com.backend_service.gymz.fitness.dto.request.exercise.ExerciseUpdateRequest;
import com.backend_service.gymz.fitness.dto.response.exercise.ExercisePageResponse;
import com.backend_service.gymz.fitness.dto.response.exercise.ExerciseResponse;
import com.backend_service.gymz.fitness.model.ExerciseEntity;
import com.backend_service.gymz.fitness.repository.ExerciseRepository;
import com.backend_service.gymz.fitness.service.ExerciseService;

import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = "EXERCISE-SERVICE")
@RequiredArgsConstructor
@Transactional
public class ExerciseServiceImpl implements ExerciseService {
    private final ExerciseRepository exerciseRepository;
    
    @Override
    public ExerciseResponse save(ExerciseCreateRequest request) {
        log.info("Creating new exercise with name: {}", request.getName());
        
        ExerciseEntity exercise = new ExerciseEntity();
        exercise.setName(request.getName());
        exercise.setDescription(request.getDescription());
        
        ExerciseEntity savedExercise = exerciseRepository.save(exercise);
        log.info("Exercise created successfully with ID: {}", savedExercise.getId());
        
        return convertToResponse(savedExercise);
    }

    @Override
    public ExerciseResponse findById(Long id) {
        log.info("Getting exercise by ID: {}", id);
        
        ExerciseEntity exercise = getExerciseEntity(id);
        return convertToResponse(exercise);
    }

    @Override
    public ExerciseResponse update(Long id, ExerciseUpdateRequest request) {
        log.info("Updating exercise with ID: {}", id);
        
        ExerciseEntity exercise = getExerciseEntity(id);
        exercise.setName(request.getName());
        exercise.setDescription(request.getDescription());
        
        ExerciseEntity updatedExercise = exerciseRepository.save(exercise);
        log.info("Exercise updated successfully with ID: {}", updatedExercise.getId());
        
        return convertToResponse(updatedExercise);
    }

    @Override
    public void deleteById(Long id) {
     log.info("Deleting exercise with ID: {}", id);
        
        if (!exerciseRepository.existsById(id)) {
            throw new EntityNotFoundException("Exercise not found with ID: " + id);
        }
        
        exerciseRepository.deleteById(id);
        log.info("Exercise deleted successfully with ID: {}", id);
    }

    @Override
    public ExercisePageResponse findAll(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        log.info("Getting exercises with paging");

        Pageable pageable = buildPageable(page, size, sortBy, direction, ignoreCase);
        Page<ExerciseEntity> exercisePage = exerciseRepository.findAll(pageable);

        List<ExerciseResponse> exerciseResponses = exercisePage.getContent().stream()
            .map(this::convertToResponse)
            .toList();

        return buildExercisePageResponse(exercisePage, exerciseResponses);
    }

    private ExerciseEntity getExerciseEntity(Long id) {
        return exerciseRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Exercise not found with ID: " + id));
    }
     private ExerciseResponse convertToResponse(ExerciseEntity exercise) {
        return ExerciseResponse.builder()
                .id(exercise.getId())
                .name(exercise.getName())
                .description(exercise.getDescription())
                .build();
    }

    // Method helper
    private Pageable buildPageable(int page, int size, String sortBy, String direction, boolean ignoreCase) {
        Sort.Order order = new Sort.Order(Sort.Direction.fromString(direction), sortBy);
        if (ignoreCase) order = order.ignoreCase();
        Sort sort = Sort.by(order);
        return PageRequest.of(page, size, sort);
    }

    private ExercisePageResponse buildExercisePageResponse(Page<ExerciseEntity> exercisePage, List<ExerciseResponse> exerciseResponses) {
        ExercisePageResponse response = new ExercisePageResponse();
        response.setPageNumber(exercisePage.getNumber());
        response.setPageSize(exercisePage.getSize());
        response.setTotalElements(exercisePage.getTotalElements());
        response.setTotalPages(exercisePage.getTotalPages());
        response.setExercises(exerciseResponses);
        return response;
    }
}
