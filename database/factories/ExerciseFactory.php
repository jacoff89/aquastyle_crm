<?php

namespace Database\Factories;

use App\Models\EventType;
use App\Models\Exercise;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Exercise>
 */
class ExerciseFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->unique()->words(3, true),
            'is_active' => true,
        ];
    }

    /**
     * Offer the exercise for events of the given types.
     */
    public function offeredFor(EventType ...$eventTypes): static
    {
        return $this->afterCreating(function (Exercise $exercise) use ($eventTypes): void {
            $exercise->eventTypes()->attach(array_map(fn (EventType $eventType): int => $eventType->id, $eventTypes));
        });
    }

    /**
     * Indicate that the exercise is hidden from new attachments.
     */
    public function hidden(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }
}
