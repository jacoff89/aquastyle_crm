<?php

namespace Database\Factories;

use App\Enums\EquipmentStatus;
use App\Models\Equipment;
use App\Models\Location;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Equipment>
 */
class EquipmentFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->randomElement(['Регулятор', 'Компенсатор плавучести', 'Гидрокостюм', 'Баллон 12 л', 'Маска', 'Ласты']),
            'inventory_number' => fake()->unique()->numerify('INV-#####'),
            'size' => fake()->optional()->randomElement(['S', 'M', 'L', 'XL']),
            'status' => EquipmentStatus::InUse,
            'location_id' => null,
            'instructor_id' => null,
            'notes' => null,
        ];
    }

    /**
     * Keep the item at the given location.
     */
    public function at(Location $location): static
    {
        return $this->state(fn (array $attributes) => [
            'location_id' => $location->id,
        ]);
    }

    /**
     * Assign the item to the given instructor.
     */
    public function assignedTo(User $instructor): static
    {
        return $this->state(fn (array $attributes) => [
            'instructor_id' => $instructor->id,
        ]);
    }
}
