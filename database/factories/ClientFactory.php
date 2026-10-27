<?php

namespace Database\Factories;

use App\Models\Client;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Client>
 */
class ClientFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'last_name' => fake()->lastName(),
            'first_name' => fake()->firstName(),
            'middle_name' => null,
            'phone' => fake()->unique()->numerify('+7 9## ###-##-##'),
            'email' => null,
            'birth_date' => null,
            'notes' => null,
        ];
    }

    /**
     * Fill in the optional fields too.
     */
    public function complete(): static
    {
        return $this->state(fn (array $attributes) => [
            'middle_name' => fake()->middleName(),
            'email' => fake()->unique()->safeEmail(),
            'birth_date' => fake()->dateTimeBetween('-60 years', '-10 years')->format('Y-m-d'),
            'notes' => fake()->sentence(),
        ]);
    }
}
