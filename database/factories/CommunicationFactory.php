<?php

namespace Database\Factories;

use App\Enums\CommunicationChannel;
use App\Models\Client;
use App\Models\Communication;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Communication>
 */
class CommunicationFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'client_id' => Client::factory(),
            'channel' => fake()->randomElement(CommunicationChannel::cases()),
            'occurred_at' => fake()->dateTimeBetween('-1 month'),
            'notes' => fake()->sentence(),
        ];
    }
}
