<?php

namespace Database\Factories;

use App\Enums\CommunicationChannel;
use App\Enums\CommunicationStatus;
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
            'status' => CommunicationStatus::Completed,
            'occurred_at' => fake()->dateTimeBetween('-1 month'),
            'notes' => fake()->sentence(),
        ];
    }

    /**
     * A contact that is still ahead.
     */
    public function planned(): static
    {
        return $this->state(fn (): array => ['status' => CommunicationStatus::Planned]);
    }
}
