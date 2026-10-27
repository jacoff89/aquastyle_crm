<?php

namespace Database\Factories;

use App\Enums\AttendanceStatus;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<EventClient>
 */
class EventClientFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'event_id' => Event::factory(),
            'client_id' => Client::factory(),
            'status' => AttendanceStatus::Booked,
            'notes' => null,
        ];
    }

    /**
     * Book the given client.
     */
    public function forClient(Client $client): static
    {
        return $this->state(fn (array $attributes) => [
            'client_id' => $client->id,
        ]);
    }

    /**
     * Book on the given event.
     */
    public function forEvent(Event $event): static
    {
        return $this->state(fn (array $attributes) => [
            'event_id' => $event->id,
        ]);
    }

    /**
     * Indicate that the client came to the event.
     */
    public function attended(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => AttendanceStatus::Attended,
        ]);
    }

    /**
     * Indicate that the client did not come to the event.
     */
    public function noShow(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => AttendanceStatus::NoShow,
        ]);
    }

    /**
     * Indicate that the client cancelled the booking.
     */
    public function cancelled(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => AttendanceStatus::Cancelled,
        ]);
    }
}
