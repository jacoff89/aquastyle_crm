<?php

namespace Database\Factories;

use App\Enums\EventStatus;
use App\Models\Event;
use App\Models\EventType;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Carbon;

/**
 * @extends Factory<Event>
 */
class EventFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $startsAt = Carbon::today()
            ->addDays(fake()->numberBetween(0, 13))
            ->setTime(fake()->numberBetween(8, 19), fake()->randomElement([0, 30]));

        return [
            'title' => null,
            'event_type_id' => EventType::factory(),
            'starts_at' => $startsAt,
            'ends_at' => $startsAt->copy()->addMinutes(fake()->randomElement([60, 90, 120])),
            'location' => fake()->optional()->randomElement(['Бассейн «Дельфин»', 'Учебный класс', 'Озеро Увильды']),
            'capacity' => fake()->optional()->numberBetween(2, 12),
            'status' => EventStatus::Planned,
            'notes' => null,
        ];
    }

    /**
     * Place the event at the given time.
     */
    public function at(string $startsAt, string $endsAt): static
    {
        return $this->state(fn (array $attributes) => [
            'starts_at' => Carbon::parse($startsAt),
            'ends_at' => Carbon::parse($endsAt),
        ]);
    }

    /**
     * Give the event a lead instructor and, optionally, assistants.
     *
     * @param  list<User>  $assistants
     */
    public function ledBy(User $lead, array $assistants = []): static
    {
        return $this->afterCreating(function (Event $event) use ($lead, $assistants): void {
            $event->assignInstructors($lead->id, array_map(fn (User $assistant): int => $assistant->id, $assistants));
        });
    }

    /**
     * Indicate that the event was cancelled.
     */
    public function cancelled(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => EventStatus::Cancelled,
        ]);
    }

    /**
     * Indicate that the event has taken place.
     */
    public function done(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => EventStatus::Done,
        ]);
    }
}
