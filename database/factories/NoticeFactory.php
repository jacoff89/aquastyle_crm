<?php

namespace Database\Factories;

use App\Models\Notice;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Notice>
 */
class NoticeFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'type' => 'ClientCreated',
            'message' => 'Новый клиент: '.fake()->lastName().' '.fake()->firstName(),
            'url' => '/clients',
            'url_for_concerned' => null,
            'actor_id' => null,
            'data' => [],
            'created_at' => now(),
        ];
    }

    /**
     * Make the notice concern the given users.
     */
    public function concerning(User ...$users): static
    {
        return $this->afterCreating(function (Notice $notice) use ($users): void {
            $notice->recipients()->attach(array_map(fn (User $user): int => $user->id, $users));
        });
    }

    /**
     * Mark the notice as read by the given user.
     */
    public function readBy(User $user): static
    {
        return $this->afterCreating(function (Notice $notice) use ($user): void {
            $notice->markAsReadBy($user);
        });
    }
}
