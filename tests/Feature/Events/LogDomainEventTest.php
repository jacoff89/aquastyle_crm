<?php

namespace Tests\Feature\Events;

use App\Models\Client;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Log;
use Mockery;
use Psr\Log\LoggerInterface;
use Tests\TestCase;

/**
 * Every domain event is written to the "events" log with who, when and what.
 */
class LogDomainEventTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_a_domain_event_is_written_to_the_events_log(): void
    {
        $client = Client::factory()->create(['first_name' => 'Пётр', 'last_name' => 'Иванов', 'phone' => '+7 912 345-67-89', 'middle_name' => null, 'email' => null, 'birth_date' => null, 'notes' => null]);
        $user = User::factory()->create();
        $this->freezeTime();

        $channel = Mockery::mock(LoggerInterface::class);
        $channel->shouldReceive('info')->once()->with('ClientUpdated', [
            'actor' => $user->id,
            'occurred_at' => now()->format('Y-m-d H:i:s'),
            'client' => "Client#{$client->id}",
            'changes' => ['first_name' => ['old' => 'Пётр', 'new' => 'Павел']],
        ]);
        Log::shouldReceive('channel')->with('events')->andReturn($channel);

        $this->actingAs($user)
            ->put("/clients/{$client->id}", ['last_name' => 'Иванов', 'first_name' => 'Павел', 'phone' => '+7 912 345-67-89'])
            ->assertSessionHasNoErrors();
    }
}
