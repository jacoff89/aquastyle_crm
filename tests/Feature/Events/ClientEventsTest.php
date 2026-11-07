<?php

namespace Tests\Feature\Events;

use App\Events\Clients\ClientCreated;
use App\Events\Clients\ClientDeleted;
use App\Events\Clients\ClientUpdated;
use App\Events\Communications\CommunicationCreated;
use App\Events\Communications\CommunicationDeleted;
use App\Events\Communications\CommunicationUpdated;
use App\Models\Client;
use App\Models\Communication;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Event;
use Tests\TestCase;

/**
 * Adding, editing and deleting clients and their communications announces domain events.
 */
class ClientEventsTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * @return array<string, string>
     */
    private function clientPayload(): array
    {
        return ['last_name' => 'Иванов', 'first_name' => 'Пётр', 'phone' => '+7 912 345-67-89'];
    }

    public function test_adding_a_client_announces_it_with_the_actor(): void
    {
        $user = User::factory()->create();
        Event::fake([ClientCreated::class]);

        $this->actingAs($user)->post('/clients', $this->clientPayload())->assertSessionHasNoErrors();

        Event::assertDispatched(ClientCreated::class, fn (ClientCreated $event): bool => $event->client->is(Client::sole())
            && $event->actor->is($user));
    }

    public function test_adding_a_client_from_the_calendar_announces_it_too(): void
    {
        Event::fake([ClientCreated::class]);

        $this->actingAs(User::factory()->create())->postJson('/clients', $this->clientPayload())->assertCreated();

        Event::assertDispatchedTimes(ClientCreated::class, 1);
    }

    public function test_a_rejected_client_is_not_announced(): void
    {
        Event::fake([ClientCreated::class]);

        $this->actingAs(User::factory()->create())->post('/clients', [])->assertSessionHasErrors();

        Event::assertNotDispatched(ClientCreated::class);
    }

    public function test_editing_a_client_announces_what_changed(): void
    {
        $client = Client::factory()->create(['last_name' => 'Петров', 'first_name' => 'Пётр', 'phone' => '+7 912 345-67-89', 'middle_name' => null, 'email' => null, 'birth_date' => null, 'notes' => null]);
        $user = User::factory()->create();
        Event::fake([ClientUpdated::class]);

        $this->actingAs($user)->put("/clients/{$client->id}", $this->clientPayload())->assertSessionHasNoErrors();

        Event::assertDispatched(ClientUpdated::class, fn (ClientUpdated $event): bool => $event->client->is($client)
            && $event->changes->toArray() === ['last_name' => ['old' => 'Петров', 'new' => 'Иванов']]
            && $event->actor->is($user));
    }

    public function test_saving_a_client_without_changes_is_not_announced(): void
    {
        $client = Client::factory()->create([...$this->clientPayload(), 'middle_name' => null, 'email' => null, 'birth_date' => null, 'notes' => null]);
        Event::fake([ClientUpdated::class]);

        $this->actingAs(User::factory()->create())->put("/clients/{$client->id}", $this->clientPayload())->assertSessionHasNoErrors();

        Event::assertNotDispatched(ClientUpdated::class);
    }

    public function test_deleting_a_client_announces_it(): void
    {
        $client = Client::factory()->create();
        $admin = User::factory()->admin()->create();
        Event::fake([ClientDeleted::class]);

        $this->actingAs($admin)->delete("/clients/{$client->id}")->assertRedirect('/clients');

        Event::assertDispatched(ClientDeleted::class, fn (ClientDeleted $event): bool => $event->client->is($client) && $event->actor->is($admin));
    }

    public function test_a_client_that_may_not_be_deleted_is_not_announced(): void
    {
        $client = Client::factory()->create();
        Event::fake([ClientDeleted::class]);

        $this->actingAs(User::factory()->create())->delete("/clients/{$client->id}")->assertForbidden();

        Event::assertNotDispatched(ClientDeleted::class);
    }

    public function test_communications_announce_adding_editing_and_deleting(): void
    {
        $client = Client::factory()->create();
        $user = User::factory()->create();
        Event::fake([CommunicationCreated::class, CommunicationUpdated::class, CommunicationDeleted::class]);

        $this->actingAs($user)->post("/clients/{$client->id}/communications", ['channel' => 'phone', 'occurred_at' => '2026-11-03T14:30', 'notes' => 'Перезвонить'])
            ->assertSessionHasNoErrors();
        $communication = Communication::sole();

        $this->patch("/communications/{$communication->id}", ['channel' => 'messenger', 'occurred_at' => '2026-11-03T14:30', 'notes' => 'Перезвонить'])
            ->assertSessionHasNoErrors();
        $this->delete("/communications/{$communication->id}")->assertRedirect();

        Event::assertDispatched(CommunicationCreated::class, fn (CommunicationCreated $event): bool => $event->communication->is($communication) && $event->actor->is($user));
        Event::assertDispatched(CommunicationUpdated::class, fn (CommunicationUpdated $event): bool => $event->changes->toArray() === ['channel' => ['old' => 'phone', 'new' => 'messenger']]);
        Event::assertDispatched(CommunicationDeleted::class, fn (CommunicationDeleted $event): bool => $event->snapshot['id'] === $communication->id
            && $event->snapshot['notes'] === 'Перезвонить'
            && $event->client->is($client)
            && $event->actor->is($user));
    }
}
