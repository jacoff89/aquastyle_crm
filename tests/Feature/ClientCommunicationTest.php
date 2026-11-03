<?php

namespace Tests\Feature;

use App\Enums\CommunicationChannel;
use App\Models\Client;
use App\Models\Communication;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Communications on the client's card: listed after the visit history, added, edited and deleted.
 */
class ClientCommunicationTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    private function user(bool $isAdmin): User
    {
        return $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
    }

    /**
     * @return array<string, string>
     */
    private function payload(): array
    {
        return ['channel' => 'phone', 'occurred_at' => '2026-11-03T14:30', 'notes' => 'Перезвонить в пятницу'];
    }

    public function test_card_lists_only_this_clients_communications_latest_first(): void
    {
        $client = Client::factory()->create();
        $older = Communication::factory()->for($client)->create(['occurred_at' => '2026-10-01 10:00']);
        $newer = Communication::factory()->for($client)->create(['occurred_at' => '2026-10-02 10:00', 'channel' => CommunicationChannel::Messenger]);
        Communication::factory()->create();

        $this->actingAs(User::factory()->create())
            ->get("/clients/{$client->id}")
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->has('communications', 2)
                ->where('communications.0.id', $newer->id)
                ->where('communications.0.channelLabel', 'Мессенджер')
                ->where('communications.0.occurredAt', '2026-10-02T10:00')
                ->where('communications.1.id', $older->id)
                ->has('communicationChannels', count(CommunicationChannel::cases())));
    }

    #[DataProvider('everyRole')]
    public function test_every_role_adds_a_communication(bool $isAdmin): void
    {
        $client = Client::factory()->create();
        $user = $this->user($isAdmin);

        $this->actingAs($user)
            ->post("/clients/{$client->id}/communications", $this->payload())
            ->assertRedirect("/clients/{$client->id}")
            ->assertSessionHas('status');

        $this->assertDatabaseHas('communications', [
            'client_id' => $client->id,
            'created_by' => $user->id,
            'channel' => 'phone',
            'occurred_at' => '2026-11-03 14:30:00',
            'notes' => 'Перезвонить в пятницу',
        ]);
    }

    public function test_communication_needs_valid_channel_time_and_notes(): void
    {
        $client = Client::factory()->create();

        $this->actingAs(User::factory()->create())
            ->post("/clients/{$client->id}/communications", ['channel' => 'pigeon', 'occurred_at' => 'вчера', 'notes' => '   '])
            ->assertSessionHasErrors(['channel', 'occurred_at', 'notes']);

        $this->assertDatabaseCount('communications', 0);
    }

    public function test_administrator_edits_and_deletes_any_communication(): void
    {
        $communication = Communication::factory()->create(['created_by' => User::factory()]);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->patch("/communications/{$communication->id}", [...$this->payload(), 'channel' => 'in_person'])
            ->assertRedirect("/clients/{$communication->client_id}");

        $communication->refresh();
        $this->assertSame(CommunicationChannel::InPerson, $communication->channel);
        $this->assertSame('Перезвонить в пятницу', $communication->notes);

        $this->actingAs($admin)->delete("/communications/{$communication->id}")->assertRedirect("/clients/{$communication->client_id}");
        $this->assertModelMissing($communication);
    }

    public function test_instructor_edits_and_deletes_own_communication(): void
    {
        $instructor = User::factory()->create();
        $communication = Communication::factory()->create(['created_by' => $instructor->id]);

        $this->actingAs($instructor)
            ->patch("/communications/{$communication->id}", $this->payload())
            ->assertRedirect("/clients/{$communication->client_id}");

        $this->assertSame('Перезвонить в пятницу', $communication->fresh()->notes);

        $this->actingAs($instructor)->delete("/communications/{$communication->id}")->assertRedirect("/clients/{$communication->client_id}");
        $this->assertModelMissing($communication);
    }

    public function test_instructor_can_not_edit_or_delete_someone_elses_communication(): void
    {
        $communication = Communication::factory()->create(['created_by' => User::factory()]);
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->patch("/communications/{$communication->id}", $this->payload())->assertForbidden();
        $this->actingAs($instructor)->delete("/communications/{$communication->id}")->assertForbidden();

        $this->assertModelExists($communication);
        $this->assertNotSame('Перезвонить в пятницу', $communication->fresh()->notes);
    }

    public function test_card_marks_which_communications_the_viewer_can_manage(): void
    {
        $instructor = User::factory()->create();
        $client = Client::factory()->create();
        $own = Communication::factory()->for($client)->create(['created_by' => $instructor->id, 'occurred_at' => '2026-10-02 10:00']);
        Communication::factory()->for($client)->create(['created_by' => User::factory(), 'occurred_at' => '2026-10-01 10:00']);

        $this->actingAs($instructor)->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page
                ->where('communications.0.id', $own->id)
                ->where('communications.0.canManage', true)
                ->where('communications.1.canManage', false));

        $this->actingAs(User::factory()->admin()->create())->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page
                ->where('communications.0.canManage', true)
                ->where('communications.1.canManage', true));
    }

    public function test_guest_is_redirected_to_login(): void
    {
        $communication = Communication::factory()->create();

        $this->post("/clients/{$communication->client_id}/communications", $this->payload())->assertRedirect('/login');
        $this->patch("/communications/{$communication->id}", $this->payload())->assertRedirect('/login');
        $this->delete("/communications/{$communication->id}")->assertRedirect('/login');
    }
}
