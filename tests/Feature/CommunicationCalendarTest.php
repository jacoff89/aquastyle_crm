<?php

namespace Tests\Feature;

use App\Enums\CommunicationChannel;
use App\Enums\CommunicationStatus;
use App\Models\Client;
use App\Models\Communication;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Carbon;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

/**
 * The calendar of every communication with clients: the page and the communications of the visible period.
 * Only administrators see it.
 */
class CommunicationCalendarTest extends TestCase
{
    use LazilyRefreshDatabase;

    private function communication(User $creator, string $occurredAt, array $attributes = []): Communication
    {
        $communication = Communication::factory()->make(['occurred_at' => $occurredAt, ...$attributes]);
        $communication->creator()->associate($creator);
        $communication->save();

        return $communication;
    }

    public function test_guest_is_redirected_to_login(): void
    {
        $this->get('/communications')->assertRedirect('/login');
        $this->getJson('/communications/events?start=2026-11-02&end=2026-11-08')->assertUnauthorized();
    }

    public function test_instructor_has_no_access(): void
    {
        $this->actingAs(User::factory()->create())->get('/communications')->assertForbidden();
        $this->actingAs(User::factory()->create())->getJson('/communications/events?start=2026-11-02&end=2026-11-08')->assertForbidden();
    }

    public function test_administrator_opens_the_calendar_on_this_month(): void
    {
        Carbon::setTestNow('2026-11-04 09:00');

        $this->actingAs(User::factory()->admin()->create())
            ->get('/communications')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('communications/Index')
                ->where('initialDate', '2026-11-04')
                ->where('initialView', 'month')
                ->where('initialFilters', ['creatorId' => null, 'channel' => null, 'status' => null])
                ->has('channels', count(CommunicationChannel::cases()))
                ->where('statuses', CommunicationStatus::options()));
    }

    public function test_page_lists_every_user_as_a_possible_creator_active_first(): void
    {
        User::factory()->create(['name' => 'Яна']);
        User::factory()->inactive()->create(['name' => 'Антон']);
        $admin = User::factory()->admin()->create(['name' => 'Борис']);

        $this->actingAs($admin)
            ->get('/communications')
            ->assertInertia(fn (Assert $page) => $page
                ->has('creators', 3)
                ->where('creators.0', ['id' => $admin->id, 'name' => 'Борис', 'isActive' => true])
                ->where('creators.1.name', 'Яна')
                ->where('creators.2', fn ($creator) => $creator['name'] === 'Антон' && $creator['isActive'] === false));
    }

    public function test_page_opens_on_the_position_and_filters_from_the_address(): void
    {
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->get("/communications?view=week&date=2026-12-10&creator_id={$admin->id}&channel=phone&status=planned")
            ->assertInertia(fn (Assert $page) => $page
                ->where('initialDate', '2026-12-10')
                ->where('initialView', 'week')
                ->where('initialFilters', ['creatorId' => $admin->id, 'channel' => 'phone', 'status' => 'planned']));
    }

    public function test_stale_or_mistyped_address_opens_without_those_parts(): void
    {
        Carbon::setTestNow('2026-11-04 09:00');

        $this->actingAs(User::factory()->admin()->create())
            ->get('/communications?view=year&date=2026-02-30&creator_id=999&channel=fax&status=lost')
            ->assertInertia(fn (Assert $page) => $page
                ->where('initialDate', '2026-11-04')
                ->where('initialView', 'month')
                ->where('initialFilters', ['creatorId' => null, 'channel' => null, 'status' => null]));
    }

    public function test_returns_communications_of_the_requested_days(): void
    {
        $admin = User::factory()->admin()->create();
        $this->communication($admin, '2026-11-01 23:59', ['notes' => 'До периода']);
        $this->communication($admin, '2026-11-02 00:00', ['notes' => 'Начало']);
        $this->communication($admin, '2026-11-05 12:00', ['notes' => 'Внутри']);
        $this->communication($admin, '2026-11-08 23:59', ['notes' => 'Конец']);
        $this->communication($admin, '2026-11-09 00:00', ['notes' => 'После периода']);

        $this->actingAs($admin)
            ->getJson('/communications/events?start=2026-11-02&end=2026-11-08')
            ->assertOk()
            ->assertJsonCount(3, 'data')
            ->assertJsonPath('data.0.notes', 'Начало')
            ->assertJsonPath('data.1.notes', 'Внутри')
            ->assertJsonPath('data.2.notes', 'Конец');
    }

    public function test_communication_is_described_for_the_calendar(): void
    {
        $admin = User::factory()->admin()->create();
        $creator = User::factory()->create(['name' => 'Анна', 'color' => '#dc2626']);
        $client = Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Пётр', 'middle_name' => null]);
        $communication = $this->communication($creator, '2026-11-05 10:15', [
            'client_id' => $client->id,
            'channel' => CommunicationChannel::Phone,
            'notes' => 'Позвонить насчёт курса',
        ]);

        $this->actingAs($admin)
            ->getJson('/communications/events?start=2026-11-02&end=2026-11-08')
            ->assertJsonPath('data.0', [
                'id' => $communication->id,
                'clientId' => $client->id,
                'clientName' => 'Иванов Пётр',
                'channel' => 'phone',
                'channelLabel' => 'Звонок',
                'status' => 'completed',
                'statusLabel' => 'Выполнена',
                'isPlanned' => false,
                'start' => '2026-11-05 10:15',
                'end' => '2026-11-05 10:45',
                'notes' => 'Позвонить насчёт курса',
                'creatorId' => $creator->id,
                'creatorName' => 'Анна',
                'color' => '#dc2626',
            ]);
    }

    public function test_planned_communication_is_marked_as_planned(): void
    {
        $admin = User::factory()->admin()->create();
        Communication::factory()->planned()->for($admin, 'creator')->create(['occurred_at' => '2026-11-03 09:00']);

        $this->actingAs($admin)
            ->getJson('/communications/events?start=2026-11-02&end=2026-11-08')
            ->assertJsonPath('data.0.status', 'planned')
            ->assertJsonPath('data.0.isPlanned', true);
    }

    public function test_filters_by_creator_and_channel(): void
    {
        $admin = User::factory()->admin()->create();
        $instructor = User::factory()->create();
        $this->communication($admin, '2026-11-03 10:00', ['channel' => CommunicationChannel::Phone, 'notes' => 'Админ, звонок']);
        $this->communication($admin, '2026-11-03 11:00', ['channel' => CommunicationChannel::Messenger, 'notes' => 'Админ, мессенджер']);
        $this->communication($instructor, '2026-11-03 12:00', ['channel' => CommunicationChannel::Phone, 'notes' => 'Инструктор, звонок']);

        $this->actingAs($admin)
            ->getJson("/communications/events?start=2026-11-02&end=2026-11-08&creator_id={$admin->id}")
            ->assertJsonCount(2, 'data')
            ->assertJsonPath('data.0.notes', 'Админ, звонок')
            ->assertJsonPath('data.1.notes', 'Админ, мессенджер');

        $this->getJson('/communications/events?start=2026-11-02&end=2026-11-08&channel=phone')
            ->assertJsonCount(2, 'data')
            ->assertJsonPath('data.0.notes', 'Админ, звонок')
            ->assertJsonPath('data.1.notes', 'Инструктор, звонок');

        $this->getJson("/communications/events?start=2026-11-02&end=2026-11-08&creator_id={$instructor->id}&channel=phone")
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.notes', 'Инструктор, звонок');
    }

    public function test_filters_by_status(): void
    {
        $admin = User::factory()->admin()->create();
        $this->communication($admin, '2026-11-03 10:00', ['notes' => 'Выполнена']);
        $this->communication($admin, '2026-11-03 11:00', ['status' => CommunicationStatus::Planned, 'notes' => 'Планируется']);

        $this->actingAs($admin)
            ->getJson('/communications/events?start=2026-11-02&end=2026-11-08&status=planned')
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.notes', 'Планируется');

        $this->getJson('/communications/events?start=2026-11-02&end=2026-11-08&status=completed')
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.notes', 'Выполнена');
    }

    public function test_communications_of_deleted_clients_are_left_out(): void
    {
        $admin = User::factory()->admin()->create();
        $deleted = $this->communication($admin, '2026-11-03 10:00', ['notes' => 'Удалённый клиент']);
        $deleted->client->delete();
        $this->communication($admin, '2026-11-03 11:00', ['notes' => 'Клиент на месте']);

        $this->actingAs($admin)
            ->getJson('/communications/events?start=2026-11-02&end=2026-11-08')
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.notes', 'Клиент на месте');
    }

    public function test_rejects_wrong_period_and_filters(): void
    {
        $this->actingAs(User::factory()->admin()->create());

        $this->getJson('/communications/events?start=2026-11-08&end=2026-11-02')->assertUnprocessable();
        $this->getJson('/communications/events?start=2026-01-01&end=2026-06-01')->assertUnprocessable();
        $this->getJson('/communications/events?start=2026-11-02&end=2026-11-08&creator_id=999')->assertUnprocessable();
        $this->getJson('/communications/events?start=2026-11-02&end=2026-11-08&channel=fax')->assertUnprocessable();
        $this->getJson('/communications/events?start=2026-11-02&end=2026-11-08&status=lost')->assertUnprocessable();
    }
}
