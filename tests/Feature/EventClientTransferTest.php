<?php

namespace Tests\Feature;

use App\Enums\AttendanceStatus;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\EventType;
use App\Models\Exercise;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Moving a client from one event to another, and the list of events offered for the move.
 */
class EventClientTransferTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_guest_cannot_move_a_client_or_see_where_to(): void
    {
        $from = $this->event();
        $to = $this->event();
        $client = Client::factory()->create();
        $this->book($from, $client);

        $this->getJson("/events/{$from->id}/clients/{$client->id}/transfer-targets?date=2026-11-12")->assertUnauthorized();
        $this->postJson("/events/{$from->id}/clients/{$client->id}/transfer", ['target_event_id' => $to->id])->assertUnauthorized();

        $this->assertSame($from->id, EventClient::query()->sole()->event_id);
    }

    public function test_administrator_moves_a_client_with_the_note_and_the_exercises(): void
    {
        $from = $this->event(['capacity' => 4]);
        $to = $this->event(['capacity' => 4]);
        $client = Client::factory()->create();
        $booking = $this->book($from, $client, notes: 'Свои ласты');
        $exercise = Exercise::factory()->create();
        $booking->exercises()->attach($exercise);

        $this->actingAs(User::factory()->admin()->create())
            ->postJson("/events/{$from->id}/clients/{$client->id}/transfer", ['target_event_id' => $to->id])
            ->assertOk()
            ->assertJsonPath('data', [])
            ->assertJsonPath('meta.occupied', 0);

        $moved = EventClient::query()->sole();
        $this->assertSame($booking->id, $moved->id);
        $this->assertSame($to->id, $moved->event_id);
        $this->assertSame(AttendanceStatus::Booked, $moved->status);
        $this->assertSame('Свои ласты', $moved->notes);
        $this->assertSame([$exercise->id], $moved->exercises()->pluck('exercises.id')->all());
    }

    public function test_client_who_cancelled_is_booked_on_the_new_event(): void
    {
        $from = $this->event();
        $to = $this->event();
        $client = Client::factory()->create();
        $this->book($from, $client, AttendanceStatus::Cancelled);

        $this->actingAs(User::factory()->admin()->create())
            ->postJson("/events/{$from->id}/clients/{$client->id}/transfer", ['target_event_id' => $to->id])
            ->assertOk();

        $this->assertSame(AttendanceStatus::Booked, EventClient::query()->where('event_id', $to->id)->sole()->status);
    }

    public function test_instructor_who_leads_both_events_moves_a_client(): void
    {
        $lead = User::factory()->create();
        $from = $this->event(lead: $lead);
        $to = $this->event(lead: $lead);
        $client = Client::factory()->create();
        $this->book($from, $client);

        $this->actingAs($lead)
            ->postJson("/events/{$from->id}/clients/{$client->id}/transfer", ['target_event_id' => $to->id])
            ->assertOk();

        $this->assertSame($to->id, EventClient::query()->sole()->event_id);
    }

    public function test_instructor_cannot_move_a_client_to_an_event_they_do_not_lead_403(): void
    {
        $lead = User::factory()->create();
        $from = $this->event(lead: $lead);
        $to = $this->event();
        $client = Client::factory()->create();
        $this->book($from, $client);

        $this->actingAs($lead)
            ->postJson("/events/{$from->id}/clients/{$client->id}/transfer", ['target_event_id' => $to->id])
            ->assertForbidden();

        $this->assertSame($from->id, EventClient::query()->sole()->event_id);
    }

    public function test_assistant_cannot_move_a_client_out_of_the_event_403(): void
    {
        $assistant = User::factory()->create();
        $from = $this->event(assistants: [$assistant]);
        $client = Client::factory()->create();
        $this->book($from, $client);

        $this->actingAs($assistant)
            ->postJson("/events/{$from->id}/clients/{$client->id}/transfer", ['target_event_id' => $this->event()->id])
            ->assertForbidden();
        $this->actingAs($assistant)
            ->getJson("/events/{$from->id}/clients/{$client->id}/transfer-targets?date=2026-11-12")
            ->assertForbidden();
    }

    public function test_client_is_moved_to_a_planned_event_that_is_already_over(): void
    {
        $this->travelTo('2026-11-20 12:00');
        $from = $this->event(['starts_at' => '2026-11-25 10:00', 'ends_at' => '2026-11-25 11:00']);
        $past = $this->event(['starts_at' => '2026-11-10 10:00', 'ends_at' => '2026-11-10 11:00']);
        $client = Client::factory()->create();
        $this->book($from, $client);

        $this->actingAs(User::factory()->admin()->create())
            ->postJson("/events/{$from->id}/clients/{$client->id}/transfer", ['target_event_id' => $past->id])
            ->assertOk();

        $this->assertSame($past->id, EventClient::query()->sole()->event_id);
    }

    /**
     * @return array<string, array{AttendanceStatus}>
     */
    public static function marked(): array
    {
        return ['attended' => [AttendanceStatus::Attended], 'no show' => [AttendanceStatus::NoShow]];
    }

    #[DataProvider('marked')]
    public function test_client_already_marked_on_the_event_stays_there(AttendanceStatus $status): void
    {
        $from = $this->event();
        $client = Client::factory()->create();
        $this->book($from, $client, $status);

        $this->moveAsAdmin($from, $client, $this->event())
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['target_event_id' => 'Клиент уже отмечен на занятии, перенести его нельзя.']);

        $this->assertSame($from->id, EventClient::query()->sole()->event_id);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function closedEvents(): array
    {
        return ['cancelled' => ['cancelled'], 'done' => ['done']];
    }

    #[DataProvider('closedEvents')]
    public function test_client_is_not_moved_to_an_event_that_is_not_planned(string $state): void
    {
        $from = $this->event();
        $to = Event::factory()->ledBy(User::factory()->create())->{$state}()->create();
        $client = Client::factory()->create();
        $this->book($from, $client);

        $this->moveAsAdmin($from, $client, $to)
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['target_event_id' => 'Перенести можно только на запланированное занятие.']);

        $this->assertSame($from->id, EventClient::query()->sole()->event_id);
    }

    public function test_client_is_not_moved_to_the_same_event(): void
    {
        $event = $this->event();
        $client = Client::factory()->create();
        $this->book($event, $client);

        $this->moveAsAdmin($event, $client, $event)
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['target_event_id' => 'Выберите другое занятие.']);
    }

    public function test_client_is_not_moved_to_an_event_they_are_already_on(): void
    {
        $from = $this->event();
        $to = $this->event();
        $client = Client::factory()->create();
        $this->book($from, $client);
        $this->book($to, $client, AttendanceStatus::Cancelled);

        $this->moveAsAdmin($from, $client, $to)
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['target_event_id' => 'Клиент уже есть в списке этого занятия.']);

        $this->assertSame(1, EventClient::query()->where('event_id', $from->id)->count());
    }

    public function test_client_is_not_moved_to_a_full_event(): void
    {
        $from = $this->event();
        $to = $this->event(['capacity' => 1]);
        $client = Client::factory()->create();
        $this->book($from, $client);
        $this->book($to, Client::factory()->create());

        $this->moveAsAdmin($from, $client, $to)
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['target_event_id' => 'На занятии нет свободных мест.']);

        $this->assertSame($from->id, EventClient::query()->where('client_id', $client->id)->sole()->event_id);
    }

    public function test_place_freed_by_a_cancelled_client_takes_the_moved_one(): void
    {
        $from = $this->event();
        $to = $this->event(['capacity' => 1]);
        $client = Client::factory()->create();
        $this->book($from, $client);
        $this->book($to, Client::factory()->create(), AttendanceStatus::Cancelled);

        $this->moveAsAdmin($from, $client, $to)->assertOk();
    }

    public function test_target_event_is_required_and_must_exist(): void
    {
        $from = $this->event();
        $client = Client::factory()->create();
        $this->book($from, $client);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->postJson("/events/{$from->id}/clients/{$client->id}/transfer", [])
            ->assertJsonValidationErrors(['target_event_id' => 'Выберите занятие.']);
        $this->actingAs($admin)
            ->postJson("/events/{$from->id}/clients/{$client->id}/transfer", ['target_event_id' => 999])
            ->assertJsonValidationErrors(['target_event_id' => 'Занятие не найдено.']);
    }

    public function test_client_who_is_not_on_the_event_is_not_found(): void
    {
        $this->moveAsAdmin($this->event(), Client::factory()->create(), $this->event())->assertNotFound();
    }

    public function test_deleted_client_is_not_moved(): void
    {
        $from = $this->event();
        $client = Client::factory()->create();
        $this->book($from, $client);
        $client->delete();

        $this->moveAsAdmin($from, $client, $this->event())->assertNotFound();

        $this->assertSame($from->id, EventClient::query()->sole()->event_id);
    }

    public function test_list_of_clients_tells_who_can_be_moved_and_by_whom(): void
    {
        $lead = User::factory()->create();
        $assistant = User::factory()->create();
        $event = $this->event(['capacity' => 5], lead: $lead, assistants: [$assistant]);
        $this->book($event, Client::factory()->create(['last_name' => 'А']));
        $this->book($event, Client::factory()->create(['last_name' => 'Б']), AttendanceStatus::Cancelled);
        $this->book($event, Client::factory()->create(['last_name' => 'В']), AttendanceStatus::Attended);
        $deleted = Client::factory()->create(['last_name' => 'Г']);
        $this->book($event, $deleted);
        $deleted->delete();

        $this->actingAs($lead)
            ->getJson("/events/{$event->id}/clients")
            ->assertJsonPath('meta.canTransfer', true)
            ->assertJsonPath('data.0.isTransferable', true)
            ->assertJsonPath('data.1.isTransferable', true)
            ->assertJsonPath('data.2.isTransferable', false)
            ->assertJsonPath('data.3.isTransferable', false);

        $this->actingAs($assistant)
            ->getJson("/events/{$event->id}/clients")
            ->assertJsonPath('meta.canTransfer', false);
    }

    public function test_administrator_is_offered_the_planned_events_of_the_day(): void
    {
        $type = EventType::factory()->create(['name' => 'Погружение у маяка']);
        $lead = User::factory()->create(['name' => 'Анна', 'last_name' => 'Иванова', 'color' => '#dc2626']);
        $from = $this->event(['starts_at' => '2026-11-12 10:00', 'ends_at' => '2026-11-12 11:00']);
        $client = Client::factory()->create();
        $this->book($from, $client);

        $evening = $this->event(['starts_at' => '2026-11-12 18:00', 'ends_at' => '2026-11-12 19:00', 'title' => 'Вечер', 'capacity' => 1], lead: $lead);
        $this->book($evening, Client::factory()->create());
        $morning = $this->event(['starts_at' => '2026-11-12 08:00', 'ends_at' => '2026-11-12 09:00', 'event_type_id' => $type->id, 'location' => 'Дельфин', 'capacity' => null], lead: $lead);
        $withClient = $this->event(['starts_at' => '2026-11-12 12:00', 'ends_at' => '2026-11-12 13:00']);
        $this->book($withClient, $client, AttendanceStatus::Cancelled);
        $overnight = $this->event(['starts_at' => '2026-11-11 23:00', 'ends_at' => '2026-11-12 01:00']);
        Event::factory()->ledBy($lead)->cancelled()->at('2026-11-12 14:00', '2026-11-12 15:00')->create();
        Event::factory()->ledBy($lead)->done()->at('2026-11-12 15:00', '2026-11-12 16:00')->create();
        $this->event(['starts_at' => '2026-11-13 10:00', 'ends_at' => '2026-11-13 11:00']);

        $this->actingAs(User::factory()->admin()->create())
            ->getJson("/events/{$from->id}/clients/{$client->id}/transfer-targets?date=2026-11-12")
            ->assertOk()
            ->assertJsonCount(4, 'data')
            ->assertJsonPath('data.0.id', $overnight->id)
            ->assertJsonPath('data.1', [
                'id' => $morning->id,
                'title' => 'Погружение у маяка',
                'period' => '12.11 08:00–09:00',
                'location' => 'Дельфин',
                'leadName' => $lead->fullName(),
                'color' => '#dc2626',
                'capacity' => null,
                'occupiedPlaces' => 0,
                'isFull' => false,
                'hasClient' => false,
            ])
            ->assertJsonPath('data.2.id', $withClient->id)
            ->assertJsonPath('data.2.hasClient', true)
            ->assertJsonPath('data.3.id', $evening->id)
            ->assertJsonPath('data.3.isFull', true);
    }

    public function test_instructor_is_offered_only_the_events_they_lead(): void
    {
        $lead = User::factory()->create();
        $from = $this->event(['starts_at' => '2026-11-12 10:00', 'ends_at' => '2026-11-12 11:00'], lead: $lead);
        $client = Client::factory()->create();
        $this->book($from, $client);
        $led = $this->event(['starts_at' => '2026-11-12 12:00', 'ends_at' => '2026-11-12 13:00'], lead: $lead);
        $this->event(['starts_at' => '2026-11-12 14:00', 'ends_at' => '2026-11-12 15:00'], assistants: [$lead]);
        $this->event(['starts_at' => '2026-11-12 16:00', 'ends_at' => '2026-11-12 17:00']);

        $this->actingAs($lead)
            ->getJson("/events/{$from->id}/clients/{$client->id}/transfer-targets?date=2026-11-12")
            ->assertOk()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.id', $led->id);
    }

    public function test_day_of_the_offered_events_is_required(): void
    {
        $from = $this->event();
        $client = Client::factory()->create();
        $this->book($from, $client);

        $this->actingAs(User::factory()->admin()->create())
            ->getJson("/events/{$from->id}/clients/{$client->id}/transfer-targets?date=12.11.2026")
            ->assertJsonValidationErrors('date');
    }

    private function moveAsAdmin(Event $from, Client $client, Event $to): TestResponse
    {
        return $this->actingAs(User::factory()->admin()->create())
            ->postJson("/events/{$from->id}/clients/{$client->id}/transfer", ['target_event_id' => $to->id]);
    }

    /**
     * A planned event of a lead instructor.
     *
     * @param  array<string, mixed>  $attributes
     * @param  list<User>  $assistants
     */
    private function event(array $attributes = [], ?User $lead = null, array $assistants = []): Event
    {
        return Event::factory()->ledBy($lead ?? User::factory()->create(), $assistants)->create($attributes);
    }

    private function book(Event $event, Client $client, AttendanceStatus $status = AttendanceStatus::Booked, ?string $notes = null): EventClient
    {
        return EventClient::factory()->forEvent($event)->forClient($client)->create(['status' => $status, 'notes' => $notes]);
    }
}
