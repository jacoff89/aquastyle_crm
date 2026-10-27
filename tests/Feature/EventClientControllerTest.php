<?php

namespace Tests\Feature;

use App\Enums\AttendanceStatus;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class EventClientControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_guest_cannot_see_or_change_the_clients_of_an_event(): void
    {
        $event = $this->event();
        $client = Client::factory()->create();
        $this->book($event, $client);

        $this->getJson("/events/{$event->id}/clients")->assertUnauthorized();
        $this->postJson("/events/{$event->id}/clients", ['client_id' => $client->id])->assertUnauthorized();
        $this->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended'])->assertUnauthorized();

        $this->assertSame(AttendanceStatus::Booked, EventClient::query()->sole()->status);
    }

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    #[DataProvider('everyRole')]
    public function test_every_role_sees_the_clients_of_an_event_ordered_by_name(bool $isAdmin): void
    {
        $event = $this->event(['capacity' => 5]);
        $this->book($event, Client::factory()->create(['last_name' => 'Петров', 'first_name' => 'Пётр', 'phone' => '+7 912 000-00-01']));
        $this->book($event, Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Борис', 'phone' => '+7 912 000-00-02']), AttendanceStatus::Cancelled);
        $this->book($event, Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Анна', 'middle_name' => 'Сергеевна', 'phone' => '+7 912 000-00-03']), AttendanceStatus::Attended, 'Свой гидрокостюм');
        $removed = Client::factory()->create(['last_name' => 'Сидоров', 'first_name' => 'Олег', 'phone' => '+7 912 000-00-04']);
        $this->book($event, $removed, AttendanceStatus::NoShow);
        $removed->delete();
        $this->book($this->event(), Client::factory()->create(['last_name' => 'Чужой']));

        $this->actingAs($this->user($isAdmin))
            ->getJson("/events/{$event->id}/clients")
            ->assertOk()
            ->assertJsonCount(4, 'data')
            ->assertJsonPath('data.0.name', 'Иванов Анна Сергеевна')
            ->assertJsonPath('data.0.phone', '+7 912 000-00-03')
            ->assertJsonPath('data.0.status', 'attended')
            ->assertJsonPath('data.0.statusLabel', 'Пришёл')
            ->assertJsonPath('data.0.isAttendanceMark', true)
            ->assertJsonPath('data.0.notes', 'Свой гидрокостюм')
            ->assertJsonPath('data.0.isDeleted', false)
            ->assertJsonPath('data.1.name', 'Иванов Борис')
            ->assertJsonPath('data.1.status', 'cancelled')
            ->assertJsonPath('data.1.isAttendanceMark', false)
            ->assertJsonPath('data.2.name', 'Петров Пётр')
            ->assertJsonPath('data.2.status', 'booked')
            ->assertJsonPath('data.3.name', 'Сидоров Олег')
            ->assertJsonPath('data.3.isDeleted', true)
            ->assertJsonPath('meta.capacity', 5)
            ->assertJsonPath('meta.occupied', 2)
            ->assertJsonPath('meta.canManage', true);
    }

    public function test_list_of_an_event_without_clients_is_empty(): void
    {
        $event = $this->event(['capacity' => null]);

        $this->actingAs($this->user())
            ->getJson("/events/{$event->id}/clients")
            ->assertOk()
            ->assertJsonPath('data', [])
            ->assertJsonPath('meta.capacity', null)
            ->assertJsonPath('meta.occupied', 0);
    }

    public function test_unknown_event_is_not_found(): void
    {
        $this->actingAs($this->user())->getJson('/events/999/clients')->assertNotFound();
        $this->actingAs($this->user())->postJson('/events/999/clients', ['client_id' => 1])->assertNotFound();
    }

    #[DataProvider('everyRole')]
    public function test_every_role_books_a_client(bool $isAdmin): void
    {
        $event = $this->event(['capacity' => 4]);
        $client = Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Анна']);

        $this->actingAs($this->user($isAdmin))
            ->postJson("/events/{$event->id}/clients", ['client_id' => $client->id, 'notes' => 'Нужны ласты 42'])
            ->assertCreated()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.clientId', $client->id)
            ->assertJsonPath('data.0.name', 'Иванов Анна')
            ->assertJsonPath('data.0.status', 'booked')
            ->assertJsonPath('data.0.notes', 'Нужны ласты 42')
            ->assertJsonPath('meta.occupied', 1);

        $this->assertDatabaseHas('event_client', [
            'event_id' => $event->id,
            'client_id' => $client->id,
            'status' => 'booked',
            'notes' => 'Нужны ласты 42',
        ]);
    }

    public function test_client_is_booked_without_a_note(): void
    {
        $event = $this->event();
        $client = Client::factory()->create();

        $this->actingAs($this->user())
            ->postJson("/events/{$event->id}/clients", ['client_id' => $client->id])
            ->assertCreated()
            ->assertJsonPath('data.0.notes', null);
    }

    public function test_client_can_be_booked_on_several_events(): void
    {
        $client = Client::factory()->create();
        $first = $this->event();
        $second = $this->event();

        $this->actingAs($this->user())->postJson("/events/{$first->id}/clients", ['client_id' => $client->id])->assertCreated();
        $this->actingAs($this->user())->postJson("/events/{$second->id}/clients", ['client_id' => $client->id])->assertCreated();

        $this->assertDatabaseCount('event_client', 2);
    }

    public function test_client_cannot_be_booked_twice_even_after_cancelling(): void
    {
        $event = $this->event(['capacity' => null]);
        $booked = Client::factory()->create();
        $cancelled = Client::factory()->create();
        $this->book($event, $booked);
        $this->book($event, $cancelled, AttendanceStatus::Cancelled);

        foreach ([$booked, $cancelled] as $client) {
            $this->actingAs($this->user())
                ->postJson("/events/{$event->id}/clients", ['client_id' => $client->id])
                ->assertUnprocessable()
                ->assertJsonValidationErrors('client_id');
        }

        $this->assertDatabaseCount('event_client', 2);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidBooking(): array
    {
        return [
            'no client' => [['client_id' => null], 'client_id'],
            'unknown client' => [['client_id' => 999], 'client_id'],
            'client is not a number' => [['client_id' => 'Иванов'], 'client_id'],
            'too long note' => [['notes' => str_repeat('а', 2001)], 'notes'],
        ];
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    #[DataProvider('invalidBooking')]
    public function test_invalid_booking_is_rejected(array $payload, string $field): void
    {
        $event = $this->event();
        $client = Client::factory()->create();

        $this->actingAs($this->user())
            ->postJson("/events/{$event->id}/clients", ['client_id' => $client->id, ...$payload])
            ->assertUnprocessable()
            ->assertJsonValidationErrors($field);

        $this->assertDatabaseCount('event_client', 0);
    }

    public function test_deleted_client_cannot_be_booked(): void
    {
        $event = $this->event();
        $client = Client::factory()->create();
        $client->delete();

        $this->actingAs($this->user())
            ->postJson("/events/{$event->id}/clients", ['client_id' => $client->id])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('client_id');
    }

    public function test_full_event_takes_no_more_clients(): void
    {
        $event = $this->event(['capacity' => 2]);
        $this->book($event, Client::factory()->create());
        $this->book($event, Client::factory()->create(), AttendanceStatus::Attended);
        $late = Client::factory()->create();

        $this->actingAs($this->user())
            ->postJson("/events/{$event->id}/clients", ['client_id' => $late->id])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['client_id' => 'На занятии нет свободных мест.']);

        $this->assertDatabaseCount('event_client', 2);
    }

    public function test_clients_who_cancelled_or_did_not_come_free_their_places(): void
    {
        $event = $this->event(['capacity' => 2]);
        $this->book($event, Client::factory()->create(), AttendanceStatus::Cancelled);
        $this->book($event, Client::factory()->create(), AttendanceStatus::NoShow);
        $admin = $this->user();

        $this->actingAs($admin)
            ->postJson("/events/{$event->id}/clients", ['client_id' => Client::factory()->create()->id])
            ->assertCreated()
            ->assertJsonPath('meta.occupied', 1);

        $this->actingAs($admin)
            ->postJson("/events/{$event->id}/clients", ['client_id' => Client::factory()->create()->id])
            ->assertCreated()
            ->assertJsonPath('meta.occupied', 2);

        $this->actingAs($admin)
            ->postJson("/events/{$event->id}/clients", ['client_id' => Client::factory()->create()->id])
            ->assertUnprocessable();
    }

    public function test_event_without_a_capacity_takes_any_number_of_clients(): void
    {
        $event = $this->event(['capacity' => null]);

        foreach (range(1, 15) as $ignored) {
            $this->book($event, Client::factory()->create());
        }

        $this->actingAs($this->user())
            ->postJson("/events/{$event->id}/clients", ['client_id' => Client::factory()->create()->id])
            ->assertCreated()
            ->assertJsonPath('meta.occupied', 16);
    }

    public function test_cancelled_event_takes_no_clients(): void
    {
        $event = $this->event(['capacity' => null], cancelled: true);
        $client = Client::factory()->create();

        $this->actingAs($this->user())
            ->postJson("/events/{$event->id}/clients", ['client_id' => $client->id])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('client_id');

        $this->assertDatabaseCount('event_client', 0);
    }

    #[DataProvider('everyRole')]
    public function test_every_role_cancels_and_restores_a_booking(bool $isAdmin): void
    {
        $event = $this->event(['capacity' => 3]);
        $client = Client::factory()->create();
        $this->book($event, $client);
        $user = $this->user($isAdmin);

        $this->actingAs($user)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'cancelled'])
            ->assertOk()
            ->assertJsonPath('data.0.status', 'cancelled')
            ->assertJsonPath('data.0.statusLabel', 'Отменил')
            ->assertJsonPath('meta.occupied', 0);

        $this->actingAs($user)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked'])
            ->assertOk()
            ->assertJsonPath('data.0.status', 'booked')
            ->assertJsonPath('meta.occupied', 1);
    }

    public function test_administrator_marks_who_came_and_who_did_not(): void
    {
        $event = $this->event(['capacity' => 3]);
        $came = Client::factory()->create();
        $absent = Client::factory()->create();
        $this->book($event, $came);
        $this->book($event, $absent);
        $admin = $this->user();

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$came->id}", ['status' => 'attended'])
            ->assertOk()
            ->assertJsonPath('meta.occupied', 2);

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$absent->id}", ['status' => 'no_show'])
            ->assertOk()
            ->assertJsonPath('meta.occupied', 1);

        $this->assertSame(AttendanceStatus::Attended, $this->statusOf($event, $came));
        $this->assertSame(AttendanceStatus::NoShow, $this->statusOf($event, $absent));
    }

    public function test_note_is_changed_only_when_it_is_sent(): void
    {
        $event = $this->event();
        $client = Client::factory()->create();
        $this->book($event, $client, notes: 'Первая заметка');
        $admin = $this->user();

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked'])
            ->assertOk()
            ->assertJsonPath('data.0.notes', 'Первая заметка');

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'notes' => 'Вторая заметка'])
            ->assertOk()
            ->assertJsonPath('data.0.notes', 'Вторая заметка');

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'notes' => ''])
            ->assertOk()
            ->assertJsonPath('data.0.notes', null);

        $this->assertNull(EventClient::query()->sole()->notes);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidChange(): array
    {
        return [
            'no status' => [[], 'status'],
            'unknown status' => [['status' => 'late'], 'status'],
            'too long note' => [['status' => 'booked', 'notes' => str_repeat('а', 2001)], 'notes'],
        ];
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    #[DataProvider('invalidChange')]
    public function test_invalid_change_is_rejected(array $payload, string $field): void
    {
        $event = $this->event();
        $client = Client::factory()->create();
        $this->book($event, $client);

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", $payload)
            ->assertUnprocessable()
            ->assertJsonValidationErrors($field);

        $this->assertSame(AttendanceStatus::Booked, $this->statusOf($event, $client));
    }

    public function test_client_who_is_not_on_the_event_is_not_found(): void
    {
        $event = $this->event();
        $other = $this->event();
        $client = Client::factory()->create();
        $this->book($other, $client);

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended'])
            ->assertNotFound();

        $this->assertSame(AttendanceStatus::Booked, $this->statusOf($other, $client));
    }

    public function test_booking_of_a_deleted_client_can_still_be_corrected(): void
    {
        $event = $this->event();
        $client = Client::factory()->create();
        $this->book($event, $client);
        $client->delete();

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended'])
            ->assertOk()
            ->assertJsonPath('data.0.isDeleted', true)
            ->assertJsonPath('data.0.status', 'attended');
    }

    public function test_bringing_a_client_back_needs_a_free_place(): void
    {
        $event = $this->event(['capacity' => 1]);
        $left = Client::factory()->create();
        $stays = Client::factory()->create();
        $this->book($event, $left, AttendanceStatus::Cancelled);
        $this->book($event, $stays);
        $admin = $this->user();

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$left->id}", ['status' => 'booked'])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['status' => 'На занятии нет свободных мест.']);

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$left->id}", ['status' => 'attended'])
            ->assertUnprocessable();

        $this->assertSame(AttendanceStatus::Cancelled, $this->statusOf($event, $left));

        $this->actingAs($admin)->patchJson("/events/{$event->id}/clients/{$stays->id}", ['status' => 'cancelled'])->assertOk();
        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$left->id}", ['status' => 'booked'])
            ->assertOk()
            ->assertJsonPath('meta.occupied', 1);
    }

    public function test_client_who_keeps_the_place_can_be_marked_on_a_full_event(): void
    {
        $event = $this->event(['capacity' => 1]);
        $client = Client::factory()->create();
        $this->book($event, $client);

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended'])
            ->assertOk();

        $this->assertSame(AttendanceStatus::Attended, $this->statusOf($event, $client));
    }

    public function test_statuses_of_a_cancelled_event_are_frozen(): void
    {
        $event = $this->event(['capacity' => null], cancelled: true);
        $client = Client::factory()->create();
        $this->book($event, $client);
        $admin = $this->user();

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended'])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('status');

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'notes' => 'Перенесём на другой день'])
            ->assertOk()
            ->assertJsonPath('data.0.notes', 'Перенесём на другой день');

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'cancelled'])
            ->assertOk();

        $this->assertSame(AttendanceStatus::Cancelled, $this->statusOf($event, $client));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function instructorRoles(): array
    {
        return ['lead' => ['lead'], 'assistant' => ['assistant']];
    }

    #[DataProvider('instructorRoles')]
    public function test_instructor_of_the_event_marks_attendance(string $part): void
    {
        $instructor = User::factory()->create();
        $other = User::factory()->create();
        $event = $this->event(['capacity' => null], lead: $part === 'lead' ? $instructor : $other, assistants: $part === 'lead' ? [] : [$instructor]);
        $client = Client::factory()->create();
        $this->book($event, $client);

        $this->actingAs($instructor)
            ->getJson("/events/{$event->id}/clients")
            ->assertJsonPath('meta.canMarkAttendance', true);

        $this->actingAs($instructor)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended'])
            ->assertOk();

        $this->actingAs($instructor)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'no_show'])
            ->assertOk();

        $this->assertSame(AttendanceStatus::NoShow, $this->statusOf($event, $client));
    }

    public function test_administrator_marks_attendance_on_any_event(): void
    {
        $event = $this->event(['capacity' => null]);
        $client = Client::factory()->create();
        $this->book($event, $client);
        $admin = $this->user();

        $this->actingAs($admin)
            ->getJson("/events/{$event->id}/clients")
            ->assertJsonPath('meta.canMarkAttendance', true);

        $this->actingAs($admin)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended'])
            ->assertOk();
    }

    public function test_administrator_who_teaches_marks_attendance_on_other_instructors_events(): void
    {
        $teachingAdmin = User::factory()->adminInstructor()->create();
        $event = $this->event(['capacity' => null]);
        $client = Client::factory()->create();
        $this->book($event, $client);

        $this->actingAs($teachingAdmin)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended'])
            ->assertOk();
    }

    public function test_instructor_of_another_event_cannot_record_attendance(): void
    {
        $outsider = User::factory()->create();
        $event = $this->event(['capacity' => null]);
        $client = Client::factory()->create();
        $this->book($event, $client);

        $this->actingAs($outsider)
            ->getJson("/events/{$event->id}/clients")
            ->assertOk()
            ->assertJsonPath('meta.canManage', true)
            ->assertJsonPath('meta.canMarkAttendance', false);

        foreach (['attended', 'no_show'] as $status) {
            $this->actingAs($outsider)
                ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => $status])
                ->assertForbidden();
        }

        $this->assertSame(AttendanceStatus::Booked, $this->statusOf($event, $client));
    }

    public function test_instructor_of_another_event_cannot_undo_a_recorded_mark(): void
    {
        $outsider = User::factory()->create();
        $event = $this->event(['capacity' => null]);
        $client = Client::factory()->create();
        $this->book($event, $client, AttendanceStatus::Attended);

        foreach (['booked', 'cancelled'] as $status) {
            $this->actingAs($outsider)
                ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => $status])
                ->assertForbidden();
        }

        $this->actingAs($outsider)
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended', 'notes' => 'Исправление'])
            ->assertForbidden();

        $this->assertSame(AttendanceStatus::Attended, $this->statusOf($event, $client));
        $this->assertNull(EventClient::query()->sole()->notes);
    }

    public function test_instructor_of_another_event_still_books_clients_and_cancels_bookings(): void
    {
        $outsider = User::factory()->create();
        $event = $this->event(['capacity' => null]);
        $client = Client::factory()->create();

        $this->actingAs($outsider)->postJson("/events/{$event->id}/clients", ['client_id' => $client->id])->assertCreated();
        $this->actingAs($outsider)->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'cancelled'])->assertOk();

        $this->assertSame(AttendanceStatus::Cancelled, $this->statusOf($event, $client));
    }

    private function user(bool $isAdmin = true): User
    {
        return $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
    }

    /**
     * An event of a lead instructor, planned unless said otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @param  list<User>  $assistants
     */
    private function event(array $attributes = [], bool $cancelled = false, ?User $lead = null, array $assistants = []): Event
    {
        $factory = Event::factory()->ledBy($lead ?? User::factory()->create(), $assistants);

        return ($cancelled ? $factory->cancelled() : $factory)->create($attributes);
    }

    private function book(Event $event, Client $client, AttendanceStatus $status = AttendanceStatus::Booked, ?string $notes = null): EventClient
    {
        return EventClient::factory()->forEvent($event)->forClient($client)->create(['status' => $status, 'notes' => $notes]);
    }

    private function statusOf(Event $event, Client $client): AttendanceStatus
    {
        return EventClient::query()->where('event_id', $event->id)->where('client_id', $client->id)->sole()->status;
    }
}
