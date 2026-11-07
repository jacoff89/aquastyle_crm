<?php

namespace Tests\Feature\Events;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Enums\InstructorRole;
use App\Events\Bookings\BookingExercisesChanged;
use App\Events\Bookings\BookingStatusChanged;
use App\Events\Bookings\BookingUpdated;
use App\Events\Bookings\ClientBooked;
use App\Events\CalendarEvents\CalendarEventCancelled;
use App\Events\CalendarEvents\CalendarEventCompleted;
use App\Events\CalendarEvents\CalendarEventCreated;
use App\Events\CalendarEvents\CalendarEventInstructorsChanged;
use App\Events\CalendarEvents\CalendarEventReopened;
use App\Events\CalendarEvents\CalendarEventRescheduled;
use App\Events\CalendarEvents\CalendarEventUpdated;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\EventType;
use App\Models\Exercise;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Event as EventFacade;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Creating and editing events in the calendar, and booking clients on them, announces domain events.
 */
class CalendarEventEventsTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * The event as the calendar sends it back after a move or an edit.
     *
     * @param  array<string, mixed>  $override
     * @return array<string, mixed>
     */
    private function payloadOf(Event $event, array $override = []): array
    {
        $event->load('instructors');

        return [
            'event_type_id' => $event->event_type_id,
            'title' => $event->title,
            'starts_at' => $event->starts_at->format('Y-m-d H:i'),
            'ends_at' => $event->ends_at->format('Y-m-d H:i'),
            'location' => $event->location,
            'capacity' => $event->capacity,
            'notes' => $event->notes,
            'status' => $event->status->value,
            'lead_instructor_id' => $event->leadInstructor()?->id,
            'assistant_ids' => $event->instructors->filter(fn (User $user) => $user->pivot->role === InstructorRole::Assistant)->pluck('id')->values()->all(),
            'confirm_conflicts' => true,
            ...$override,
        ];
    }

    public function test_a_new_event_is_announced_with_its_instructors_attached(): void
    {
        $user = User::factory()->create();
        $lead = User::factory()->create();
        $assistant = User::factory()->create();
        $type = EventType::factory()->create();
        EventFacade::fake([CalendarEventCreated::class, CalendarEventInstructorsChanged::class]);

        $this->actingAs($user)->postJson('/events', [
            'event_type_id' => $type->id,
            'starts_at' => '2026-11-03 10:00',
            'ends_at' => '2026-11-03 11:00',
            'lead_instructor_id' => $lead->id,
            'assistant_ids' => [$assistant->id],
        ])->assertCreated();

        $event = Event::sole();
        EventFacade::assertDispatched(CalendarEventCreated::class, fn (CalendarEventCreated $created): bool => $created->event->is($event) && $created->actor->is($user));
        EventFacade::assertDispatched(CalendarEventInstructorsChanged::class, fn (CalendarEventInstructorsChanged $changed): bool => $changed->event->is($event)
            && $changed->attachedInstructorIds === [$lead->id, $assistant->id]
            && $changed->detachedInstructorIds === []
            && $changed->roleChangedInstructorIds === []);
    }

    public function test_an_event_without_instructors_announces_no_instructor_change(): void
    {
        $type = EventType::factory()->create();
        EventFacade::fake([CalendarEventCreated::class, CalendarEventInstructorsChanged::class]);

        $this->actingAs(User::factory()->create())->postJson('/events', [
            'event_type_id' => $type->id,
            'starts_at' => '2026-11-03 10:00',
            'ends_at' => '2026-11-03 11:00',
        ])->assertCreated();

        EventFacade::assertDispatchedTimes(CalendarEventCreated::class, 1);
        EventFacade::assertNotDispatched(CalendarEventInstructorsChanged::class);
    }

    public function test_an_event_held_back_by_an_instructor_conflict_is_not_announced(): void
    {
        $lead = User::factory()->create();
        Event::factory()->at('2026-11-03 10:00', '2026-11-03 11:00')->ledBy($lead)->create();
        $type = EventType::factory()->create();
        EventFacade::fake([CalendarEventCreated::class, CalendarEventInstructorsChanged::class]);

        $this->actingAs(User::factory()->create())->postJson('/events', [
            'event_type_id' => $type->id,
            'starts_at' => '2026-11-03 10:30',
            'ends_at' => '2026-11-03 11:30',
            'lead_instructor_id' => $lead->id,
        ])->assertConflict();

        EventFacade::assertNotDispatched(CalendarEventCreated::class);
        EventFacade::assertNotDispatched(CalendarEventInstructorsChanged::class);
    }

    public function test_moving_an_event_announces_the_change_and_the_previous_time(): void
    {
        $event = Event::factory()->at('2026-11-03 10:00', '2026-11-03 11:00')->create();
        $user = User::factory()->create();
        EventFacade::fake([CalendarEventUpdated::class, CalendarEventRescheduled::class]);

        $this->actingAs($user)
            ->patchJson("/events/{$event->id}", $this->payloadOf($event, ['starts_at' => '2026-11-04 12:00', 'ends_at' => '2026-11-04 13:00']))
            ->assertOk();

        EventFacade::assertDispatched(CalendarEventUpdated::class, fn (CalendarEventUpdated $updated): bool => $updated->changes->attributes() === ['starts_at', 'ends_at']
            && $updated->actor->is($user));
        EventFacade::assertDispatched(CalendarEventRescheduled::class, fn (CalendarEventRescheduled $rescheduled): bool => $rescheduled->event->is($event)
            && $rescheduled->previousStartsAt->format('Y-m-d H:i') === '2026-11-03 10:00'
            && $rescheduled->previousEndsAt->format('Y-m-d H:i') === '2026-11-03 11:00');
    }

    public function test_editing_only_the_notes_is_not_a_reschedule(): void
    {
        $event = Event::factory()->create();
        EventFacade::fake([CalendarEventUpdated::class, CalendarEventRescheduled::class, CalendarEventCancelled::class]);

        $this->actingAs(User::factory()->create())->patchJson("/events/{$event->id}", $this->payloadOf($event, ['notes' => 'Взять грузы']))->assertOk();

        EventFacade::assertDispatched(CalendarEventUpdated::class, fn (CalendarEventUpdated $updated): bool => $updated->changes->attributes() === ['notes']);
        EventFacade::assertNotDispatched(CalendarEventRescheduled::class);
        EventFacade::assertNotDispatched(CalendarEventCancelled::class);
    }

    public function test_saving_an_event_without_changes_is_not_announced(): void
    {
        $event = Event::factory()->ledBy(User::factory()->create())->create();
        EventFacade::fake([CalendarEventUpdated::class, CalendarEventInstructorsChanged::class]);

        $this->actingAs(User::factory()->create())->patchJson("/events/{$event->id}", $this->payloadOf($event))->assertOk();

        EventFacade::assertNotDispatched(CalendarEventUpdated::class);
        EventFacade::assertNotDispatched(CalendarEventInstructorsChanged::class);
    }

    /**
     * @return array<string, array{EventStatus, EventStatus, class-string}>
     */
    public static function statusChanges(): array
    {
        return [
            'cancelled' => [EventStatus::Planned, EventStatus::Cancelled, CalendarEventCancelled::class],
            'completed' => [EventStatus::Planned, EventStatus::Done, CalendarEventCompleted::class],
            'reopened after cancelling' => [EventStatus::Cancelled, EventStatus::Planned, CalendarEventReopened::class],
            'reopened after completing' => [EventStatus::Done, EventStatus::Planned, CalendarEventReopened::class],
        ];
    }

    /**
     * @param  class-string<CalendarEventCancelled|CalendarEventCompleted|CalendarEventReopened>  $expected
     */
    #[DataProvider('statusChanges')]
    public function test_a_new_status_is_announced_by_its_own_event(EventStatus $from, EventStatus $to, string $expected): void
    {
        $event = Event::factory()->create(['status' => $from]);
        $user = User::factory()->create();
        $statusEvents = [CalendarEventCancelled::class, CalendarEventCompleted::class, CalendarEventReopened::class];
        EventFacade::fake($statusEvents);

        $this->actingAs($user)->patchJson("/events/{$event->id}", $this->payloadOf($event, ['status' => $to->value]))->assertOk();

        EventFacade::assertDispatched($expected, fn (CalendarEventCancelled|CalendarEventCompleted|CalendarEventReopened $changed): bool => $changed->event->is($event)
            && $changed->previousStatus === $from
            && $changed->actor->is($user));

        foreach (array_diff($statusEvents, [$expected]) as $other) {
            EventFacade::assertNotDispatched($other);
        }
    }

    public function test_changing_instructors_announces_who_was_put_on_taken_off_and_switched(): void
    {
        $oldLead = User::factory()->create();
        $leaving = User::factory()->create();
        $newcomer = User::factory()->create();
        $event = Event::factory()->ledBy($oldLead, [$leaving])->create();
        EventFacade::fake([CalendarEventInstructorsChanged::class]);

        $this->actingAs(User::factory()->create())
            ->patchJson("/events/{$event->id}", $this->payloadOf($event, ['lead_instructor_id' => $newcomer->id, 'assistant_ids' => [$oldLead->id]]))
            ->assertOk();

        EventFacade::assertDispatched(CalendarEventInstructorsChanged::class, fn (CalendarEventInstructorsChanged $changed): bool => $changed->attachedInstructorIds === [$newcomer->id]
            && $changed->detachedInstructorIds === [$leaving->id]
            && $changed->roleChangedInstructorIds === [$oldLead->id]);
    }

    public function test_booking_a_client_announces_the_booking(): void
    {
        $event = Event::factory()->create();
        $client = Client::factory()->create();
        $user = User::factory()->create();
        EventFacade::fake([ClientBooked::class]);

        $this->actingAs($user)->postJson("/events/{$event->id}/clients", ['client_id' => $client->id])->assertCreated();

        EventFacade::assertDispatched(ClientBooked::class, fn (ClientBooked $booked): bool => $booked->booking->is(EventClient::sole())
            && $booked->actor->is($user));
    }

    public function test_a_refused_booking_is_not_announced(): void
    {
        $event = Event::factory()->cancelled()->create();
        $client = Client::factory()->create();
        EventFacade::fake([ClientBooked::class]);

        $this->actingAs(User::factory()->create())->postJson("/events/{$event->id}/clients", ['client_id' => $client->id])->assertUnprocessable();

        EventFacade::assertNotDispatched(ClientBooked::class);
    }

    public function test_marking_attendance_announces_the_change_and_the_previous_status(): void
    {
        $booking = EventClient::factory()->create();
        $admin = User::factory()->admin()->create();
        EventFacade::fake([BookingUpdated::class, BookingStatusChanged::class]);

        $this->actingAs($admin)
            ->patchJson("/events/{$booking->event_id}/clients/{$booking->client_id}", ['status' => 'attended'])
            ->assertOk();

        EventFacade::assertDispatched(BookingUpdated::class, fn (BookingUpdated $updated): bool => $updated->booking->is($booking)
            && $updated->changes->toArray() === ['status' => ['old' => 'booked', 'new' => 'attended']]);
        EventFacade::assertDispatched(BookingStatusChanged::class, fn (BookingStatusChanged $changed): bool => $changed->booking->is($booking)
            && $changed->booking->status === AttendanceStatus::Attended
            && $changed->previousStatus === AttendanceStatus::Booked
            && $changed->actor->is($admin));
    }

    public function test_editing_only_the_note_of_a_booking_does_not_announce_a_status_change(): void
    {
        $booking = EventClient::factory()->create();
        EventFacade::fake([BookingUpdated::class, BookingStatusChanged::class]);

        $this->actingAs(User::factory()->admin()->create())
            ->patchJson("/events/{$booking->event_id}/clients/{$booking->client_id}", ['status' => 'booked', 'notes' => 'Нужны ласты'])
            ->assertOk();

        EventFacade::assertDispatched(BookingUpdated::class, fn (BookingUpdated $updated): bool => $updated->changes->attributes() === ['notes']);
        EventFacade::assertNotDispatched(BookingStatusChanged::class);
    }

    public function test_attaching_and_taking_off_exercises_is_announced(): void
    {
        $booking = EventClient::factory()->create();
        $kept = Exercise::factory()->offeredFor($booking->event->type)->create();
        $removed = Exercise::factory()->offeredFor($booking->event->type)->create();
        $added = Exercise::factory()->offeredFor($booking->event->type)->create();
        $booking->exercises()->attach([$kept->id, $removed->id]);
        $url = "/events/{$booking->event_id}/clients/{$booking->client_id}";
        EventFacade::fake([BookingExercisesChanged::class]);

        $this->actingAs(User::factory()->admin()->create())
            ->patchJson($url, ['status' => 'booked', 'exercise_ids' => [$kept->id, $added->id]])
            ->assertOk();
        $this->patchJson($url, ['status' => 'booked', 'exercise_ids' => [$kept->id, $added->id]])->assertOk();

        EventFacade::assertDispatchedTimes(BookingExercisesChanged::class, 1);
        EventFacade::assertDispatched(BookingExercisesChanged::class, fn (BookingExercisesChanged $changed): bool => $changed->booking->is($booking)
            && $changed->attachedExerciseIds === [$added->id]
            && $changed->detachedExerciseIds === [$removed->id]);
    }
}
