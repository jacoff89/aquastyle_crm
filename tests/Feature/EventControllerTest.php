<?php

namespace Tests\Feature;

use App\Enums\EventStatus;
use App\Enums\InstructorRole;
use App\Models\Event;
use App\Models\EventType;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class EventControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_guest_cannot_create_or_edit_events(): void
    {
        $event = Event::factory()->ledBy(User::factory()->create())->create();

        $this->postJson('/events', $this->validPayload())->assertUnauthorized();
        $this->patchJson("/events/{$event->id}", $this->validPayload())->assertUnauthorized();

        $this->assertDatabaseCount('events', 1);
    }

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    #[DataProvider('everyRole')]
    public function test_every_role_creates_an_event(bool $isAdmin): void
    {
        $user = $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
        $type = EventType::factory()->create(['name' => 'Глубокий бассейн']);
        $lead = User::factory()->create(['name' => 'Анна Ведущая', 'color' => '#0891b2']);
        $assistant = User::factory()->create(['name' => 'Борис Помощник']);

        $response = $this->actingAs($user)->postJson('/events', $this->validPayload([
            'event_type_id' => $type->id,
            'title' => '  ',
            'starts_at' => '2026-11-03 10:00',
            'ends_at' => '2026-11-03 11:30',
            'location' => ' Бассейн «Дельфин» ',
            'capacity' => 6,
            'lead_instructor_id' => $lead->id,
            'assistant_ids' => [$assistant->id],
            'notes' => 'Взять ласты',
        ]));

        $response->assertCreated()
            ->assertJsonPath('data.title', 'Глубокий бассейн')
            ->assertJsonPath('data.customTitle', null)
            ->assertJsonPath('data.start', '2026-11-03 10:00')
            ->assertJsonPath('data.end', '2026-11-03 11:30')
            ->assertJsonPath('data.location', 'Бассейн «Дельфин»')
            ->assertJsonPath('data.capacity', 6)
            ->assertJsonPath('data.status', 'planned')
            ->assertJsonPath('data.color', '#0891b2')
            ->assertJsonPath('data.leadInstructorId', $lead->id)
            ->assertJsonPath('data.assistantIds', [$assistant->id])
            ->assertJsonPath('data.instructors.0.name', 'Анна Ведущая')
            ->assertJsonPath('data.instructors.0.role', 'lead')
            ->assertJsonPath('data.instructors.1.name', 'Борис Помощник')
            ->assertJsonPath('data.instructors.1.role', 'assistant');

        $event = Event::query()->sole();
        $this->assertNull($event->title);
        $this->assertSame('2026-11-03 10:00:00', $event->starts_at->format('Y-m-d H:i:s'));
        $this->assertSame(EventStatus::Planned, $event->status);
        $this->assertTrue($event->creator->is($user));
        $this->assertTrue($event->leadInstructor()->is($lead));
        $this->assertSame(InstructorRole::Assistant, $event->instructors->firstWhere('id', $assistant->id)->pivot->role);
    }

    public function test_new_event_is_always_planned(): void
    {
        $this->actingAs($this->admin())
            ->postJson('/events', $this->validPayload(['status' => 'done']))
            ->assertCreated()
            ->assertJsonPath('data.status', 'planned');
    }

    public function test_lead_is_not_also_stored_as_assistant(): void
    {
        $lead = User::factory()->create();

        $this->actingAs($this->admin())
            ->postJson('/events', $this->validPayload(['lead_instructor_id' => $lead->id, 'assistant_ids' => [$lead->id]]))
            ->assertUnprocessable()
            ->assertJsonValidationErrors('assistant_ids.0');

        $this->assertDatabaseCount('events', 0);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidInput(): array
    {
        return [
            'no type' => [['event_type_id' => null], 'event_type_id'],
            'unknown type' => [['event_type_id' => 999], 'event_type_id'],
            'no start' => [['starts_at' => ''], 'starts_at'],
            'start in another format' => [['starts_at' => '03.11.2026 10:00'], 'starts_at'],
            'end before start' => [['ends_at' => '2026-11-03 09:00'], 'ends_at'],
            'end equal to start' => [['ends_at' => '2026-11-03 10:00'], 'ends_at'],
            'longer than a day' => [['ends_at' => '2026-11-04 10:30'], 'ends_at'],
            'zero places' => [['capacity' => 0], 'capacity'],
            'too long title' => [['title' => str_repeat('а', 256)], 'title'],
            'no lead' => [['lead_instructor_id' => null], 'lead_instructor_id'],
            'unknown lead' => [['lead_instructor_id' => 999], 'lead_instructor_id'],
            'assistants not a list' => [['assistant_ids' => 'все'], 'assistant_ids'],
        ];
    }

    /**
     * @param  array<string, mixed>  $override
     */
    #[DataProvider('invalidInput')]
    public function test_invalid_input_is_rejected(array $override, string $field): void
    {
        $this->actingAs($this->admin())
            ->postJson('/events', $this->validPayload($override))
            ->assertUnprocessable()
            ->assertJsonValidationErrors($field);

        $this->assertDatabaseCount('events', 0);
    }

    public function test_event_may_end_the_next_day_within_a_day(): void
    {
        $this->actingAs($this->admin())
            ->postJson('/events', $this->validPayload(['starts_at' => '2026-11-03 21:00', 'ends_at' => '2026-11-04 01:00']))
            ->assertCreated()
            ->assertJsonPath('data.end', '2026-11-04 01:00');
    }

    public function test_hidden_type_cannot_be_chosen_for_a_new_event(): void
    {
        $hidden = EventType::factory()->hidden()->create();

        $this->actingAs($this->admin())
            ->postJson('/events', $this->validPayload(['event_type_id' => $hidden->id]))
            ->assertUnprocessable()
            ->assertJsonValidationErrors('event_type_id');
    }

    public function test_only_active_instructors_can_be_assigned_to_a_new_event(): void
    {
        $inactive = User::factory()->inactive()->create();
        $admin = $this->admin();

        $this->actingAs($admin)
            ->postJson('/events', $this->validPayload(['lead_instructor_id' => $inactive->id]))
            ->assertJsonValidationErrors('lead_instructor_id');

        $this->actingAs($admin)
            ->postJson('/events', $this->validPayload(['lead_instructor_id' => $admin->id]))
            ->assertJsonValidationErrors('lead_instructor_id');

        $this->actingAs($admin)
            ->postJson('/events', $this->validPayload(['assistant_ids' => [$inactive->id]]))
            ->assertJsonValidationErrors('assistant_ids.0');

        $this->assertDatabaseCount('events', 0);
    }

    public function test_administrator_who_teaches_can_lead_and_assist(): void
    {
        $teachingAdmin = User::factory()->adminInstructor()->create();

        $this->actingAs($teachingAdmin)
            ->postJson('/events', $this->validPayload(['lead_instructor_id' => $teachingAdmin->id]))
            ->assertCreated()
            ->assertJsonPath('data.leadInstructorId', $teachingAdmin->id)
            ->assertJsonPath('data.color', $teachingAdmin->color);

        $this->actingAs($teachingAdmin)
            ->postJson('/events', $this->validPayload(['starts_at' => '2026-11-04 10:00', 'ends_at' => '2026-11-04 11:00', 'assistant_ids' => [$teachingAdmin->id]]))
            ->assertCreated();
    }

    public function test_busy_instructor_is_reported_and_event_is_not_saved(): void
    {
        $lead = User::factory()->create(['name' => 'Анна']);
        Event::factory()->ledBy($lead)->at('2026-11-03 10:30', '2026-11-03 12:00')->create(['title' => 'Теория OWD']);

        $this->actingAs($this->admin())
            ->postJson('/events', $this->validPayload([
                'lead_instructor_id' => $lead->id,
                'starts_at' => '2026-11-03 10:00',
                'ends_at' => '2026-11-03 11:00',
            ]))
            ->assertConflict()
            ->assertJsonPath('conflicts.0.instructor', 'Анна')
            ->assertJsonPath('conflicts.0.title', 'Теория OWD')
            ->assertJsonPath('conflicts.0.time', '03.11 10:30–12:00');

        $this->assertDatabaseCount('events', 1);
    }

    public function test_busy_assistant_is_reported_too(): void
    {
        $assistant = User::factory()->create(['name' => 'Борис']);
        Event::factory()->ledBy(User::factory()->create(), [$assistant])->at('2026-11-03 10:00', '2026-11-03 11:00')->create();

        $this->actingAs($this->admin())
            ->postJson('/events', $this->validPayload(['assistant_ids' => [$assistant->id]]))
            ->assertConflict()
            ->assertJsonCount(1, 'conflicts')
            ->assertJsonPath('conflicts.0.instructor', 'Борис');
    }

    public function test_confirmed_conflict_is_saved_anyway(): void
    {
        $lead = User::factory()->create();
        Event::factory()->ledBy($lead)->at('2026-11-03 10:00', '2026-11-03 11:00')->create();

        $this->actingAs($this->admin())
            ->postJson('/events', $this->validPayload(['lead_instructor_id' => $lead->id, 'confirm_conflicts' => true]))
            ->assertCreated();

        $this->assertDatabaseCount('events', 2);
    }

    public function test_back_to_back_and_cancelled_events_are_not_conflicts(): void
    {
        $lead = User::factory()->create();
        Event::factory()->ledBy($lead)->at('2026-11-03 09:00', '2026-11-03 10:00')->create();
        Event::factory()->ledBy($lead)->at('2026-11-03 11:00', '2026-11-03 12:00')->create();
        Event::factory()->ledBy($lead)->cancelled()->at('2026-11-03 10:00', '2026-11-03 11:00')->create();
        Event::factory()->ledBy(User::factory()->create())->at('2026-11-03 10:00', '2026-11-03 11:00')->create();

        $this->actingAs($this->admin())
            ->postJson('/events', $this->validPayload(['lead_instructor_id' => $lead->id]))
            ->assertCreated();
    }

    #[DataProvider('everyRole')]
    public function test_every_role_edits_an_event(bool $isAdmin): void
    {
        $user = $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
        $creator = User::factory()->admin()->create();
        $event = Event::factory()->ledBy(User::factory()->create())->create(['created_by' => $creator->id]);
        $type = EventType::factory()->create();
        $lead = User::factory()->create();

        $this->actingAs($user)
            ->patchJson("/events/{$event->id}", $this->validPayload([
                'event_type_id' => $type->id,
                'title' => 'Ночное погружение',
                'starts_at' => '2026-11-05 20:00',
                'ends_at' => '2026-11-05 22:00',
                'lead_instructor_id' => $lead->id,
                'status' => 'cancelled',
            ]))
            ->assertOk()
            ->assertJsonPath('data.title', 'Ночное погружение')
            ->assertJsonPath('data.status', 'cancelled')
            ->assertJsonPath('data.isCancelled', true)
            ->assertJsonPath('data.leadInstructorId', $lead->id);

        $event->refresh();
        $this->assertSame($type->id, $event->event_type_id);
        $this->assertSame('2026-11-05 20:00', $event->starts_at->format('Y-m-d H:i'));
        $this->assertSame(EventStatus::Cancelled, $event->status);
        $this->assertTrue($event->creator->is($creator));
        $this->assertCount(1, $event->instructors);
    }

    public function test_edit_requires_a_status(): void
    {
        $event = Event::factory()->ledBy(User::factory()->create())->create();

        $this->actingAs($this->admin())
            ->patchJson("/events/{$event->id}", $this->validPayload(['status' => 'unknown']))
            ->assertJsonValidationErrors('status');
    }

    public function test_event_keeps_its_hidden_type_and_deactivated_instructors(): void
    {
        $type = EventType::factory()->create();
        $lead = User::factory()->create();
        $assistant = User::factory()->create();
        $event = Event::factory()->ledBy($lead, [$assistant])->create(['event_type_id' => $type->id]);
        $type->update(['is_active' => false]);
        $lead->update(['is_active' => false]);
        $assistant->update(['is_active' => false]);

        $this->actingAs($this->admin())
            ->patchJson("/events/{$event->id}", $this->validPayload([
                'event_type_id' => $type->id,
                'lead_instructor_id' => $lead->id,
                'assistant_ids' => [$assistant->id],
                'notes' => 'Перенесли',
            ]))
            ->assertOk();

        $this->assertSame('Перенесли', $event->refresh()->notes);
    }

    public function test_moving_onto_a_busy_instructor_asks_for_confirmation(): void
    {
        $lead = User::factory()->create();
        Event::factory()->ledBy($lead)->at('2026-11-03 12:00', '2026-11-03 13:00')->create();
        $event = Event::factory()->ledBy($lead)->at('2026-11-03 10:00', '2026-11-03 11:00')->create();

        $payload = $this->payloadOf($event, ['starts_at' => '2026-11-03 12:30', 'ends_at' => '2026-11-03 13:30']);

        $this->actingAs($this->admin())->patchJson("/events/{$event->id}", $payload)->assertConflict();
        $this->assertSame('10:00', $event->refresh()->starts_at->format('H:i'));

        $this->actingAs($this->admin())->patchJson("/events/{$event->id}", [...$payload, 'confirm_conflicts' => true])->assertOk();
        $this->assertSame('12:30', $event->refresh()->starts_at->format('H:i'));
    }

    public function test_editing_details_of_an_overlapping_event_does_not_warn_again(): void
    {
        $lead = User::factory()->create();
        Event::factory()->ledBy($lead)->at('2026-11-03 10:00', '2026-11-03 11:00')->create();
        $event = Event::factory()->ledBy($lead)->at('2026-11-03 10:30', '2026-11-03 11:30')->create();

        $this->actingAs($this->admin())
            ->patchJson("/events/{$event->id}", $this->payloadOf($event, ['notes' => 'Новая заметка']))
            ->assertOk();
    }

    public function test_event_does_not_conflict_with_itself(): void
    {
        $lead = User::factory()->create();
        $event = Event::factory()->ledBy($lead)->at('2026-11-03 10:00', '2026-11-03 11:00')->create();

        $this->actingAs($this->admin())
            ->patchJson("/events/{$event->id}", $this->payloadOf($event, ['ends_at' => '2026-11-03 11:30']))
            ->assertOk()
            ->assertJsonPath('data.end', '2026-11-03 11:30');
    }

    public function test_restoring_a_cancelled_event_checks_for_conflicts(): void
    {
        $lead = User::factory()->create();
        Event::factory()->ledBy($lead)->at('2026-11-03 10:00', '2026-11-03 11:00')->create();
        $event = Event::factory()->ledBy($lead)->cancelled()->at('2026-11-03 10:00', '2026-11-03 11:00')->create();

        $this->actingAs($this->admin())
            ->patchJson("/events/{$event->id}", $this->payloadOf($event, ['status' => 'planned']))
            ->assertConflict();
    }

    public function test_moving_to_another_instructor_replaces_the_lead(): void
    {
        $old = User::factory()->create();
        $new = User::factory()->create();
        $event = Event::factory()->ledBy($old)->create();

        $this->actingAs($this->admin())
            ->patchJson("/events/{$event->id}", $this->payloadOf($event, ['lead_instructor_id' => $new->id]))
            ->assertOk();

        $this->assertSame([$new->id], $event->refresh()->instructors->pluck('id')->all());
    }

    public function test_unknown_event_is_not_found(): void
    {
        $this->actingAs($this->admin())->patchJson('/events/999', $this->validPayload())->assertNotFound();
    }

    private function admin(): User
    {
        return User::factory()->admin()->create();
    }

    /**
     * @param  array<string, mixed>  $override
     * @return array<string, mixed>
     */
    private function validPayload(array $override = []): array
    {
        return [
            'event_type_id' => array_key_exists('event_type_id', $override) ? null : EventType::factory()->create()->id,
            'title' => null,
            'starts_at' => '2026-11-03 10:00',
            'ends_at' => '2026-11-03 11:00',
            'location' => null,
            'capacity' => null,
            'notes' => null,
            'lead_instructor_id' => array_key_exists('lead_instructor_id', $override) ? null : User::factory()->create()->id,
            'assistant_ids' => [],
            'status' => 'planned',
            ...$override,
        ];
    }

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
            'lead_instructor_id' => $event->leadInstructor()->id,
            'assistant_ids' => $event->instructors->filter(fn (User $user) => $user->pivot->role === InstructorRole::Assistant)->pluck('id')->values()->all(),
            ...$override,
        ];
    }
}
