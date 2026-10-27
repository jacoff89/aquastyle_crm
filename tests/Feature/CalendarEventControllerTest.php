<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\EventType;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class CalendarEventControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_returns_events_overlapping_the_requested_days(): void
    {
        $lead = User::factory()->create();
        Event::factory()->ledBy($lead)->at('2026-11-01 23:00', '2026-11-02 01:00')->create(['title' => 'Через полночь в начале']);
        Event::factory()->ledBy($lead)->at('2026-11-04 10:00', '2026-11-04 11:00')->create(['title' => 'Внутри']);
        Event::factory()->ledBy($lead)->at('2026-11-08 22:00', '2026-11-08 23:30')->create(['title' => 'Последний день']);
        Event::factory()->ledBy($lead)->at('2026-11-01 10:00', '2026-11-01 11:00')->create(['title' => 'До периода']);
        Event::factory()->ledBy($lead)->at('2026-11-09 00:00', '2026-11-09 01:00')->create(['title' => 'После периода']);

        $this->actingAs(User::factory()->admin()->create())
            ->getJson('/calendar/events?start=2026-11-02&end=2026-11-08')
            ->assertOk()
            ->assertJsonCount(3, 'data')
            ->assertJsonPath('data.0.title', 'Через полночь в начале')
            ->assertJsonPath('data.1.title', 'Внутри')
            ->assertJsonPath('data.2.title', 'Последний день');
    }

    public function test_event_is_described_for_the_calendar(): void
    {
        $type = EventType::factory()->create(['name' => 'Глубокий бассейн']);
        $lead = User::factory()->create(['name' => 'Анна', 'color' => '#dc2626']);
        $assistant = User::factory()->create(['name' => 'Борис', 'color' => '#16a34a']);
        $event = Event::factory()
            ->ledBy($lead, [$assistant])
            ->at('2026-11-04 10:00', '2026-11-04 11:30')
            ->create(['event_type_id' => $type->id, 'location' => 'Дельфин', 'capacity' => 4, 'notes' => 'Ласты']);

        $this->actingAs(User::factory()->create())
            ->getJson('/calendar/events?start=2026-11-04&end=2026-11-04')
            ->assertExactJson(['data' => [[
                'id' => $event->id,
                'title' => 'Глубокий бассейн',
                'customTitle' => null,
                'eventTypeId' => $type->id,
                'typeName' => 'Глубокий бассейн',
                'start' => '2026-11-04 10:00',
                'end' => '2026-11-04 11:30',
                'location' => 'Дельфин',
                'capacity' => 4,
                'status' => 'planned',
                'statusLabel' => 'Запланировано',
                'isCancelled' => false,
                'notes' => 'Ласты',
                'color' => '#dc2626',
                'leadInstructorId' => $lead->id,
                'assistantIds' => [$assistant->id],
                'instructors' => [
                    ['id' => $lead->id, 'name' => 'Анна', 'color' => '#dc2626', 'role' => 'lead', 'roleLabel' => 'Ведущий'],
                    ['id' => $assistant->id, 'name' => 'Борис', 'color' => '#16a34a', 'role' => 'assistant', 'roleLabel' => 'Помощник'],
                ],
                'isMine' => false,
                'canUpdate' => true,
            ]]]);
    }

    public function test_event_is_marked_as_mine_for_its_lead_and_assistants_only(): void
    {
        $lead = User::factory()->create();
        $assistant = User::factory()->create();
        $other = User::factory()->create();
        Event::factory()->ledBy($lead, [$assistant])->at('2026-11-04 10:00', '2026-11-04 11:00')->create();

        foreach ([[$lead, true], [$assistant, true], [$other, false]] as [$user, $isMine]) {
            $this->actingAs($user)
                ->getJson('/calendar/events?start=2026-11-04&end=2026-11-04')
                ->assertJsonPath('data.0.isMine', $isMine);
        }
    }

    public function test_administrator_sees_own_events_as_mine_only_when_teaching(): void
    {
        $teachingAdmin = User::factory()->adminInstructor()->create();
        $plainAdmin = User::factory()->admin()->create();
        Event::factory()->ledBy($teachingAdmin)->at('2026-11-04 10:00', '2026-11-04 11:00')->create();
        Event::factory()->ledBy(User::factory()->create())->at('2026-11-04 12:00', '2026-11-04 13:00')->create();

        $this->actingAs($teachingAdmin)
            ->getJson('/calendar/events?start=2026-11-04&end=2026-11-04')
            ->assertJsonCount(2, 'data')
            ->assertJsonPath('data.0.isMine', true)
            ->assertJsonPath('data.1.isMine', false);

        $this->actingAs($plainAdmin)
            ->getJson('/calendar/events?start=2026-11-04&end=2026-11-04')
            ->assertJsonPath('data.0.isMine', false)
            ->assertJsonPath('data.1.isMine', false);
    }

    public function test_instructor_sees_every_event_not_only_their_own(): void
    {
        $instructor = User::factory()->create();
        Event::factory()->ledBy($instructor)->at('2026-11-04 10:00', '2026-11-04 11:00')->create();
        Event::factory()->ledBy(User::factory()->create())->at('2026-11-04 12:00', '2026-11-04 13:00')->create();

        $this->actingAs($instructor)
            ->getJson('/calendar/events?start=2026-11-04&end=2026-11-04')
            ->assertJsonCount(2, 'data');
    }

    public function test_events_can_be_narrowed_to_one_instructor_lead_or_assistant(): void
    {
        $anna = User::factory()->create(['name' => 'Анна']);
        $boris = User::factory()->create(['name' => 'Борис']);
        Event::factory()->ledBy($anna)->at('2026-11-04 10:00', '2026-11-04 11:00')->create(['title' => 'Ведёт Анна']);
        Event::factory()->ledBy($boris, [$anna])->at('2026-11-04 12:00', '2026-11-04 13:00')->create(['title' => 'Анна помогает']);
        Event::factory()->ledBy($boris)->at('2026-11-04 14:00', '2026-11-04 15:00')->create(['title' => 'Только Борис']);

        $response = $this->actingAs(User::factory()->admin()->create())
            ->getJson("/calendar/events?start=2026-11-04&end=2026-11-04&instructor_id={$anna->id}")
            ->assertOk()
            ->assertJsonCount(2, 'data')
            ->assertJsonPath('data.0.title', 'Ведёт Анна')
            ->assertJsonPath('data.1.title', 'Анна помогает');

        $this->assertCount(2, $response->json('data.1.instructors'), 'The event keeps all of its instructors.');
    }

    public function test_events_can_be_narrowed_to_one_event_type(): void
    {
        $pool = EventType::factory()->create(['name' => 'Глубокий бассейн']);
        $theory = EventType::factory()->create(['name' => 'Лекция']);
        $lead = User::factory()->create();
        Event::factory()->ledBy($lead)->at('2026-11-04 10:00', '2026-11-04 11:00')->create(['event_type_id' => $pool->id]);
        Event::factory()->ledBy($lead)->at('2026-11-04 12:00', '2026-11-04 13:00')->create(['event_type_id' => $theory->id]);

        $this->actingAs(User::factory()->admin()->create())
            ->getJson("/calendar/events?start=2026-11-04&end=2026-11-04&event_type_id={$theory->id}")
            ->assertOk()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.typeName', 'Лекция');
    }

    public function test_instructor_and_type_filters_work_together(): void
    {
        $type = EventType::factory()->create();
        $otherType = EventType::factory()->create();
        $anna = User::factory()->create();
        $boris = User::factory()->create();
        Event::factory()->ledBy($anna)->at('2026-11-04 10:00', '2026-11-04 11:00')->create(['event_type_id' => $type->id, 'title' => 'Подходит']);
        Event::factory()->ledBy($anna)->at('2026-11-04 12:00', '2026-11-04 13:00')->create(['event_type_id' => $otherType->id]);
        Event::factory()->ledBy($boris)->at('2026-11-04 14:00', '2026-11-04 15:00')->create(['event_type_id' => $type->id]);

        $this->actingAs(User::factory()->admin()->create())
            ->getJson("/calendar/events?start=2026-11-04&end=2026-11-04&instructor_id={$anna->id}&event_type_id={$type->id}")
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.title', 'Подходит');
    }

    public function test_empty_filters_mean_no_filtering(): void
    {
        Event::factory()->ledBy(User::factory()->create())->at('2026-11-04 10:00', '2026-11-04 11:00')->create();

        $this->actingAs(User::factory()->admin()->create())
            ->getJson('/calendar/events?start=2026-11-04&end=2026-11-04&instructor_id=&event_type_id=')
            ->assertOk()
            ->assertJsonCount(1, 'data');
    }

    public function test_deactivated_instructor_and_hidden_type_can_still_be_filtered_by(): void
    {
        $former = User::factory()->inactive()->create();
        $hiddenType = EventType::factory()->hidden()->create();
        Event::factory()->ledBy($former)->at('2026-11-04 10:00', '2026-11-04 11:00')->create(['event_type_id' => $hiddenType->id]);

        $this->actingAs(User::factory()->admin()->create())
            ->getJson("/calendar/events?start=2026-11-04&end=2026-11-04&instructor_id={$former->id}&event_type_id={$hiddenType->id}")
            ->assertOk()
            ->assertJsonCount(1, 'data');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidFilters(): array
    {
        return [
            'unknown instructor' => ['instructor_id=999999'],
            'not a number instructor' => ['instructor_id=anna'],
            'unknown type' => ['event_type_id=999999'],
            'not a number type' => ['event_type_id=pool'],
            'list instead of a value' => ['instructor_id[]=1'],
        ];
    }

    #[DataProvider('invalidFilters')]
    public function test_invalid_filter_is_rejected(string $filter): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->getJson("/calendar/events?start=2026-11-04&end=2026-11-04&{$filter}")
            ->assertUnprocessable();
    }

    public function test_user_without_the_instructor_role_is_not_a_valid_instructor_filter(): void
    {
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->getJson("/calendar/events?start=2026-11-04&end=2026-11-04&instructor_id={$admin->id}")
            ->assertUnprocessable()
            ->assertJsonValidationErrors('instructor_id');
    }

    public function test_cancelled_events_are_included(): void
    {
        Event::factory()->ledBy(User::factory()->create())->cancelled()->at('2026-11-04 10:00', '2026-11-04 11:00')->create();

        $this->actingAs(User::factory()->admin()->create())
            ->getJson('/calendar/events?start=2026-11-04&end=2026-11-04')
            ->assertJsonPath('data.0.status', 'cancelled')
            ->assertJsonPath('data.0.statusLabel', 'Отменено')
            ->assertJsonPath('data.0.isCancelled', true);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidPeriods(): array
    {
        return [
            'no dates' => [''],
            'wrong format' => ['start=02.11.2026&end=08.11.2026'],
            'end before start' => ['start=2026-11-08&end=2026-11-02'],
        ];
    }

    #[DataProvider('invalidPeriods')]
    public function test_invalid_period_is_rejected(string $query): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->getJson("/calendar/events?{$query}")
            ->assertUnprocessable();
    }

    public function test_too_long_period_is_rejected(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->getJson('/calendar/events?start=2026-01-01&end=2026-12-31')
            ->assertUnprocessable();
    }
}
