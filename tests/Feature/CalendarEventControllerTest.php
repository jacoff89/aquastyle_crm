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
                'canUpdate' => true,
            ]]]);
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
