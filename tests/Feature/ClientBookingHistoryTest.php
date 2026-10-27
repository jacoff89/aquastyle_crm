<?php

namespace Tests\Feature;

use App\Enums\AttendanceStatus;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\EventType;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Carbon;
use Inertia\Testing\AssertableInertia as Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * The client card: classes the client is booked on and the history of their visits.
 */
class ClientBookingHistoryTest extends TestCase
{
    use LazilyRefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(Carbon::parse('2026-11-10 12:00'));
    }

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    #[DataProvider('everyRole')]
    public function test_every_role_sees_upcoming_classes_soonest_first(bool $isAdmin): void
    {
        $client = Client::factory()->create();
        $lead = User::factory()->create(['name' => 'Анна Ведущая']);
        $pool = EventType::query()->where('name', 'Бассейн')->firstOrFail();
        $later = $this->event($lead, $pool->id, '2026-11-12 10:00', '2026-11-12 11:30', ['location' => 'Бассейн «Дельфин»']);
        $sooner = $this->event($lead, $pool->id, '2026-11-11 09:00', '2026-11-11 10:00', ['title' => 'Теория OWD']);
        $inProgress = $this->event($lead, $pool->id, '2026-11-10 11:00', '2026-11-10 13:00');
        $this->book($later, $client);
        $this->book($sooner, $client);
        $this->book($inProgress, $client);

        $this->actingAs($this->user($isAdmin))
            ->get("/clients/{$client->id}")
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('clients/Show')
                ->has('upcoming', 3)
                ->where('upcoming.0.eventId', $inProgress->id)
                ->where('upcoming.1.eventId', $sooner->id)
                ->where('upcoming.1.title', 'Теория OWD')
                ->where('upcoming.2.eventId', $later->id)
                ->where('upcoming.2.title', 'Бассейн')
                ->where('upcoming.2.dateLabel', '12.11.2026')
                ->where('upcoming.2.timeLabel', '10:00–11:30')
                ->where('upcoming.2.location', 'Бассейн «Дельфин»')
                ->where('upcoming.2.leadInstructor', 'Анна Ведущая')
                ->where('upcoming.2.status', 'booked')
                ->where('upcoming.2.statusLabel', 'Записан')
                ->where('upcoming.2.isEventCancelled', false)
                ->where('upcoming.2.calendarUrl', route('calendar', ['view' => 'day', 'date' => '2026-11-12']))
                ->has('history', 0)
                ->where('historyTotal', 0));
    }

    public function test_history_holds_everything_that_is_not_upcoming_latest_first(): void
    {
        $client = Client::factory()->create();
        $lead = User::factory()->create();
        $type = EventType::factory()->create();

        $noShow = $this->event($lead, $type->id, '2026-11-01 10:00', '2026-11-01 11:00');
        $attended = $this->event($lead, $type->id, '2026-11-03 10:00', '2026-11-03 11:00');
        $unmarked = $this->event($lead, $type->id, '2026-11-05 10:00', '2026-11-05 11:00');
        $cancelledEvent = $this->event($lead, $type->id, '2026-11-15 10:00', '2026-11-15 11:00', cancelled: true);
        $leftEarly = $this->event($lead, $type->id, '2026-11-20 10:00', '2026-11-20 11:00');
        $this->book($noShow, $client, AttendanceStatus::NoShow);
        $this->book($attended, $client, AttendanceStatus::Attended);
        $this->book($unmarked, $client);
        $this->book($cancelledEvent, $client);
        $this->book($leftEarly, $client, AttendanceStatus::Cancelled);

        $this->actingAs($this->user())
            ->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page
                ->has('upcoming', 0)
                ->has('history', 5)
                ->where('historyTotal', 5)
                ->where('history.0.eventId', $leftEarly->id)
                ->where('history.0.status', 'cancelled')
                ->where('history.0.statusLabel', 'Отменил')
                ->where('history.1.eventId', $cancelledEvent->id)
                ->where('history.1.isEventCancelled', true)
                ->where('history.2.eventId', $unmarked->id)
                ->where('history.2.status', 'booked')
                ->where('history.3.eventId', $attended->id)
                ->where('history.3.status', 'attended')
                ->where('history.3.statusLabel', 'Пришёл')
                ->where('history.4.eventId', $noShow->id)
                ->where('history.4.status', 'no_show')
                ->where('history.4.statusLabel', 'Не пришёл'));
    }

    public function test_class_that_has_just_ended_moves_to_the_history(): void
    {
        $client = Client::factory()->create();
        $lead = User::factory()->create();
        $event = $this->event($lead, EventType::factory()->create()->id, '2026-11-10 10:00', '2026-11-10 11:59');
        $this->book($event, $client);

        $this->actingAs($this->user())
            ->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page
                ->has('upcoming', 0)
                ->where('history.0.eventId', $event->id));
    }

    public function test_only_this_clients_bookings_are_shown(): void
    {
        $client = Client::factory()->create();
        $other = Client::factory()->create();
        $event = $this->event(User::factory()->create(), EventType::factory()->create()->id, '2026-11-12 10:00', '2026-11-12 11:00');
        $this->book($event, $other);

        $this->actingAs($this->user())
            ->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page->has('upcoming', 0)->has('history', 0)->where('historyTotal', 0));
    }

    public function test_class_over_midnight_shows_both_ends(): void
    {
        $client = Client::factory()->create();
        $event = $this->event(User::factory()->create(), EventType::factory()->create()->id, '2026-11-12 21:00', '2026-11-13 01:00');
        $this->book($event, $client);

        $this->actingAs($this->user())
            ->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page
                ->where('upcoming.0.dateLabel', '12.11.2026')
                ->where('upcoming.0.timeLabel', '21:00 – 13.11 01:00'));
    }

    public function test_history_shows_the_latest_fifty_visits_and_counts_all(): void
    {
        $client = Client::factory()->create();
        $lead = User::factory()->create();
        $type = EventType::factory()->create();

        foreach (range(1, 52) as $day) {
            $start = Carbon::parse('2026-09-01 10:00')->addDays($day);
            $this->book($this->event($lead, $type->id, $start->format('Y-m-d H:i'), $start->copy()->addHour()->format('Y-m-d H:i')), $client, AttendanceStatus::Attended);
        }

        $this->actingAs($this->user())
            ->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page
                ->has('history', 50)
                ->where('historyTotal', 52)
                ->where('history.0.dateLabel', '23.10.2026')
                ->where('history.49.dateLabel', '04.09.2026'));
    }

    private function user(bool $isAdmin = true): User
    {
        return $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function event(User $lead, int $typeId, string $startsAt, string $endsAt, array $attributes = [], bool $cancelled = false): Event
    {
        $factory = Event::factory()->ledBy($lead)->at($startsAt, $endsAt);

        return ($cancelled ? $factory->cancelled() : $factory)->create([
            'event_type_id' => $typeId,
            'location' => null,
            'capacity' => null,
            ...$attributes,
        ]);
    }

    private function book(Event $event, Client $client, AttendanceStatus $status = AttendanceStatus::Booked): EventClient
    {
        return EventClient::factory()->forEvent($event)->forClient($client)->create(['status' => $status]);
    }
}
