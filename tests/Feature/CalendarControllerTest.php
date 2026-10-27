<?php

namespace Tests\Feature;

use App\Models\EventType;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Carbon;
use Inertia\Testing\AssertableInertia as Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class CalendarControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_guest_is_redirected_to_login(): void
    {
        $this->get('/calendar')->assertRedirect('/login');
        $this->getJson('/calendar/events?start=2026-11-02&end=2026-11-08')->assertUnauthorized();
    }

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    #[DataProvider('everyRole')]
    public function test_every_role_opens_the_calendar_on_this_week(bool $isAdmin): void
    {
        Carbon::setTestNow('2026-11-04 09:00');
        $user = $isAdmin ? User::factory()->admin()->create() : User::factory()->create(['name' => 'Яна']);

        $this->actingAs($user)
            ->get('/calendar')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('calendar/Index')
                ->where('initialDate', '2026-11-04')
                ->where('initialView', 'week')
                ->where('canCreate', true));
    }

    public function test_calendar_offers_every_attendance_status(): void
    {
        $this->actingAs(User::factory()->create())
            ->get('/calendar')
            ->assertInertia(fn (Assert $page) => $page
                ->has('attendanceStatuses', 4)
                ->where('attendanceStatuses.0', ['value' => 'booked', 'label' => 'Записан', 'isAttendanceMark' => false])
                ->where('attendanceStatuses.1', ['value' => 'attended', 'label' => 'Пришёл', 'isAttendanceMark' => true])
                ->where('attendanceStatuses.2', ['value' => 'no_show', 'label' => 'Не пришёл', 'isAttendanceMark' => true])
                ->where('attendanceStatuses.3', ['value' => 'cancelled', 'label' => 'Отменил', 'isAttendanceMark' => false]));
    }

    public function test_calendar_lists_instructors_active_first_and_every_event_type(): void
    {
        User::factory()->create(['name' => 'Яна', 'color' => '#0891b2']);
        User::factory()->inactive()->create(['name' => 'Антон']);
        User::factory()->create(['name' => 'Борис']);
        $admin = User::factory()->admin()->create(['name' => 'Администратор']);
        EventType::factory()->hidden()->create(['name' => 'Скрытый']);

        $this->actingAs($admin)
            ->get('/calendar')
            ->assertInertia(fn (Assert $page) => $page
                ->has('instructors', 3)
                ->where('instructors.0', fn ($instructor) => $instructor['name'] === 'Борис' && $instructor['isActive'] === true)
                ->where('instructors.1.name', 'Яна')
                ->where('instructors.1.color', '#0891b2')
                ->where('instructors.2.name', 'Антон')
                ->where('instructors.2.isActive', false)
                ->has('eventTypes', 6)
                ->where('eventTypes.0.name', 'Теория')
                ->where('eventTypes.5.name', 'Скрытый')
                ->where('eventTypes.5.isActive', false)
                ->where('statuses.0', ['value' => 'planned', 'label' => 'Запланировано'])
                ->has('statuses', 3));
    }

    public function test_calendar_opens_on_the_requested_day_and_view(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->get('/calendar?date=2026-12-31&view=day')
            ->assertInertia(fn (Assert $page) => $page
                ->where('initialDate', '2026-12-31')
                ->where('initialView', 'day'));
    }

    public function test_invalid_date_and_view_fall_back_to_today_and_week(): void
    {
        Carbon::setTestNow('2026-11-04 09:00');

        $this->actingAs(User::factory()->admin()->create())
            ->get('/calendar?date=2026-02-31&view=year')
            ->assertInertia(fn (Assert $page) => $page
                ->where('initialDate', '2026-11-04')
                ->where('initialView', 'week'));
    }
}
