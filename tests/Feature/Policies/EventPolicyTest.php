<?php

namespace Tests\Feature\Policies;

use App\Enums\InstructorRole;
use App\Models\Event;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class EventPolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    #[DataProvider('everyRole')]
    public function test_every_role_views_creates_and_edits_any_event(bool $isAdmin): void
    {
        $user = $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
        $someoneElsesEvent = Event::factory()->ledBy(User::factory()->create())->create();

        $this->assertTrue($user->can('viewAny', Event::class));
        $this->assertTrue($user->can('create', Event::class));
        $this->assertTrue($user->can('update', $someoneElsesEvent));
    }

    #[DataProvider('everyRole')]
    public function test_every_role_views_an_event_and_manages_its_clients(bool $isAdmin): void
    {
        $user = $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
        $someoneElsesEvent = Event::factory()->ledBy(User::factory()->create())->create();

        $this->assertTrue($user->can('view', $someoneElsesEvent));
        $this->assertTrue($user->can('manageClients', $someoneElsesEvent));
    }

    public function test_administrator_marks_attendance_on_any_event(): void
    {
        $event = Event::factory()->ledBy(User::factory()->create())->create();

        $this->assertTrue(User::factory()->admin()->create()->can('markAttendance', $event));
    }

    public function test_lead_and_assistant_mark_attendance_on_their_own_event(): void
    {
        $lead = User::factory()->create();
        $assistant = User::factory()->create();
        $event = Event::factory()->ledBy($lead)->create();
        $event->instructors()->attach($assistant, ['role' => InstructorRole::Assistant]);

        $this->assertTrue($lead->can('markAttendance', $event));
        $this->assertTrue($assistant->can('markAttendance', $event));
    }

    public function test_instructor_cannot_mark_attendance_on_someone_elses_event(): void
    {
        $event = Event::factory()->ledBy(User::factory()->create())->create();

        $this->assertFalse(User::factory()->create()->can('markAttendance', $event));
    }

    public function test_administrator_who_teaches_marks_attendance_on_any_event(): void
    {
        $teachingAdmin = User::factory()->admin()->create();
        $event = Event::factory()->ledBy($teachingAdmin)->create();

        $this->assertTrue($teachingAdmin->can('markAttendance', $event));
    }
}
