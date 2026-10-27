<?php

namespace Tests\Feature\Database;

use App\Enums\EventStatus;
use App\Enums\InstructorRole;
use App\Enums\Role;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\User;
use Database\Seeders\DatabaseSeeder;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Carbon;
use Tests\TestCase;

class DatabaseSeederTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_demo_admin_and_instructor_are_created_outside_production(): void
    {
        $this->seed(DatabaseSeeder::class);

        $admin = User::where('email', 'admin@example.com')->sole();
        $instructor = User::where('email', 'instructor@example.com')->sole();

        $this->assertEquals([Role::Admin], $admin->roles->all());
        $this->assertEquals([Role::Instructor], $instructor->roles->all());
        $this->assertTrue($instructor->creator->is($admin));
    }

    public function test_demo_instructors_include_a_teaching_administrator_and_a_former_instructor(): void
    {
        $this->seed(DatabaseSeeder::class);

        $teachingAdmin = User::where('email', 'admin-instructor@example.com')->sole();
        $former = User::where('email', 'olga@example.com')->sole();

        $this->assertEquals([Role::Admin, Role::Instructor], $teachingAdmin->roles->all());
        $this->assertTrue($teachingAdmin->is_active);
        $this->assertFalse($former->is_active);
        $this->assertSame(5, User::instructors()->count());
        $this->assertSame(4, User::instructors()->where('is_active', true)->count());
        $this->assertTrue(User::instructors()->get()->every(fn (User $instructor) => $instructor->color !== null));
        $this->assertSame(5, User::instructors()->distinct()->count('color'));
    }

    public function test_seeder_can_run_twice_without_duplicates(): void
    {
        $this->seed(DatabaseSeeder::class);
        $this->seed(DatabaseSeeder::class);

        $this->assertDatabaseCount('users', 6);
        $this->assertDatabaseCount('clients', 30);
        $this->assertDatabaseCount('events', 14);
    }

    public function test_demo_clients_are_created_with_a_normalized_phone(): void
    {
        $this->seed(DatabaseSeeder::class);

        $this->assertDatabaseCount('clients', 30);
        $this->assertSame(0, Client::query()->where('phone_digits', '')->count());
        $this->assertTrue(Client::query()->with('creator')->get()->every(fn (Client $client) => $client->creator->email === 'admin@example.com'));
    }

    public function test_demo_events_surround_today_with_every_status(): void
    {
        Carbon::setTestNow('2026-11-04 09:00');

        $this->seed(DatabaseSeeder::class);

        $today = Carbon::today();

        $this->assertTrue(Event::query()->where('starts_at', '<', $today)->exists(), 'There are past events.');
        $this->assertTrue(Event::query()->where('starts_at', '>=', $today)->where('starts_at', '<', $today->copy()->addDay())->exists(), 'There are events today.');
        $this->assertTrue(Event::query()->where('starts_at', '>=', $today->copy()->addDay())->exists(), 'There are upcoming events.');
        $this->assertSame(0, Event::query()->where('starts_at', '<', $today->copy()->subDays(14))->count());
        $this->assertSame(0, Event::query()->where('starts_at', '>=', $today->copy()->addDays(14))->count());

        foreach (EventStatus::cases() as $status) {
            $this->assertTrue(Event::query()->where('status', $status->value)->exists(), "No demo event is {$status->label()}.");
        }
    }

    public function test_every_demo_event_has_exactly_one_lead_and_a_type(): void
    {
        $this->seed(DatabaseSeeder::class);

        $events = Event::query()->with(['type', 'instructors'])->get();

        $this->assertCount(14, $events);
        $this->assertTrue($events->every(fn (Event $event) => $event->type !== null));
        $this->assertTrue($events->every(fn (Event $event) => $event->instructors->filter(fn (User $instructor) => $instructor->pivot->role === InstructorRole::Lead)->count() === 1));
        $this->assertTrue(Event::query()->withInstructor(User::where('email', 'olga@example.com')->sole())->exists(), 'The former instructor kept her past event.');
        $this->assertTrue(Event::query()->withInstructor(User::where('email', 'admin-instructor@example.com')->sole())->exists(), 'The teaching administrator has events.');
    }

    public function test_demo_bookings_respect_event_capacity_and_attendance_marks(): void
    {
        $this->seed(DatabaseSeeder::class);

        $events = Event::query()->get();

        foreach ($events as $event) {
            if ($event->capacity !== null) {
                $this->assertLessThanOrEqual($event->capacity, $event->occupiedPlaces(), "Event {$event->id} is over capacity.");
            }
        }

        $this->assertTrue($events->contains(fn (Event $event) => $event->capacity !== null && ! $event->hasFreePlace()), 'One event is full.');
        $this->assertTrue($events->contains(fn (Event $event) => $event->capacity === null && $event->bookings()->exists()), 'One event has no limit of places.');

        $doneEvents = Event::query()->where('status', EventStatus::Done->value)->pluck('id');
        $this->assertSame(0, EventClient::query()->whereIn('event_id', $doneEvents)->where('status', 'booked')->count(), 'Past events have every client marked.');
        $this->assertTrue(EventClient::query()->whereIn('event_id', $doneEvents)->where('status', 'attended')->exists());
        $this->assertTrue(EventClient::query()->whereIn('event_id', $doneEvents)->where('status', 'no_show')->exists());
        $this->assertTrue(EventClient::query()->where('status', 'booked')->exists(), 'Upcoming events have booked clients.');
    }

    public function test_no_demo_users_are_created_in_production(): void
    {
        $this->app['env'] = 'production';

        $this->seed(DatabaseSeeder::class);

        $this->assertDatabaseCount('users', 0);
        $this->assertDatabaseCount('clients', 0);
        $this->assertDatabaseCount('events', 0);
    }
}
