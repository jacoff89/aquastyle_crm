<?php

namespace Database\Seeders;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Enums\Role;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\EventType;
use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;

/**
 * Demo data for local development: accounts of both roles, clients, and a fortnight
 * of events around today with every status, so each screen has something to show.
 * On production the first administrator is created with `php artisan app:create-admin`
 * instead.
 *
 * Running the seeder again changes nothing that already exists.
 */
class DatabaseSeeder extends Seeder
{
    use WithoutModelEvents;

    private const CLIENTS_WITH_ALL_FIELDS = 10;

    private const CLIENTS_WITH_REQUIRED_FIELDS = 20;

    /**
     * Instructors by e-mail. The last two are the cases the calendar has to handle:
     * an administrator who teaches and an instructor who no longer works.
     *
     * @var array<string, array{name: string, phone: string, color: string, roles: list<Role>, isActive: bool}>
     */
    private const INSTRUCTORS = [
        'instructor@example.com' => ['name' => 'Демо Инструктор', 'phone' => '+7 912 000-00-01', 'color' => '#0891b2', 'roles' => [Role::Instructor], 'isActive' => true],
        'anna@example.com' => ['name' => 'Анна Волкова', 'phone' => '+7 912 000-00-02', 'color' => '#e11d48', 'roles' => [Role::Instructor], 'isActive' => true],
        'boris@example.com' => ['name' => 'Борис Орлов', 'phone' => '+7 912 000-00-03', 'color' => '#16a34a', 'roles' => [Role::Instructor], 'isActive' => true],
        'admin-instructor@example.com' => ['name' => 'Сергей Морозов', 'phone' => '+7 912 000-00-04', 'color' => '#7c3aed', 'roles' => [Role::Admin, Role::Instructor], 'isActive' => true],
        'olga@example.com' => ['name' => 'Ольга Кузнецова', 'phone' => '+7 912 000-00-05', 'color' => '#f59e0b', 'roles' => [Role::Instructor], 'isActive' => false],
    ];

    /**
     * The demo events. `day` is the offset from today, `bookings` the number of clients
     * by attendance status. Instructors are named by the start of their e-mail; the first is the lead.
     *
     * @var list<array{day: int, at: string, minutes: int, type: string, title?: string, location: ?string, capacity: ?int, status: EventStatus, instructors: list<string>, bookings: array<string, int>, notes?: string}>
     */
    private const EVENTS = [
        ['day' => -8, 'at' => '18:00', 'minutes' => 90, 'type' => 'Бассейн', 'location' => 'Бассейн «Дельфин»', 'capacity' => 8, 'status' => EventStatus::Done, 'instructors' => ['anna', 'boris'], 'bookings' => ['attended' => 4, 'no_show' => 1, 'cancelled' => 1]],
        ['day' => -6, 'at' => '10:00', 'minutes' => 120, 'type' => 'Теория', 'location' => 'Учебный класс', 'capacity' => 12, 'status' => EventStatus::Done, 'instructors' => ['instructor'], 'bookings' => ['attended' => 7, 'no_show' => 1]],
        ['day' => -4, 'at' => '11:00', 'minutes' => 240, 'type' => 'Открытая вода', 'location' => 'Озеро Увильды', 'capacity' => 6, 'status' => EventStatus::Done, 'instructors' => ['olga', 'anna'], 'bookings' => ['attended' => 5, 'cancelled' => 1]],
        ['day' => -1, 'at' => '19:00', 'minutes' => 90, 'type' => 'Бассейн', 'location' => 'Бассейн «Дельфин»', 'capacity' => 8, 'status' => EventStatus::Done, 'instructors' => ['boris'], 'bookings' => ['attended' => 4, 'no_show' => 1]],
        ['day' => 0, 'at' => '09:00', 'minutes' => 90, 'type' => 'Пробное погружение', 'location' => 'Бассейн «Дельфин»', 'capacity' => 4, 'status' => EventStatus::Planned, 'instructors' => ['instructor', 'anna'], 'bookings' => ['booked' => 3]],
        ['day' => 0, 'at' => '18:00', 'minutes' => 90, 'type' => 'Бассейн', 'location' => 'Бассейн «Дельфин»', 'capacity' => 8, 'status' => EventStatus::Planned, 'instructors' => ['admin-instructor'], 'bookings' => ['booked' => 5]],
        ['day' => 1, 'at' => '10:00', 'minutes' => 120, 'type' => 'Теория', 'location' => 'Учебный класс', 'capacity' => 10, 'status' => EventStatus::Planned, 'instructors' => ['anna'], 'bookings' => ['booked' => 6]],
        ['day' => 2, 'at' => '19:00', 'minutes' => 90, 'type' => 'Бассейн', 'location' => 'Бассейн «Дельфин»', 'capacity' => 6, 'status' => EventStatus::Planned, 'instructors' => ['boris', 'instructor'], 'bookings' => ['booked' => 6]],
        ['day' => 3, 'at' => '12:00', 'minutes' => 60, 'type' => 'Пробное погружение', 'location' => 'Бассейн «Дельфин»', 'capacity' => 3, 'status' => EventStatus::Planned, 'instructors' => ['instructor'], 'bookings' => ['booked' => 2]],
        ['day' => 4, 'at' => '10:00', 'minutes' => 360, 'type' => 'Открытая вода', 'location' => 'Озеро Увильды', 'capacity' => 10, 'status' => EventStatus::Planned, 'instructors' => ['admin-instructor', 'anna', 'boris'], 'bookings' => ['booked' => 7], 'notes' => 'Взять гидрокостюмы и термос.'],
        ['day' => 5, 'at' => '18:00', 'minutes' => 90, 'type' => 'Бассейн', 'location' => 'Бассейн «Дельфин»', 'capacity' => 8, 'status' => EventStatus::Cancelled, 'instructors' => ['anna'], 'bookings' => ['booked' => 2], 'notes' => 'Бассейн закрыт на санитарный день.'],
        ['day' => 7, 'at' => '10:00', 'minutes' => 120, 'type' => 'Теория', 'location' => 'Учебный класс', 'capacity' => 10, 'status' => EventStatus::Planned, 'instructors' => ['instructor'], 'bookings' => ['booked' => 4]],
        ['day' => 9, 'at' => '19:00', 'minutes' => 90, 'type' => 'Бассейн', 'location' => 'Бассейн «Дельфин»', 'capacity' => 8, 'status' => EventStatus::Planned, 'instructors' => ['boris'], 'bookings' => ['booked' => 5]],
        ['day' => 12, 'at' => '11:00', 'minutes' => 240, 'type' => 'Открытая вода', 'title' => 'Выезд на озеро', 'location' => 'Озеро Увильды', 'capacity' => null, 'status' => EventStatus::Planned, 'instructors' => ['admin-instructor', 'boris'], 'bookings' => ['booked' => 3]],
    ];

    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        if (app()->isProduction()) {
            $this->command?->warn('Демо-данные на production не создаются. Администратора создайте командой app:create-admin.');

            return;
        }

        $admin = User::firstOrCreate(['email' => 'admin@example.com'], [
            'name' => 'Демо Администратор',
            'password' => 'password',
            'roles' => [Role::Admin],
        ]);

        $instructors = $this->seedInstructors($admin);
        $clients = $this->seedClients($admin);
        $this->seedEvents($admin, $instructors, $clients);

        $this->command?->info('Демо-аккаунты, пароль у всех — password: admin@example.com, '.implode(', ', array_keys(self::INSTRUCTORS)).'.');
    }

    /**
     * @return Collection<string, User> The instructors by the start of their e-mail ("anna", "admin-instructor").
     */
    private function seedInstructors(User $admin): Collection
    {
        return collect(self::INSTRUCTORS)->mapWithKeys(function (array $attributes, string $email) use ($admin): array {
            $instructor = User::firstOrCreate(['email' => $email], [
                'name' => $attributes['name'],
                'password' => 'password',
                'phone' => $attributes['phone'],
                'roles' => $attributes['roles'],
                'color' => $attributes['color'],
                'is_active' => $attributes['isActive'],
            ]);
            $instructor->creator()->associate($admin)->save();

            return [strstr($email, '@', true) => $instructor];
        });
    }

    /**
     * @return Collection<int, Client>
     */
    private function seedClients(User $admin): Collection
    {
        if (Client::query()->doesntExist()) {
            Client::factory()->count(self::CLIENTS_WITH_ALL_FIELDS)->complete()->create(['created_by' => $admin->id]);
            Client::factory()->count(self::CLIENTS_WITH_REQUIRED_FIELDS)->create(['created_by' => $admin->id]);
        }

        return Client::query()->orderBy('id')->get();
    }

    /**
     * @param  Collection<string, User>  $instructors
     * @param  Collection<int, Client>  $clients
     */
    private function seedEvents(User $admin, Collection $instructors, Collection $clients): void
    {
        if (Event::query()->exists() || $clients->isEmpty()) {
            return;
        }

        foreach (self::EVENTS as $index => $demo) {
            $startsAt = Carbon::today()->addDays($demo['day'])->setTimeFromTimeString($demo['at']);
            $lead = $instructors[$demo['instructors'][0]];
            $assistants = array_map(fn (string $key): User => $instructors[$key], array_slice($demo['instructors'], 1));

            $event = Event::factory()->ledBy($lead, $assistants)->create([
                'title' => $demo['title'] ?? null,
                'event_type_id' => EventType::query()->firstOrCreate(['name' => $demo['type']])->id,
                'starts_at' => $startsAt,
                'ends_at' => $startsAt->copy()->addMinutes($demo['minutes']),
                'location' => $demo['location'],
                'capacity' => $demo['capacity'],
                'status' => $demo['status'],
                'notes' => $demo['notes'] ?? null,
                'created_by' => $admin->id,
            ]);

            $this->bookClients($event, $clients, $demo['bookings'], $index);
        }
    }

    /**
     * Book clients on the event, a different group each time: the first group of the
     * event starts at its position in the list, so the same client rarely meets the same classmates.
     *
     * @param  Collection<int, Client>  $clients
     * @param  array<string, int>  $countsByStatus
     */
    private function bookClients(Event $event, Collection $clients, array $countsByStatus, int $position): void
    {
        $statuses = collect($countsByStatus)->flatMap(
            fn (int $count, string $status): array => array_fill(0, $count, AttendanceStatus::from($status)),
        );

        foreach ($statuses->values() as $offset => $status) {
            EventClient::factory()
                ->forEvent($event)
                ->forClient($clients[($position * 4 + $offset) % $clients->count()])
                ->create(['status' => $status]);
        }
    }
}
