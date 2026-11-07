<?php

namespace Tests\Feature\Events;

use App\Enums\InstructorRole;
use App\Models\Client;
use App\Models\Equipment;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\EventType;
use App\Models\Notice;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

/**
 * Every domain event becomes a notice that reads well, concerns the right users
 * and is already read by the person who made the change.
 */
class NoticeCreationTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
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

    /**
     * @return list<int>
     */
    private function recipientIds(Notice $notice): array
    {
        return $notice->recipients()->orderBy('users.id')->pluck('users.id')->all();
    }

    public function test_a_new_event_gives_one_notice_for_its_instructors(): void
    {
        $admin = User::factory()->admin()->create();
        $lead = User::factory()->create(['name' => 'Иван', 'last_name' => 'Петров']);
        $assistant = User::factory()->create();
        $type = EventType::factory()->create(['name' => 'Фридайвинг']);

        $this->actingAs($admin)->postJson('/events', [
            'event_type_id' => $type->id,
            'starts_at' => '2026-11-12 10:00',
            'ends_at' => '2026-11-12 11:00',
            'lead_instructor_id' => $lead->id,
            'assistant_ids' => [$assistant->id],
        ])->assertCreated();

        $notice = Notice::sole();
        $this->assertSame('CalendarEventCreated', $notice->type);
        $this->assertSame('Новое занятие «Фридайвинг» 12.11 10:00–11:00, ведущий Иван Петров', $notice->message);
        $this->assertSame(route('calendar', ['view' => 'day', 'date' => '2026-11-12']), $notice->url);
        $this->assertSame([$lead->id, $assistant->id], $this->recipientIds($notice));
        $this->assertTrue($notice->actor->is($admin));
        $this->assertSame(0, Notice::unreadCountFor($admin));
        $this->assertSame(1, Notice::unreadCountFor($lead));
    }

    public function test_moving_an_event_gives_one_notice_with_both_times(): void
    {
        $lead = User::factory()->create();
        $event = Event::factory()->at('2026-11-12 10:00', '2026-11-12 11:00')->ledBy($lead)->create(['title' => 'Теория']);
        Notice::query()->delete();

        $this->actingAs(User::factory()->admin()->create())
            ->patchJson("/events/{$event->id}", $this->payloadOf($event, ['starts_at' => '2026-11-13 12:00', 'ends_at' => '2026-11-13 13:00']))
            ->assertOk();

        $notice = Notice::sole();
        $this->assertSame('Занятие «Теория» перенесено с 12.11 10:00–11:00 на 13.11 12:00–13:00', $notice->message);
        $this->assertSame([$lead->id], $this->recipientIds($notice));
    }

    public function test_an_edit_gives_a_notice_for_every_kind_of_change_once(): void
    {
        $lead = User::factory()->create();
        $event = Event::factory()->at('2026-11-12 10:00', '2026-11-12 11:00')->ledBy($lead)->create(['title' => 'Теория', 'location' => null, 'notes' => null]);
        Notice::query()->delete();

        $this->actingAs(User::factory()->admin()->create())
            ->patchJson("/events/{$event->id}", $this->payloadOf($event, ['status' => 'cancelled', 'location' => 'Класс']))
            ->assertOk();

        $this->assertEqualsCanonicalizing([
            'Изменено занятие «Теория» 12.11 10:00–11:00: место',
            'Отменено занятие «Теория» 12.11 10:00–11:00',
        ], Notice::pluck('message')->all());
    }

    public function test_changing_instructors_concerns_everyone_put_on_taken_off_or_switched(): void
    {
        $oldLead = User::factory()->create(['name' => 'Олег', 'last_name' => null]);
        $leaving = User::factory()->create(['name' => 'Анна', 'last_name' => null]);
        $newcomer = User::factory()->create(['name' => 'Иван', 'last_name' => null]);
        $bystander = User::factory()->create();
        $event = Event::factory()->at('2026-11-12 10:00', '2026-11-12 11:00')->ledBy($oldLead, [$leaving])->create(['title' => 'Теория']);
        Notice::query()->delete();

        $this->actingAs(User::factory()->admin()->create())
            ->patchJson("/events/{$event->id}", $this->payloadOf($event, ['lead_instructor_id' => $newcomer->id, 'assistant_ids' => [$oldLead->id]]))
            ->assertOk();

        $notice = Notice::where('type', 'CalendarEventInstructorsChanged')->sole();
        $this->assertSame('Инструкторы занятия «Теория» 12.11 10:00–11:00: назначены Иван (ведущий); сняты Анна; сменили роль Олег (помощник)', $notice->message);
        $this->assertEqualsCanonicalizing([$oldLead->id, $leaving->id, $newcomer->id], $this->recipientIds($notice));
        $this->assertSame(0, Notice::unreadCountFor($bystander));
    }

    public function test_a_change_to_a_client_concerns_nobody_but_the_administrators(): void
    {
        $client = Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Пётр', 'middle_name' => null, 'phone' => '+7 900 000-00-00', 'email' => null, 'birth_date' => null, 'notes' => null]);
        $author = User::factory()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($author)
            ->put("/clients/{$client->id}", ['last_name' => 'Иванов', 'first_name' => 'Пётр', 'phone' => '+7 912 345-67-89'])
            ->assertSessionHasNoErrors();

        $notice = Notice::sole();
        $this->assertSame('Изменены данные клиента Иванов Пётр: телефон', $notice->message);
        $this->assertSame([], $this->recipientIds($notice));
        $this->assertSame(1, Notice::unreadCountFor($admin));
        $this->assertSame(0, Notice::unreadCountFor($author));
    }

    public function test_attendance_concerns_the_instructors_of_the_event(): void
    {
        $lead = User::factory()->create();
        $event = Event::factory()->at('2026-11-12 10:00', '2026-11-12 11:00')->ledBy($lead)->create(['title' => 'Бассейн']);
        $client = Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Пётр', 'middle_name' => null]);
        EventClient::factory()->forEvent($event)->forClient($client)->create();
        Notice::query()->delete();

        $this->actingAs($lead)->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'attended'])->assertOk();

        $notice = Notice::sole();
        $this->assertSame('Клиент Иванов Пётр на занятии «Бассейн» 12.11 10:00–11:00: пришёл (было: записан)', $notice->message);
        $this->assertSame([$lead->id], $this->recipientIds($notice));
        $this->assertSame(0, Notice::unreadCountFor($lead));
    }

    public function test_reassigning_equipment_concerns_both_instructors(): void
    {
        $previous = User::factory()->create(['name' => 'Анна', 'last_name' => null]);
        $next = User::factory()->create(['name' => 'Иван', 'last_name' => null]);
        $item = Equipment::factory()->create(['name' => 'Регулятор', 'inventory_number' => 'R-001', 'instructor_id' => $previous->id]);

        $this->actingAs(User::factory()->admin()->create())
            ->put("/equipment/{$item->id}", ['name' => 'Регулятор', 'category_id' => $item->category_id, 'inventory_number' => 'R-001', 'size' => $item->size, 'status' => $item->status->value, 'location_id' => $item->location_id, 'notes' => $item->notes, 'instructor_id' => $next->id])
            ->assertSessionHasNoErrors();

        $notice = Notice::sole();
        $this->assertSame('Снаряжение «Регулятор» (R-001) закреплено за Иван вместо Анна', $notice->message);
        $this->assertEqualsCanonicalizing([$previous->id, $next->id], $this->recipientIds($notice));
    }

    public function test_equipment_added_with_an_instructor_gives_one_notice_for_them(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->post('/equipment', ['name' => 'Ласты', 'status' => 'in_use', 'instructor_id' => $instructor->id])
            ->assertSessionHasNoErrors();

        $notice = Notice::sole();
        $this->assertSame('Добавлено снаряжение «Ласты»', $notice->message);
        $this->assertSame([$instructor->id], $this->recipientIds($notice));
    }

    public function test_a_change_to_an_account_leads_its_owner_to_their_profile(): void
    {
        $instructor = User::factory()->create(['name' => 'Ирина', 'last_name' => null, 'phone' => '+7 900 000-00-00']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->put("/instructors/{$instructor->id}", [
            'name' => 'Ирина',
            'last_name' => null,
            'email' => $instructor->email,
            'phone' => '+7 912 345-67-89',
            'color' => $instructor->color,
            'is_active' => true,
            'notes' => $instructor->notes,
        ])->assertSessionHasNoErrors();

        $notice = Notice::sole();
        $this->assertSame('Изменена учётная запись Ирина: телефон', $notice->message);
        $this->assertSame([$instructor->id], $this->recipientIds($notice));
        $this->assertSame(route('profile.edit'), $notice->urlFor($instructor));
        $this->assertSame(route('instructors.show', $instructor), $notice->urlFor($admin));
    }

    public function test_a_change_from_the_console_has_no_author_and_is_unread_for_everyone(): void
    {
        $this->artisan('app:create-admin', ['--name' => 'Анна', '--email' => 'anna@aquastyle74.ru'])
            ->expectsQuestion('Пароль (не короче 8 символов)', 'secret-password')
            ->expectsQuestion('Повторите пароль', 'secret-password')
            ->assertSuccessful();

        $notice = Notice::sole();
        $this->assertSame('Новая учётная запись: Анна (администратор)', $notice->message);
        $this->assertNull($notice->actor_id);
        $this->assertFalse($notice->readers()->exists());
    }

    public function test_the_event_data_is_kept_with_the_notice(): void
    {
        $client = Client::factory()->create(['first_name' => 'Пётр', 'last_name' => 'Иванов', 'middle_name' => null, 'phone' => '+7 912 345-67-89', 'email' => null, 'birth_date' => null, 'notes' => null]);

        $this->actingAs(User::factory()->create())
            ->put("/clients/{$client->id}", ['last_name' => 'Иванов', 'first_name' => 'Павел', 'phone' => '+7 912 345-67-89'])
            ->assertSessionHasNoErrors();

        $this->assertSame([
            'client' => "Client#{$client->id}",
            'changes' => ['first_name' => ['old' => 'Пётр', 'new' => 'Павел']],
        ], Notice::sole()->data);
    }
}
