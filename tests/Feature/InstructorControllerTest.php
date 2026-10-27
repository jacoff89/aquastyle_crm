<?php

namespace Tests\Feature;

use App\Enums\Role;
use App\Models\Event;
use App\Models\EventType;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;
use Inertia\Testing\AssertableInertia as Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class InstructorControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_guest_is_redirected_to_login(): void
    {
        $this->get('/instructors')->assertRedirect('/login');
        $this->post('/instructors', $this->validPayload())->assertRedirect('/login');
    }

    public function test_admin_sees_only_instructors_active_first_then_by_name(): void
    {
        $admin = User::factory()->admin()->create(['name' => 'Админ']);
        User::factory()->create(['name' => 'Борис', 'color' => '#2563eb']);
        User::factory()->create(['name' => 'Анна']);
        User::factory()->inactive()->create(['name' => 'Аркадий']);

        $this->actingAs($admin)
            ->get('/instructors')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('instructors/Index')
                ->has('instructors', 3)
                ->where('instructors.0.name', 'Анна')
                ->where('instructors.1.name', 'Борис')
                ->where('instructors.1.color', '#2563eb')
                ->where('instructors.2.name', 'Аркадий')
                ->where('instructors.2.isActive', false));
    }

    public function test_instructor_list_does_not_expose_passwords(): void
    {
        User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->get('/instructors')
            ->assertInertia(fn (Assert $page) => $page
                ->has('instructors.0', fn (Assert $instructor) => $instructor
                    ->hasAll(['id', 'name', 'email', 'phone', 'color', 'isActive'])
                    ->missing('password')));
    }

    public function test_instructor_is_forbidden_from_every_instructor_page(): void
    {
        $instructor = User::factory()->create();
        $other = User::factory()->create();

        $this->actingAs($instructor)->get('/instructors')->assertForbidden();
        $this->actingAs($instructor)->get('/instructors/create')->assertForbidden();
        $this->actingAs($instructor)->get("/instructors/{$other->id}")->assertForbidden();
        $this->actingAs($instructor)->get("/instructors/{$other->id}/edit")->assertForbidden();
        $this->actingAs($instructor)->post('/instructors', $this->validPayload())->assertForbidden();
        $this->actingAs($instructor)->put("/instructors/{$other->id}", $this->validPayload())->assertForbidden();

        $this->assertDatabaseMissing('users', ['email' => 'irina@aquastyle74.ru']);
        $this->assertNotSame('Ирина Волкова', $other->fresh()->name);
    }

    public function test_admin_creates_instructor(): void
    {
        $admin = User::factory()->admin()->create();

        $response = $this->actingAs($admin)->post('/instructors', $this->validPayload());

        $instructor = User::where('email', 'irina@aquastyle74.ru')->sole();
        $response
            ->assertRedirect("/instructors/{$instructor->id}")
            ->assertSessionHas('status', 'Добавлен инструктор: Ирина Волкова.');

        $this->assertSame('Ирина Волкова', $instructor->name);
        $this->assertSame('+7 912 345-67-89', $instructor->phone);
        $this->assertSame('#0891b2', $instructor->color);
        $this->assertSame('Ведёт детские группы', $instructor->notes);
        $this->assertSame(Role::Instructor, $instructor->role);
        $this->assertTrue($instructor->is_active);
        $this->assertTrue(Hash::check('diving-2026', $instructor->password));
        $this->assertTrue($instructor->creator->is($admin));
    }

    public function test_new_instructor_gets_the_instructor_role_even_if_another_is_submitted(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/instructors', $this->validPayload(['role' => 'admin']));

        $this->assertSame(Role::Instructor, User::where('email', 'irina@aquastyle74.ru')->sole()->role);
    }

    public function test_email_and_color_are_stored_in_lower_case(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/instructors', $this->validPayload(['email' => '  Irina@AquaStyle74.ru ', 'color' => '#0891B2']));

        $instructor = User::where('email', 'irina@aquastyle74.ru')->sole();
        $this->assertSame('#0891b2', $instructor->color);
    }

    public function test_new_instructor_requires_name_email_color_and_password(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/instructors', [])
            ->assertSessionHasErrors([
                'name' => 'Поле «Имя» обязательно для заполнения.',
                'email' => 'Поле «Email» обязательно для заполнения.',
                'color' => 'Поле «Цвет» обязательно для заполнения.',
                'password' => 'Поле «Пароль» обязательно для заполнения.',
            ]);
    }

    public function test_new_instructor_password_must_be_confirmed(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/instructors', $this->validPayload(['password_confirmation' => 'other-password']))
            ->assertSessionHasErrors(['password' => 'Поле «Пароль» не совпадает с подтверждением.']);
    }

    public function test_email_must_be_unique_across_all_accounts(): void
    {
        User::factory()->admin()->create(['email' => 'irina@aquastyle74.ru']);

        $this->actingAs(User::factory()->admin()->create())
            ->post('/instructors', $this->validPayload())
            ->assertSessionHasErrors(['email' => 'Такое значение поля «Email» уже занято.']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidColors(): array
    {
        return [
            'not a color' => ['red'],
            'no hash' => ['0891b2'],
            'too short' => ['#0891b'],
            'too long' => ['#0891b2f'],
            'not hex digits' => ['#0891bz'],
            'short hex form' => ['#fff'],
        ];
    }

    #[DataProvider('invalidColors')]
    public function test_color_must_be_a_six_digit_hex_value(string $color): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/instructors', $this->validPayload(['color' => $color]))
            ->assertSessionHasErrors(['color' => 'Поле «Цвет» имеет неверный формат.']);

        $this->assertDatabaseMissing('users', ['email' => 'irina@aquastyle74.ru']);
    }

    public function test_show_page_lists_instructor_contacts_without_password(): void
    {
        $instructor = User::factory()->create([
            'name' => 'Ирина',
            'phone' => '+7 912 345-67-89',
            'color' => '#16a34a',
            'notes' => 'Ведёт детские группы',
        ]);

        $this->actingAs(User::factory()->admin()->create())
            ->get("/instructors/{$instructor->id}")
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('instructors/Show')
                ->where('instructor.name', 'Ирина')
                ->where('instructor.phone', '+7 912 345-67-89')
                ->where('instructor.color', '#16a34a')
                ->where('instructor.notes', 'Ведёт детские группы')
                ->where('instructor.isActive', true)
                ->missing('instructor.password'));
    }

    public function test_show_page_lists_the_schedule_for_the_next_two_weeks(): void
    {
        Carbon::setTestNow('2026-11-04 12:00');
        $instructor = User::factory()->create();
        $pool = EventType::factory()->create(['name' => 'Глубокий бассейн']);

        Event::factory()->ledBy($instructor)->at('2026-11-03 10:00', '2026-11-03 11:00')->create(['title' => 'Вчера']);
        Event::factory()->ledBy($instructor)->at('2026-11-04 09:00', '2026-11-04 10:00')->create(['title' => 'Сегодня утром']);
        Event::factory()->ledBy(User::factory()->create(), [$instructor])->at('2026-11-06 18:00', '2026-11-06 19:30')
            ->create(['event_type_id' => $pool->id, 'location' => 'Дельфин']);
        Event::factory()->ledBy($instructor)->cancelled()->at('2026-11-10 10:00', '2026-11-10 11:00')->create(['title' => 'Отменённое']);
        Event::factory()->ledBy($instructor)->at('2026-11-18 10:00', '2026-11-18 11:00')->create(['title' => 'Через две недели']);
        Event::factory()->ledBy(User::factory()->create())->at('2026-11-05 10:00', '2026-11-05 11:00')->create(['title' => 'Чужое']);

        $this->actingAs(User::factory()->admin()->create())
            ->get("/instructors/{$instructor->id}")
            ->assertInertia(fn (Assert $page) => $page
                ->has('schedule', 3)
                ->where('schedule.0.title', 'Сегодня утром')
                ->where('schedule.0.role', 'Ведущий')
                ->where('schedule.1.title', 'Глубокий бассейн')
                ->where('schedule.1.date', '2026-11-06')
                ->where('schedule.1.time', '18:00–19:30')
                ->where('schedule.1.location', 'Дельфин')
                ->where('schedule.1.role', 'Помощник')
                ->where('schedule.2.title', 'Отменённое')
                ->where('schedule.2.isCancelled', true)
                ->where('schedule.2.statusLabel', 'Отменено'));
    }

    public function test_admin_account_is_not_found_among_instructors(): void
    {
        $admin = User::factory()->admin()->create();
        $otherAdmin = User::factory()->admin()->create();

        $this->actingAs($admin)->get("/instructors/{$otherAdmin->id}")->assertNotFound();
        $this->actingAs($admin)->get("/instructors/{$otherAdmin->id}/edit")->assertNotFound();
        $this->actingAs($admin)->put("/instructors/{$otherAdmin->id}", $this->validPayload())->assertNotFound();

        $this->assertNotSame('Ирина Волкова', $otherAdmin->fresh()->name);
    }

    public function test_edit_form_shows_instructor_without_password(): void
    {
        $instructor = User::factory()->create(['name' => 'Ирина', 'color' => '#16a34a']);

        $this->actingAs(User::factory()->admin()->create())
            ->get("/instructors/{$instructor->id}/edit")
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('instructors/Form')
                ->where('instructor.id', $instructor->id)
                ->where('instructor.name', 'Ирина')
                ->where('instructor.color', '#16a34a')
                ->missing('instructor.password'));
    }

    public function test_create_form_has_no_instructor(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->get('/instructors/create')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('instructors/Form')
                ->where('instructor', null));
    }

    public function test_admin_updates_instructor_and_keeps_password_when_left_empty(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->put("/instructors/{$instructor->id}", $this->validPayload(['password' => '', 'password_confirmation' => '']))
            ->assertRedirect("/instructors/{$instructor->id}")
            ->assertSessionHas('status', 'Изменения сохранены: Ирина Волкова.');

        $instructor->refresh();
        $this->assertSame('irina@aquastyle74.ru', $instructor->email);
        $this->assertSame('+7 912 345-67-89', $instructor->phone);
        $this->assertSame('#0891b2', $instructor->color);
        $this->assertSame('Ведёт детские группы', $instructor->notes);
        $this->assertTrue(Hash::check('password', $instructor->password));
    }

    public function test_admin_sets_new_password_for_instructor(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->put("/instructors/{$instructor->id}", $this->validPayload());

        $this->assertTrue(Hash::check('diving-2026', $instructor->fresh()->password));
    }

    public function test_instructor_can_keep_own_email_when_updated(): void
    {
        $instructor = User::factory()->create(['email' => 'irina@aquastyle74.ru']);

        $this->actingAs(User::factory()->admin()->create())
            ->put("/instructors/{$instructor->id}", $this->validPayload(['password' => '', 'password_confirmation' => '']))
            ->assertSessionHasNoErrors();
    }

    public function test_update_rejects_email_of_another_account(): void
    {
        User::factory()->create(['email' => 'irina@aquastyle74.ru']);
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->put("/instructors/{$instructor->id}", $this->validPayload(['password' => '', 'password_confirmation' => '']))
            ->assertSessionHasErrors(['email' => 'Такое значение поля «Email» уже занято.']);
    }

    public function test_update_rejects_invalid_color(): void
    {
        $instructor = User::factory()->create(['color' => '#16a34a']);

        $this->actingAs(User::factory()->admin()->create())
            ->put("/instructors/{$instructor->id}", $this->validPayload(['color' => 'green', 'password' => '', 'password_confirmation' => '']))
            ->assertSessionHasErrors(['color' => 'Поле «Цвет» имеет неверный формат.']);

        $this->assertSame('#16a34a', $instructor->fresh()->color);
    }

    public function test_update_does_not_change_the_role(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->put("/instructors/{$instructor->id}", $this->validPayload(['role' => 'admin', 'password' => '', 'password_confirmation' => '']));

        $this->assertSame(Role::Instructor, $instructor->fresh()->role);
    }

    public function test_admin_deactivates_and_reactivates_instructor(): void
    {
        $instructor = User::factory()->create();
        $admin = User::factory()->admin()->create();
        $payload = ['password' => '', 'password_confirmation' => ''];

        $this->actingAs($admin)->put("/instructors/{$instructor->id}", $this->validPayload([...$payload, 'is_active' => false]));
        $this->assertFalse($instructor->fresh()->is_active);

        $this->actingAs($admin)->put("/instructors/{$instructor->id}", $this->validPayload([...$payload, 'is_active' => true]));
        $this->assertTrue($instructor->fresh()->is_active);
    }

    public function test_deactivated_instructor_can_not_log_in_but_stays_in_the_list(): void
    {
        $instructor = User::factory()->create(['email' => 'irina@aquastyle74.ru']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->put("/instructors/{$instructor->id}", $this->validPayload([
            'is_active' => false,
            'password' => '',
            'password_confirmation' => '',
        ]));

        $this->post('/logout');
        $this->post('/login', ['email' => 'irina@aquastyle74.ru', 'password' => 'password'])
            ->assertSessionHasErrors('email');
        $this->assertGuest();

        $this->actingAs($admin)
            ->get('/instructors')
            ->assertInertia(fn (Assert $page) => $page
                ->where('instructors.0.name', 'Ирина Волкова')
                ->where('instructors.0.isActive', false));
    }

    public function test_instructors_can_not_be_deleted(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->delete("/instructors/{$instructor->id}")
            ->assertStatus(405);

        $this->assertDatabaseHas('users', ['id' => $instructor->id]);
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private function validPayload(array $overrides = []): array
    {
        return [
            'name' => 'Ирина Волкова',
            'email' => 'irina@aquastyle74.ru',
            'phone' => '+7 912 345-67-89',
            'color' => '#0891b2',
            'is_active' => true,
            'notes' => 'Ведёт детские группы',
            'password' => 'diving-2026',
            'password_confirmation' => 'diving-2026',
            ...$overrides,
        ];
    }
}
