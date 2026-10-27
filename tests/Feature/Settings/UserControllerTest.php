<?php

namespace Tests\Feature\Settings;

use App\Enums\Role;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class UserControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_sees_active_users_first_then_by_name(): void
    {
        $admin = User::factory()->admin()->create(['name' => 'Борис']);
        User::factory()->create(['name' => 'Анна']);
        User::factory()->inactive()->create(['name' => 'Аркадий']);

        $this->actingAs($admin)
            ->get('/settings/users')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('settings/users/Index')
                ->where('users.0.name', 'Анна')
                ->where('users.1.name', 'Борис')
                ->where('users.1.isCurrentUser', true)
                ->where('users.2.name', 'Аркадий')
                ->where('users.2.isActive', false));
    }

    public function test_user_list_does_not_expose_passwords(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->get('/settings/users')
            ->assertInertia(fn (Assert $page) => $page
                ->has('users.0', fn (Assert $user) => $user
                    ->hasAll(['id', 'name', 'email', 'phone', 'roleLabel', 'isActive', 'isCurrentUser'])
                    ->missing('password')));
    }

    public function test_instructor_can_not_open_user_management(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->get('/settings/users')->assertForbidden();
        $this->actingAs($instructor)->get('/settings/users/create')->assertForbidden();
        $this->actingAs($instructor)->get("/settings/users/{$instructor->id}/edit")->assertForbidden();
    }

    public function test_admin_creates_instructor(): void
    {
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->post('/settings/users', $this->validPayload())
            ->assertRedirect('/settings/users')
            ->assertSessionHas('status', 'Добавлена учётная запись: Ирина Волкова.');

        $user = User::where('email', 'irina@aquastyle74.ru')->sole();
        $this->assertSame('Ирина Волкова', $user->name);
        $this->assertSame('+7 912 345-67-89', $user->phone);
        $this->assertSame(Role::Instructor, $user->role);
        $this->assertTrue($user->is_active);
        $this->assertTrue(Hash::check('diving-2026', $user->password));
        $this->assertTrue($user->creator->is($admin));
    }

    public function test_email_is_stored_in_lower_case(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/users', $this->validPayload(['email' => '  Irina@AquaStyle74.ru ']));

        $this->assertDatabaseHas('users', ['email' => 'irina@aquastyle74.ru']);
    }

    public function test_instructor_can_not_create_users(): void
    {
        $this->actingAs(User::factory()->create())
            ->post('/settings/users', $this->validPayload())
            ->assertForbidden();

        $this->assertDatabaseMissing('users', ['email' => 'irina@aquastyle74.ru']);
    }

    public function test_new_user_requires_name_email_role_and_password(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/users', [])
            ->assertSessionHasErrors([
                'name' => 'Поле «Имя» обязательно для заполнения.',
                'email' => 'Поле «Email» обязательно для заполнения.',
                'role' => 'Поле «Роль» обязательно для заполнения.',
                'password' => 'Поле «Пароль» обязательно для заполнения.',
            ]);
    }

    public function test_email_must_be_unique(): void
    {
        User::factory()->create(['email' => 'irina@aquastyle74.ru']);

        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/users', $this->validPayload())
            ->assertSessionHasErrors(['email' => 'Такое значение поля «Email» уже занято.']);
    }

    public function test_role_must_be_known(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/users', $this->validPayload(['role' => 'manager']))
            ->assertSessionHasErrors(['role' => 'Выбрано недопустимое значение поля «Роль».']);
    }

    public function test_edit_form_shows_user_without_password(): void
    {
        $instructor = User::factory()->create(['name' => 'Ирина', 'notes' => 'Ведёт детские группы']);

        $this->actingAs(User::factory()->admin()->create())
            ->get("/settings/users/{$instructor->id}/edit")
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('settings/users/Form')
                ->where('user.name', 'Ирина')
                ->where('user.role', 'instructor')
                ->where('user.notes', 'Ведёт детские группы')
                ->where('user.isCurrentUser', false)
                ->missing('user.password')
                ->has('roles', 2));
    }

    public function test_admin_updates_user_and_keeps_password_when_left_empty(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->put("/settings/users/{$instructor->id}", $this->validPayload([
                'role' => 'admin',
                'password' => '',
                'password_confirmation' => '',
            ]))
            ->assertRedirect('/settings/users')
            ->assertSessionHas('status', 'Изменения сохранены: Ирина Волкова.');

        $instructor->refresh();
        $this->assertSame('irina@aquastyle74.ru', $instructor->email);
        $this->assertSame(Role::Admin, $instructor->role);
        $this->assertTrue(Hash::check('password', $instructor->password));
    }

    public function test_admin_sets_new_password(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->put("/settings/users/{$instructor->id}", $this->validPayload());

        $this->assertTrue(Hash::check('diving-2026', $instructor->fresh()->password));
    }

    public function test_admin_deactivates_user(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->put("/settings/users/{$instructor->id}", $this->validPayload(['is_active' => false, 'password' => '', 'password_confirmation' => '']));

        $this->assertFalse($instructor->fresh()->is_active);
    }

    public function test_user_can_keep_own_email_when_updated(): void
    {
        $instructor = User::factory()->create(['email' => 'irina@aquastyle74.ru']);

        $this->actingAs(User::factory()->admin()->create())
            ->put("/settings/users/{$instructor->id}", $this->validPayload(['password' => '', 'password_confirmation' => '']))
            ->assertSessionHasNoErrors();
    }

    public function test_admin_can_not_change_own_role(): void
    {
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->put("/settings/users/{$admin->id}", $this->validPayload(['role' => 'instructor', 'password' => '', 'password_confirmation' => '']))
            ->assertSessionHasErrors(['role' => 'Свою роль изменить нельзя.']);

        $this->assertTrue($admin->fresh()->isAdmin());
    }

    public function test_admin_can_not_deactivate_own_account(): void
    {
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->put("/settings/users/{$admin->id}", $this->validPayload(['role' => 'admin', 'is_active' => false, 'password' => '', 'password_confirmation' => '']))
            ->assertSessionHasErrors(['is_active' => 'Свою учётную запись отключить нельзя.']);

        $this->assertTrue($admin->fresh()->is_active);
    }

    public function test_admin_can_edit_own_name(): void
    {
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->put("/settings/users/{$admin->id}", $this->validPayload(['role' => 'admin', 'email' => $admin->email, 'password' => '', 'password_confirmation' => '']))
            ->assertSessionHasNoErrors();

        $this->assertSame('Ирина Волкова', $admin->fresh()->name);
    }

    public function test_instructor_can_not_update_users(): void
    {
        $other = User::factory()->create();

        $this->actingAs(User::factory()->create())
            ->put("/settings/users/{$other->id}", $this->validPayload(['role' => 'admin']))
            ->assertForbidden();

        $this->assertTrue($other->fresh()->isInstructor());
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
            'role' => 'instructor',
            'is_active' => true,
            'notes' => null,
            'password' => 'diving-2026',
            'password_confirmation' => 'diving-2026',
            ...$overrides,
        ];
    }
}
