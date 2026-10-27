<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class ProfileTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_profile_page_shows_own_data(): void
    {
        $user = User::factory()->create(['name' => 'Иван Сидоров', 'phone' => '+7 900 000-00-00']);

        $this->actingAs($user)
            ->get('/profile')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('profile/Edit')
                ->where('profile.name', 'Иван Сидоров')
                ->where('profile.phone', '+7 900 000-00-00')
                ->where('profile.role', 'Инструктор'));
    }

    public function test_user_can_update_name_and_phone(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->from('/profile')
            ->patch('/profile', ['name' => 'Новое Имя', 'phone' => '+7 911 111-11-11'])
            ->assertRedirect('/profile')
            ->assertSessionHas('status', 'Профиль сохранён.');

        $this->assertSame('Новое Имя', $user->fresh()->name);
        $this->assertSame('+7 911 111-11-11', $user->fresh()->phone);
    }

    public function test_profile_update_can_not_change_role(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)->patch('/profile', ['name' => 'Хитрый', 'role' => 'admin']);

        $this->assertTrue($user->fresh()->isInstructor());
    }

    public function test_name_is_required(): void
    {
        $this->actingAs(User::factory()->create())
            ->patch('/profile', ['name' => ''])
            ->assertSessionHasErrors(['name' => 'Поле «Имя» обязательно для заполнения.']);
    }

    public function test_user_can_change_password_with_current_password(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->put('/profile/password', [
                'current_password' => 'password',
                'password' => 'new-password-123',
                'password_confirmation' => 'new-password-123',
            ])
            ->assertSessionHasNoErrors()
            ->assertSessionHas('status', 'Пароль изменён.');

        $this->assertTrue(Hash::check('new-password-123', $user->fresh()->password));
    }

    public function test_password_is_not_changed_with_wrong_current_password(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->put('/profile/password', [
                'current_password' => 'wrong-password',
                'password' => 'new-password-123',
                'password_confirmation' => 'new-password-123',
            ])
            ->assertSessionHasErrors(['current_password' => 'Неверный пароль.']);

        $this->assertTrue(Hash::check('password', $user->fresh()->password));
    }
}
