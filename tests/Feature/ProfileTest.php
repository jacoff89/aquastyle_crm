<?php

namespace Tests\Feature;

use App\Enums\Role;
use App\Models\Event;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Carbon;
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

    public function test_instructor_sees_own_schedule_in_profile(): void
    {
        Carbon::setTestNow('2026-11-04 12:00');
        $instructor = User::factory()->create();
        Event::factory()->ledBy($instructor)->at('2026-11-05 10:00', '2026-11-05 11:00')->create(['title' => 'Моё']);
        Event::factory()->ledBy(User::factory()->create())->at('2026-11-05 12:00', '2026-11-05 13:00')->create(['title' => 'Чужое']);

        $this->actingAs($instructor)
            ->get('/profile')
            ->assertInertia(fn (Assert $page) => $page
                ->where('scheduleRange', '2w')
                ->has('scheduleRanges', 5)
                ->has('schedule', 1)
                ->where('schedule.0.title', 'Моё'));

        $this->actingAs($instructor)->patch('/schedule-range', ['range' => '3d']);

        $this->actingAs($instructor->fresh())->get('/profile')
            ->assertInertia(fn (Assert $page) => $page->where('scheduleRange', '3d'));
    }

    public function test_user_without_instructor_role_has_no_schedule_in_profile(): void
    {
        $admin = User::factory()->admin()->create(['roles' => [Role::Admin]]);

        $this->actingAs($admin)
            ->get('/profile')
            ->assertInertia(fn (Assert $page) => $page->where('schedule', null));
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
