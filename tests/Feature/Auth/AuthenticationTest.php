<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_login_screen_is_shown_to_guests(): void
    {
        $this->get('/login')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page->component('auth/Login'));
    }

    public function test_guest_is_redirected_to_login_from_protected_pages(): void
    {
        $this->get('/calendar')->assertRedirect('/login');
    }

    public function test_home_page_redirects_to_calendar(): void
    {
        $this->actingAs(User::factory()->create())
            ->get('/')
            ->assertRedirect('/calendar');
    }

    public function test_user_can_log_in_with_correct_password(): void
    {
        $user = User::factory()->create();

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'password',
        ])->assertRedirect('/calendar');

        $this->assertAuthenticatedAs($user);
    }

    public function test_user_can_not_log_in_with_wrong_password(): void
    {
        $user = User::factory()->create();

        $this->from('/login')
            ->post('/login', [
                'email' => $user->email,
                'password' => 'wrong-password',
            ])
            ->assertRedirect('/login')
            ->assertSessionHasErrors(['email' => 'Неверный email или пароль.']);

        $this->assertGuest();
    }

    public function test_deactivated_user_can_not_log_in_and_is_told_why(): void
    {
        $user = User::factory()->inactive()->create();

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'password',
        ])->assertSessionHasErrors(['email' => 'Учётная запись отключена. Обратитесь к администратору.']);

        $this->assertGuest();
    }

    public function test_deactivated_user_with_wrong_password_gets_the_generic_error(): void
    {
        $user = User::factory()->inactive()->create();

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'wrong-password',
        ])->assertSessionHasErrors(['email' => 'Неверный email или пароль.']);
    }

    public function test_login_is_blocked_after_five_failed_attempts(): void
    {
        $user = User::factory()->create();

        foreach (range(1, 5) as $attempt) {
            $this->post('/login', ['email' => $user->email, 'password' => 'wrong-password']);
        }

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'password',
        ])->assertSessionHasErrors('email');

        $this->assertGuest();
        $this->assertStringStartsWith('Слишком много попыток входа.', session('errors')->first('email'));
    }

    public function test_login_requires_email_and_password(): void
    {
        $this->post('/login', [])->assertSessionHasErrors([
            'email' => 'Поле «Email» обязательно для заполнения.',
            'password' => 'Поле «Пароль» обязательно для заполнения.',
        ]);
    }

    public function test_user_can_log_out(): void
    {
        $this->actingAs(User::factory()->create())
            ->post('/logout')
            ->assertRedirect('/login');

        $this->assertGuest();
    }
}
