<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class PasswordResetTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_forgot_password_screen_is_shown(): void
    {
        $this->get('/forgot-password')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page->component('auth/ForgotPassword'));
    }

    public function test_reset_link_is_sent_to_existing_user(): void
    {
        $user = User::factory()->create();
        Notification::fake();

        $this->post('/forgot-password', ['email' => $user->email])
            ->assertSessionHas('status', 'Если такой email зарегистрирован, мы отправили на него ссылку для сброса пароля.');

        Notification::assertSentTo($user, ResetPassword::class);
    }

    public function test_unknown_email_gets_the_same_answer_as_a_known_one(): void
    {
        Notification::fake();

        $this->post('/forgot-password', ['email' => 'nobody@example.com'])
            ->assertSessionHasNoErrors()
            ->assertSessionHas('status', 'Если такой email зарегистрирован, мы отправили на него ссылку для сброса пароля.');

        Notification::assertNothingSent();
    }

    public function test_reset_link_email_is_in_russian_and_points_to_reset_page(): void
    {
        $user = User::factory()->create();
        Notification::fake();

        $this->post('/forgot-password', ['email' => $user->email]);

        Notification::assertSentTo($user, ResetPassword::class, function (ResetPassword $notification) use ($user): bool {
            $mail = $notification->toMail($user);

            return $mail->subject === 'Сброс пароля'
                && $mail->actionText === 'Сбросить пароль'
                && str_contains($mail->actionUrl, '/reset-password/'.$notification->token);
        });
    }

    public function test_reset_password_screen_is_shown_with_token_and_email(): void
    {
        $this->get('/reset-password/some-token?email=diver@example.com')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('auth/ResetPassword')
                ->where('token', 'some-token')
                ->where('email', 'diver@example.com'));
    }

    public function test_password_can_be_reset_with_valid_token(): void
    {
        $user = User::factory()->create();
        $token = Password::createToken($user);

        $this->post('/reset-password', [
            'token' => $token,
            'email' => $user->email,
            'password' => 'new-password-123',
            'password_confirmation' => 'new-password-123',
        ])
            ->assertRedirect('/login')
            ->assertSessionHas('status', 'Пароль изменён. Войдите с новым паролем.');

        $this->assertTrue(Hash::check('new-password-123', $user->fresh()->password));
    }

    public function test_password_is_not_reset_with_invalid_token(): void
    {
        $user = User::factory()->create();

        $this->post('/reset-password', [
            'token' => 'invalid-token',
            'email' => $user->email,
            'password' => 'new-password-123',
            'password_confirmation' => 'new-password-123',
        ])->assertSessionHasErrors(['email' => 'Ссылка для сброса пароля недействительна или устарела.']);

        $this->assertTrue(Hash::check('password', $user->fresh()->password));
    }

    public function test_new_password_must_be_at_least_eight_characters(): void
    {
        $user = User::factory()->create();

        $this->post('/reset-password', [
            'token' => Password::createToken($user),
            'email' => $user->email,
            'password' => 'short',
            'password_confirmation' => 'short',
        ])->assertSessionHasErrors(['password' => 'Поле «Пароль» должно содержать не меньше 8 символов.']);
    }
}
