<?php

namespace Tests\Feature\Console;

use App\Enums\Role;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class CreateAdminTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_is_created_from_interactive_answers(): void
    {
        $this->artisan('app:create-admin')
            ->expectsQuestion('Имя', 'Анна Петрова')
            ->expectsQuestion('Email', 'anna@aquastyle74.ru')
            ->expectsQuestion('Пароль (не короче 8 символов)', 'secret-password')
            ->expectsQuestion('Повторите пароль', 'secret-password')
            ->expectsOutput('Администратор anna@aquastyle74.ru создан. Теперь можно войти в систему.')
            ->assertSuccessful();

        $admin = User::where('email', 'anna@aquastyle74.ru')->sole();
        $this->assertSame('Анна Петрова', $admin->name);
        $this->assertEquals([Role::Admin], $admin->roles->all());
        $this->assertTrue($admin->is_active);
        $this->assertTrue(Hash::check('secret-password', $admin->password));
    }

    public function test_name_and_email_can_be_passed_as_options(): void
    {
        $this->artisan('app:create-admin', ['--name' => 'Анна', '--email' => 'anna@aquastyle74.ru'])
            ->expectsQuestion('Пароль (не короче 8 символов)', 'secret-password')
            ->expectsQuestion('Повторите пароль', 'secret-password')
            ->assertSuccessful();

        $this->assertTrue(User::where('email', 'anna@aquastyle74.ru')->sole()->isAdmin());
    }

    public function test_admin_is_not_created_when_passwords_differ(): void
    {
        $this->artisan('app:create-admin', ['--name' => 'Анна', '--email' => 'anna@aquastyle74.ru'])
            ->expectsQuestion('Пароль (не короче 8 символов)', 'secret-password')
            ->expectsQuestion('Повторите пароль', 'other-password')
            ->expectsOutput('Поле «Пароль» не совпадает с подтверждением.')
            ->assertFailed();

        $this->assertDatabaseCount('users', 0);
    }

    public function test_admin_is_not_created_with_taken_email(): void
    {
        User::factory()->create(['email' => 'anna@aquastyle74.ru']);

        $this->artisan('app:create-admin', ['--name' => 'Анна', '--email' => 'anna@aquastyle74.ru'])
            ->expectsQuestion('Пароль (не короче 8 символов)', 'secret-password')
            ->expectsQuestion('Повторите пароль', 'secret-password')
            ->expectsOutput('Такое значение поля «Email» уже занято.')
            ->assertFailed();

        $this->assertDatabaseCount('users', 1);
    }

    public function test_command_refuses_to_run_without_interaction(): void
    {
        $this->artisan('app:create-admin', ['--name' => 'Анна', '--email' => 'anna@aquastyle74.ru', '--no-interaction' => true])
            ->assertFailed();

        $this->assertDatabaseCount('users', 0);
    }
}
