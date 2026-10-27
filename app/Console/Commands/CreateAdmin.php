<?php

namespace App\Console\Commands;

use App\Enums\Role;
use App\Models\User;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;

/**
 * Creates an administrator account. This is the only way to get the first user
 * on a fresh installation, because the application has no self-registration.
 */
#[Signature('app:create-admin
    {--name= : Имя администратора}
    {--email= : Email для входа}')]
#[Description('Создать администратора (пароль вводится интерактивно)')]
class CreateAdmin extends Command
{
    public function handle(): int
    {
        if (! $this->input->isInteractive()) {
            $this->error('Пароль вводится с клавиатуры, поэтому команду нужно запускать без --no-interaction.');

            return self::FAILURE;
        }

        $data = [
            'name' => $this->option('name') ?? $this->ask('Имя'),
            'email' => $this->option('email') ?? $this->ask('Email'),
            'password' => $this->secret('Пароль (не короче 8 символов)'),
            'password_confirmation' => $this->secret('Повторите пароль'),
        ];

        $validator = Validator::make($data, [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', Rule::unique(User::class)],
            'password' => ['required', 'confirmed', Password::defaults()],
        ]);

        if ($validator->fails()) {
            foreach ($validator->errors()->all() as $message) {
                $this->error($message);
            }

            return self::FAILURE;
        }

        $validated = $validator->validated();

        User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => $validated['password'],
            'role' => Role::Admin,
            'is_active' => true,
        ]);

        $this->info("Администратор {$validated['email']} создан. Теперь можно войти в систему.");

        return self::SUCCESS;
    }
}
