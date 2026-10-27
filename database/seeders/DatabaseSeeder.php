<?php

namespace Database\Seeders;

use App\Enums\Role;
use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

/**
 * Demo data for local development. On production the first administrator
 * is created with `php artisan app:create-admin` instead.
 */
class DatabaseSeeder extends Seeder
{
    use WithoutModelEvents;

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
            'role' => Role::Admin,
        ]);

        User::firstOrCreate(['email' => 'instructor@example.com'], [
            'name' => 'Демо Инструктор',
            'password' => 'password',
            'role' => Role::Instructor,
            'color' => '#0891b2',
        ])->creator()->associate($admin)->save();
    }
}
