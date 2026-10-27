<?php

namespace Tests\Feature\Database;

use App\Enums\Role;
use App\Models\User;
use Database\Seeders\DatabaseSeeder;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class DatabaseSeederTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_demo_admin_and_instructor_are_created_outside_production(): void
    {
        $this->seed(DatabaseSeeder::class);

        $admin = User::where('email', 'admin@example.com')->sole();
        $instructor = User::where('email', 'instructor@example.com')->sole();

        $this->assertSame(Role::Admin, $admin->role);
        $this->assertSame(Role::Instructor, $instructor->role);
        $this->assertTrue($instructor->creator->is($admin));
    }

    public function test_seeder_can_run_twice_without_duplicates(): void
    {
        $this->seed(DatabaseSeeder::class);
        $this->seed(DatabaseSeeder::class);

        $this->assertDatabaseCount('users', 2);
    }

    public function test_no_demo_users_are_created_in_production(): void
    {
        $this->app['env'] = 'production';

        $this->seed(DatabaseSeeder::class);

        $this->assertDatabaseCount('users', 0);
    }
}
