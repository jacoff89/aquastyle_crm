<?php

namespace Tests\Feature\Database;

use App\Enums\Role;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class UserRolesMigrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_single_role_is_converted_to_a_list_and_back(): void
    {
        $this->artisan('migrate:rollback', ['--path' => 'database/migrations/2026_10_27_225326_replace_role_with_roles_on_users_table.php'])->assertSuccessful();
        $this->assertTrue(Schema::hasColumn('users', 'role'));

        DB::table('users')->insert([
            ['name' => 'Админ', 'email' => 'admin@example.com', 'password' => 'x', 'role' => 'admin'],
            ['name' => 'Инструктор', 'email' => 'instructor@example.com', 'password' => 'x', 'role' => 'instructor'],
        ]);

        $this->artisan('migrate')->assertSuccessful();

        $this->assertFalse(Schema::hasColumn('users', 'role'));
        $this->assertEquals([Role::Admin], User::where('email', 'admin@example.com')->sole()->roles->all());
        $this->assertEquals([Role::Instructor], User::where('email', 'instructor@example.com')->sole()->roles->all());

        User::where('email', 'admin@example.com')->sole()->update(['roles' => [Role::Admin, Role::Instructor]]);

        $this->artisan('migrate:rollback', ['--path' => 'database/migrations/2026_10_27_225326_replace_role_with_roles_on_users_table.php'])->assertSuccessful();

        $this->assertSame('admin', DB::table('users')->where('email', 'admin@example.com')->value('role'));
        $this->assertSame('instructor', DB::table('users')->where('email', 'instructor@example.com')->value('role'));
    }
}
