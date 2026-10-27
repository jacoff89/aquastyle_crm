<?php

namespace Tests\Feature\Policies;

use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class UserPolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_can_list_create_and_update_users(): void
    {
        $admin = User::factory()->admin()->create();

        $this->assertTrue($admin->can('viewAny', User::class));
        $this->assertTrue($admin->can('create', User::class));
        $this->assertTrue($admin->can('update', User::factory()->create()));
    }

    public function test_instructor_can_not_list_create_or_update_users(): void
    {
        $instructor = User::factory()->create();

        $this->assertFalse($instructor->can('viewAny', User::class));
        $this->assertFalse($instructor->can('create', User::class));
        $this->assertFalse($instructor->can('update', User::factory()->create()));
    }
}
