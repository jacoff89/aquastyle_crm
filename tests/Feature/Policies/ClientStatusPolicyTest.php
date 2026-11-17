<?php

namespace Tests\Feature\Policies;

use App\Models\ClientStatus;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class ClientStatusPolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_can_list_create_and_update_client_statuses(): void
    {
        $admin = User::factory()->admin()->create();

        $this->assertTrue($admin->can('viewAny', ClientStatus::class));
        $this->assertTrue($admin->can('create', ClientStatus::class));
        $this->assertTrue($admin->can('update', ClientStatus::factory()->create()));
    }

    public function test_instructor_can_not_list_create_or_update_client_statuses(): void
    {
        $instructor = User::factory()->create();

        $this->assertFalse($instructor->can('viewAny', ClientStatus::class));
        $this->assertFalse($instructor->can('create', ClientStatus::class));
        $this->assertFalse($instructor->can('update', ClientStatus::factory()->create()));
    }
}
