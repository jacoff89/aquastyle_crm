<?php

namespace Tests\Feature\Policies;

use App\Models\Client;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class ClientPolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_can_list_view_create_update_and_delete_clients(): void
    {
        $admin = User::factory()->admin()->create();
        $client = Client::factory()->create();

        $this->assertTrue($admin->can('viewAny', Client::class));
        $this->assertTrue($admin->can('view', $client));
        $this->assertTrue($admin->can('create', Client::class));
        $this->assertTrue($admin->can('update', $client));
        $this->assertTrue($admin->can('delete', $client));
    }

    public function test_instructor_can_list_view_create_and_update_but_not_delete_clients(): void
    {
        $instructor = User::factory()->create();
        $client = Client::factory()->create();

        $this->assertTrue($instructor->can('viewAny', Client::class));
        $this->assertTrue($instructor->can('view', $client));
        $this->assertTrue($instructor->can('create', Client::class));
        $this->assertTrue($instructor->can('update', $client));
        $this->assertFalse($instructor->can('delete', $client));
    }
}
