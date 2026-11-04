<?php

namespace Tests\Feature\Policies;

use App\Models\Location;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class LocationPolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_can_list_create_and_update_locations(): void
    {
        $admin = User::factory()->admin()->create();

        $this->assertTrue($admin->can('viewAny', Location::class));
        $this->assertTrue($admin->can('create', Location::class));
        $this->assertTrue($admin->can('update', Location::factory()->create()));
    }

    public function test_instructor_can_not_list_create_or_update_locations(): void
    {
        $instructor = User::factory()->create();

        $this->assertFalse($instructor->can('viewAny', Location::class));
        $this->assertFalse($instructor->can('create', Location::class));
        $this->assertFalse($instructor->can('update', Location::factory()->create()));
    }
}
