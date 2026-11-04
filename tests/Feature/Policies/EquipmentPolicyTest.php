<?php

namespace Tests\Feature\Policies;

use App\Models\Equipment;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class EquipmentPolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_can_list_create_and_update_equipment(): void
    {
        $admin = User::factory()->admin()->create();

        $this->assertTrue($admin->can('viewAny', Equipment::class));
        $this->assertTrue($admin->can('create', Equipment::class));
        $this->assertTrue($admin->can('update', Equipment::factory()->create()));
    }

    public function test_instructor_can_list_but_not_create_or_update_equipment(): void
    {
        $instructor = User::factory()->create();

        $this->assertTrue($instructor->can('viewAny', Equipment::class));
        $this->assertFalse($instructor->can('create', Equipment::class));
        $this->assertFalse($instructor->can('update', Equipment::factory()->create()));
    }
}
