<?php

namespace Tests\Feature\Policies;

use App\Models\EventType;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class EventTypePolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_can_list_create_and_update_event_types(): void
    {
        $admin = User::factory()->admin()->create();

        $this->assertTrue($admin->can('viewAny', EventType::class));
        $this->assertTrue($admin->can('create', EventType::class));
        $this->assertTrue($admin->can('update', EventType::factory()->create()));
    }

    public function test_instructor_can_not_list_create_or_update_event_types(): void
    {
        $instructor = User::factory()->create();

        $this->assertFalse($instructor->can('viewAny', EventType::class));
        $this->assertFalse($instructor->can('create', EventType::class));
        $this->assertFalse($instructor->can('update', EventType::factory()->create()));
    }
}
