<?php

namespace Tests\Feature\Policies;

use App\Models\Certification;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class CertificationPolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_can_list_create_and_update_certifications(): void
    {
        $admin = User::factory()->admin()->create();

        $this->assertTrue($admin->can('viewAny', Certification::class));
        $this->assertTrue($admin->can('create', Certification::class));
        $this->assertTrue($admin->can('update', Certification::factory()->create()));
    }

    public function test_instructor_can_not_list_create_or_update_certifications(): void
    {
        $instructor = User::factory()->create();

        $this->assertFalse($instructor->can('viewAny', Certification::class));
        $this->assertFalse($instructor->can('create', Certification::class));
        $this->assertFalse($instructor->can('update', Certification::factory()->create()));
    }
}
