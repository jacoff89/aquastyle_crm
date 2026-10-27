<?php

namespace Tests\Feature\Policies;

use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class UserPolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * @return array<string, array{string}>
     */
    public static function abilitiesOnAnotherUser(): array
    {
        return [
            'view' => ['view'],
            'update' => ['update'],
            'delete' => ['delete'],
        ];
    }

    public function test_admin_can_list_and_create_users(): void
    {
        $admin = User::factory()->admin()->create();

        $this->assertTrue($admin->can('viewAny', User::class));
        $this->assertTrue($admin->can('create', User::class));
    }

    public function test_instructor_can_not_list_or_create_users(): void
    {
        $instructor = User::factory()->create();

        $this->assertFalse($instructor->can('viewAny', User::class));
        $this->assertFalse($instructor->can('create', User::class));
    }

    #[DataProvider('abilitiesOnAnotherUser')]
    public function test_admin_can_manage_another_user(string $ability): void
    {
        $admin = User::factory()->admin()->create();

        $this->assertTrue($admin->can($ability, User::factory()->create()));
    }

    #[DataProvider('abilitiesOnAnotherUser')]
    public function test_instructor_can_not_manage_another_user(string $ability): void
    {
        $instructor = User::factory()->create();

        $this->assertFalse($instructor->can($ability, User::factory()->create()));
    }

    public function test_instructor_can_view_own_account(): void
    {
        $instructor = User::factory()->create();

        $this->assertTrue($instructor->can('view', $instructor));
    }

    public function test_admin_can_not_delete_own_account(): void
    {
        $admin = User::factory()->admin()->create();

        $this->assertFalse($admin->can('delete', $admin));
    }
}
