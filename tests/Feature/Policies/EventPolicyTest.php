<?php

namespace Tests\Feature\Policies;

use App\Models\Event;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class EventPolicyTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    #[DataProvider('everyRole')]
    public function test_every_role_views_creates_and_edits_any_event(bool $isAdmin): void
    {
        $user = $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
        $someoneElsesEvent = Event::factory()->ledBy(User::factory()->create())->create();

        $this->assertTrue($user->can('viewAny', Event::class));
        $this->assertTrue($user->can('create', Event::class));
        $this->assertTrue($user->can('update', $someoneElsesEvent));
    }
}
