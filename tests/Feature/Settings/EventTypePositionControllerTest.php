<?php

namespace Tests\Feature\Settings;

use App\Models\EventType;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

class EventTypePositionControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_type_moves_up_one_place(): void
    {
        $this->moveAs(User::factory()->admin()->create(), 'Открытая вода', 'up');

        $this->assertSame(
            ['Теория', 'Открытая вода', 'Бассейн', 'Пробное погружение', 'Прочее'],
            $this->orderedNames(),
        );
    }

    public function test_type_moves_down_one_place(): void
    {
        $this->moveAs(User::factory()->admin()->create(), 'Теория', 'down');

        $this->assertSame(
            ['Бассейн', 'Теория', 'Открытая вода', 'Пробное погружение', 'Прочее'],
            $this->orderedNames(),
        );
    }

    public function test_first_type_stays_first_when_moved_up(): void
    {
        $this->moveAs(User::factory()->admin()->create(), 'Теория', 'up');

        $this->assertSame('Теория', $this->orderedNames()[0]);
    }

    public function test_last_type_stays_last_when_moved_down(): void
    {
        $this->moveAs(User::factory()->admin()->create(), 'Прочее', 'down');

        $this->assertSame('Прочее', $this->orderedNames()[4]);
    }

    public function test_types_sharing_a_position_still_move_correctly(): void
    {
        EventType::query()->update(['sort_order' => 1]);

        $this->moveAs(User::factory()->admin()->create(), 'Бассейн', 'up');

        $this->assertSame('Бассейн', $this->orderedNames()[0]);
        $this->assertSame([1, 2, 3, 4, 5], EventType::query()->ordered()->pluck('sort_order')->all());
    }

    public function test_direction_must_be_up_or_down(): void
    {
        $theory = EventType::where('name', 'Теория')->sole();

        $this->actingAs(User::factory()->admin()->create())
            ->patch("/settings/event-types/{$theory->id}/position", ['direction' => 'sideways'])
            ->assertSessionHasErrors('direction');
    }

    public function test_instructor_can_not_reorder_types(): void
    {
        $this->moveAs(User::factory()->create(), 'Прочее', 'up')->assertForbidden();

        $this->assertSame('Прочее', $this->orderedNames()[4]);
    }

    private function moveAs(User $user, string $name, string $direction): TestResponse
    {
        $eventType = EventType::where('name', $name)->sole();

        return $this->actingAs($user)->patch("/settings/event-types/{$eventType->id}/position", ['direction' => $direction]);
    }

    /**
     * @return list<string>
     */
    private function orderedNames(): array
    {
        return EventType::query()->ordered()->pluck('name')->all();
    }
}
