<?php

namespace Tests\Feature\Settings;

use App\Models\EventType;
use App\Models\Exercise;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class ExerciseControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_sees_exercises_in_list_order_with_hidden_ones(): void
    {
        $hidden = Exercise::factory()->hidden()->create(['name' => 'Буксировка']);
        Exercise::factory()->create(['name' => 'Всплытие']);

        $this->actingAs(User::factory()->admin()->create())
            ->get('/settings/exercises')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('settings/exercises/Index')
                ->has('exercises', 2)
                ->where('exercises.0', ['id' => $hidden->id, 'name' => 'Буксировка', 'isActive' => false, 'eventTypeIds' => []])
                ->where('exercises.1.name', 'Всплытие'));
    }

    public function test_admin_sees_event_types_of_each_exercise_and_every_type_in_tree_order(): void
    {
        $pool = EventType::factory()->create(['name' => 'Глубокий бассейн']);
        $theory = EventType::factory()->hidden()->create(['name' => 'Лекция']);
        $beginners = EventType::factory()->create(['parent_id' => $pool->id, 'name' => 'Начальный']);
        Exercise::factory()->offeredFor($beginners, $theory)->create();

        $this->actingAs(User::factory()->admin()->create())
            ->get('/settings/exercises')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->where('exercises.0.eventTypeIds', fn ($ids) => collect($ids)->sort()->values()->all() === collect([$beginners->id, $theory->id])->sort()->values()->all())
                ->where('eventTypes', fn ($types) => collect($types)->whereIn('id', [$pool->id, $beginners->id, $theory->id])->values()->all() === [
                    ['id' => $pool->id, 'parentId' => null, 'name' => 'Глубокий бассейн', 'isActive' => true],
                    ['id' => $beginners->id, 'parentId' => $pool->id, 'name' => 'Начальный', 'isActive' => true],
                    ['id' => $theory->id, 'parentId' => null, 'name' => 'Лекция', 'isActive' => false],
                ]));
    }

    public function test_admin_replaces_and_clears_event_types_of_exercise(): void
    {
        $pool = EventType::factory()->create();
        $beginners = EventType::factory()->create(['parent_id' => $pool->id]);
        $theory = EventType::factory()->create();
        $exercise = Exercise::factory()->offeredFor($theory)->create(['name' => 'Всплытие']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->patch("/settings/exercises/{$exercise->id}", ['event_type_ids' => [$pool->id, $beginners->id]])
            ->assertSessionHas('status', 'Типы занятий для «Всплытие» сохранены.');
        $this->assertEqualsCanonicalizing([$pool->id, $beginners->id], $exercise->eventTypes()->pluck('event_types.id')->all());

        $this->actingAs($admin)->patch("/settings/exercises/{$exercise->id}", ['event_type_ids' => []])->assertSessionHasNoErrors();
        $this->assertSame(0, $exercise->eventTypes()->count());
    }

    public function test_renaming_exercise_keeps_its_event_types(): void
    {
        $type = EventType::factory()->create();
        $exercise = Exercise::factory()->offeredFor($type)->create();

        $this->actingAs(User::factory()->admin()->create())
            ->patch("/settings/exercises/{$exercise->id}", ['name' => 'Новое'])
            ->assertSessionHasNoErrors();

        $this->assertSame([$type->id], $exercise->eventTypes()->pluck('event_types.id')->all());
    }

    public function test_unknown_and_repeated_event_types_are_refused(): void
    {
        $type = EventType::factory()->create();
        $exercise = Exercise::factory()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->patch("/settings/exercises/{$exercise->id}", ['event_type_ids' => [999]])->assertSessionHasErrors('event_type_ids.0');
        $this->actingAs($admin)->patch("/settings/exercises/{$exercise->id}", ['event_type_ids' => [$type->id, $type->id]])->assertSessionHasErrors();
        $this->actingAs(User::factory()->create())->patch("/settings/exercises/{$exercise->id}", ['event_type_ids' => [$type->id]])->assertForbidden();

        $this->assertSame(0, $exercise->eventTypes()->count());
    }

    public function test_instructor_can_not_open_add_or_change_exercises(): void
    {
        $exercise = Exercise::factory()->create();
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->get('/settings/exercises')->assertForbidden();
        $this->actingAs($instructor)->post('/settings/exercises', ['name' => 'Новое'])->assertForbidden();
        $this->actingAs($instructor)->patch("/settings/exercises/{$exercise->id}", ['is_active' => false])->assertForbidden();

        $this->assertDatabaseCount('exercises', 1);
        $this->assertTrue($exercise->fresh()->is_active);
    }

    public function test_guest_is_redirected_to_login(): void
    {
        $this->get('/settings/exercises')->assertRedirect('/login');
    }

    public function test_admin_adds_exercise(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/exercises', ['name' => '  Снятие маски  '])
            ->assertSessionHas('status', 'Упражнение «Снятие маски» добавлено.');

        $this->assertDatabaseHas('exercises', ['name' => 'Снятие маски', 'is_active' => true]);
    }

    public function test_exercise_name_is_required_and_unique(): void
    {
        Exercise::factory()->create(['name' => 'Снятие маски']);

        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->post('/settings/exercises', ['name' => ' '])->assertSessionHasErrors('name');
        $this->actingAs($admin)->post('/settings/exercises', ['name' => 'Снятие маски'])->assertSessionHasErrors('name');

        $this->assertDatabaseCount('exercises', 1);
    }

    public function test_admin_renames_hides_and_returns_exercise(): void
    {
        $exercise = Exercise::factory()->create(['name' => 'Старое']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->patch("/settings/exercises/{$exercise->id}", ['name' => 'Новое'])
            ->assertSessionHas('status', 'Упражнение переименовано в «Новое».');
        $this->actingAs($admin)
            ->patch("/settings/exercises/{$exercise->id}", ['is_active' => false])
            ->assertSessionHas('status', 'Упражнение «Новое» скрыто: выбрать его для клиента больше нельзя.');
        $this->assertFalse($exercise->fresh()->is_active);

        $this->actingAs($admin)
            ->patch("/settings/exercises/{$exercise->id}", ['is_active' => true])
            ->assertSessionHas('status', 'Упражнение «Новое» снова доступно для выбора.');
        $this->assertTrue($exercise->fresh()->is_active);
    }

    public function test_new_exercise_goes_to_the_end_of_the_list(): void
    {
        $first = Exercise::factory()->create(['name' => 'Я первое']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->post('/settings/exercises', ['name' => 'А второе']);

        $this->assertSame(
            [$first->id, Exercise::query()->where('name', 'А второе')->value('id')],
            Exercise::query()->ordered()->pluck('id')->all(),
        );
    }

    public function test_admin_moves_exercise_up_and_down(): void
    {
        $first = Exercise::factory()->create();
        $second = Exercise::factory()->create();
        $third = Exercise::factory()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->patch("/settings/exercises/{$third->id}/position", ['direction' => 'up'])->assertRedirect();
        $this->assertSame([$first->id, $third->id, $second->id], Exercise::query()->ordered()->pluck('id')->all());

        $this->actingAs($admin)->patch("/settings/exercises/{$first->id}/position", ['direction' => 'down'])->assertRedirect();
        $this->assertSame([$third->id, $first->id, $second->id], Exercise::query()->ordered()->pluck('id')->all());
    }

    public function test_moving_past_the_ends_of_the_list_changes_nothing(): void
    {
        $first = Exercise::factory()->create();
        $last = Exercise::factory()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->patch("/settings/exercises/{$first->id}/position", ['direction' => 'up'])->assertRedirect();
        $this->actingAs($admin)->patch("/settings/exercises/{$last->id}/position", ['direction' => 'down'])->assertRedirect();

        $this->assertSame([$first->id, $last->id], Exercise::query()->ordered()->pluck('id')->all());
    }

    public function test_exercise_position_needs_a_valid_direction_and_an_admin(): void
    {
        $first = Exercise::factory()->create();
        $second = Exercise::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->patch("/settings/exercises/{$second->id}/position", ['direction' => 'sideways'])
            ->assertSessionHasErrors('direction');
        $this->actingAs(User::factory()->create())
            ->patch("/settings/exercises/{$second->id}/position", ['direction' => 'up'])
            ->assertForbidden();

        $this->assertSame([$first->id, $second->id], Exercise::query()->ordered()->pluck('id')->all());
    }

    public function test_exercise_can_not_take_the_name_of_another(): void
    {
        Exercise::factory()->create(['name' => 'Первое']);
        $second = Exercise::factory()->create(['name' => 'Второе']);

        $this->actingAs(User::factory()->admin()->create())
            ->patch("/settings/exercises/{$second->id}", ['name' => 'Первое'])
            ->assertSessionHasErrors('name');

        $this->assertSame('Второе', $second->fresh()->name);
    }
}
