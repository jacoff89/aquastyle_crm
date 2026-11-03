<?php

namespace Tests\Feature\Settings;

use App\Models\Exercise;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class ExerciseControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_sees_exercises_by_name_with_hidden_ones(): void
    {
        $hidden = Exercise::factory()->hidden()->create(['name' => 'Буксировка']);
        Exercise::factory()->create(['name' => 'Всплытие']);

        $this->actingAs(User::factory()->admin()->create())
            ->get('/settings/exercises')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('settings/exercises/Index')
                ->has('exercises', 2)
                ->where('exercises.0', ['id' => $hidden->id, 'name' => 'Буксировка', 'isActive' => false])
                ->where('exercises.1.name', 'Всплытие'));
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
