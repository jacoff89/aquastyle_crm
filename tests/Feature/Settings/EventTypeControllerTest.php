<?php

namespace Tests\Feature\Settings;

use App\Models\EventType;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class EventTypeControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_starter_types_exist_after_migration_in_this_order(): void
    {
        $this->assertSame(
            ['Теория', 'Бассейн', 'Открытая вода', 'Пробное погружение', 'Прочее'],
            EventType::query()->ordered()->pluck('name')->all(),
        );
    }

    public function test_admin_sees_types_in_list_order(): void
    {
        $hidden = EventType::factory()->hidden()->create(['name' => 'Ночное погружение']);

        $this->actingAs(User::factory()->admin()->create())
            ->get('/settings/event-types')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('settings/event-types/Index')
                ->has('eventTypes', 6)
                ->where('eventTypes.0.name', 'Теория')
                ->where('eventTypes.5', [
                    'id' => $hidden->id,
                    'name' => 'Ночное погружение',
                    'isActive' => false,
                ]));
    }

    public function test_instructor_can_not_open_event_types(): void
    {
        $this->actingAs(User::factory()->create())
            ->get('/settings/event-types')
            ->assertForbidden();
    }

    public function test_guest_is_redirected_to_login(): void
    {
        $this->get('/settings/event-types')->assertRedirect('/login');
    }

    public function test_admin_adds_type_to_the_end_of_the_list(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/event-types', ['name' => '  Спасательный курс  '])
            ->assertSessionHas('status', 'Тип «Спасательный курс» добавлен.');

        $this->assertSame('Спасательный курс', EventType::query()->ordered()->get()->last()->name);
    }

    public function test_instructor_can_not_add_type(): void
    {
        $this->actingAs(User::factory()->create())
            ->post('/settings/event-types', ['name' => 'Спасательный курс'])
            ->assertForbidden();

        $this->assertDatabaseMissing('event_types', ['name' => 'Спасательный курс']);
    }

    public function test_type_name_is_required(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/event-types', ['name' => '   '])
            ->assertSessionHasErrors(['name' => 'Поле «Название» обязательно для заполнения.']);
    }

    public function test_type_name_must_be_unique(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/event-types', ['name' => 'Бассейн'])
            ->assertSessionHasErrors(['name' => 'Такое значение поля «Название» уже занято.']);
    }

    public function test_admin_renames_type(): void
    {
        $pool = EventType::where('name', 'Бассейн')->sole();

        $this->actingAs(User::factory()->admin()->create())
            ->patch("/settings/event-types/{$pool->id}", ['name' => 'Бассейн (25 м)'])
            ->assertSessionHas('status', 'Тип переименован в «Бассейн (25 м)».');

        $this->assertSame('Бассейн (25 м)', $pool->fresh()->name);
    }

    public function test_type_can_keep_its_own_name_when_renamed(): void
    {
        $pool = EventType::where('name', 'Бассейн')->sole();

        $this->actingAs(User::factory()->admin()->create())
            ->patch("/settings/event-types/{$pool->id}", ['name' => 'Бассейн'])
            ->assertSessionHasNoErrors();
    }

    public function test_admin_hides_and_returns_type(): void
    {
        $admin = User::factory()->admin()->create();
        $pool = EventType::where('name', 'Бассейн')->sole();

        $this->actingAs($admin)
            ->patch("/settings/event-types/{$pool->id}", ['is_active' => false])
            ->assertSessionHas('status', 'Тип «Бассейн» скрыт: для новых занятий его не будет.');
        $this->assertFalse($pool->fresh()->is_active);

        $this->actingAs($admin)
            ->patch("/settings/event-types/{$pool->id}", ['is_active' => true])
            ->assertSessionHas('status', 'Тип «Бассейн» снова доступен для новых занятий.');
        $this->assertTrue($pool->fresh()->is_active);
    }

    public function test_instructor_can_not_update_type(): void
    {
        $pool = EventType::where('name', 'Бассейн')->sole();

        $this->actingAs(User::factory()->create())
            ->patch("/settings/event-types/{$pool->id}", ['is_active' => false])
            ->assertForbidden();

        $this->assertTrue($pool->fresh()->is_active);
    }
}
