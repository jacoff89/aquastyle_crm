<?php

namespace Tests\Feature\Settings;

use App\Models\Event;
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
                    'parentId' => null,
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

    public function test_admin_adds_child_type_shown_after_its_parent(): void
    {
        $pool = EventType::query()->where('name', 'Бассейн')->firstOrFail();

        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/event-types', ['name' => 'Начальный уровень', 'parent_id' => $pool->id])
            ->assertSessionHasNoErrors();

        $child = EventType::query()->where('name', 'Начальный уровень')->firstOrFail();

        $this->assertTrue($child->parent->is($pool));
        $this->assertSame('Бассейн / Начальный уровень', $child->full_name);
        $this->assertSame(
            ['Теория', 'Бассейн', 'Начальный уровень', 'Открытая вода', 'Пробное погружение', 'Прочее'],
            EventType::inTreeOrder()->pluck('name')->all(),
        );
    }

    public function test_child_type_can_not_have_children(): void
    {
        $child = EventType::factory()->create(['parent_id' => EventType::query()->firstOrFail()->id]);

        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/event-types', ['name' => 'Внук', 'parent_id' => $child->id])
            ->assertSessionHasErrors('parent_id');
    }

    public function test_calendar_filter_by_parent_type_includes_children(): void
    {
        $parent = EventType::query()->firstOrFail();
        $child = EventType::factory()->create(['parent_id' => $parent->id]);
        $other = EventType::factory()->create();
        $inParent = Event::factory()->at('2026-11-10 10:00', '2026-11-10 11:00')->create(['event_type_id' => $parent->id]);
        $inChild = Event::factory()->at('2026-11-10 12:00', '2026-11-10 13:00')->create(['event_type_id' => $child->id]);
        Event::factory()->at('2026-11-10 14:00', '2026-11-10 15:00')->create(['event_type_id' => $other->id]);

        $response = $this->actingAs(User::factory()->admin()->create())
            ->getJson("/calendar/events?start=2026-11-10&end=2026-11-10&event_type_id={$parent->id}")
            ->assertOk();

        $this->assertEqualsCanonicalizing([$inParent->id, $inChild->id], collect($response->json('data'))->pluck('id')->all());
    }

    public function test_admin_moves_type_under_another_parent_and_back(): void
    {
        $admin = User::factory()->admin()->create();
        $parent = EventType::query()->where('name', 'Бассейн')->firstOrFail();
        $type = EventType::query()->where('name', 'Прочее')->firstOrFail();

        $this->actingAs($admin)
            ->patch("/settings/event-types/{$type->id}", ['parent_id' => $parent->id])
            ->assertSessionHas('status', 'Тип «Прочее» перенесён в «Бассейн».');
        $this->assertTrue($type->refresh()->parent->is($parent));

        $this->actingAs($admin)
            ->patch("/settings/event-types/{$type->id}", ['parent_id' => ''])
            ->assertSessionHas('status', 'Тип «Прочее» теперь на верхнем уровне.');
        $this->assertNull($type->refresh()->parent_id);
    }

    public function test_type_can_not_become_its_own_child_or_a_grandchild(): void
    {
        $admin = User::factory()->admin()->create();
        $parent = EventType::query()->firstOrFail();
        $child = EventType::factory()->create(['parent_id' => $parent->id]);
        $other = EventType::factory()->create();

        $this->actingAs($admin)->patch("/settings/event-types/{$other->id}", ['parent_id' => $other->id])->assertSessionHasErrors('parent_id');
        $this->actingAs($admin)->patch("/settings/event-types/{$other->id}", ['parent_id' => $child->id])->assertSessionHasErrors('parent_id');
        $this->actingAs($admin)->patch("/settings/event-types/{$parent->id}", ['parent_id' => $other->id])->assertSessionHasErrors('parent_id');
    }
}
