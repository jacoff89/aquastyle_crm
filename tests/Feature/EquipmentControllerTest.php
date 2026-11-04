<?php

namespace Tests\Feature;

use App\Enums\EquipmentStatus;
use App\Models\Equipment;
use App\Models\Location;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class EquipmentControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_sees_equipment_with_its_location_and_instructor(): void
    {
        $pool = Location::factory()->create(['name' => 'Дельфин']);
        $instructor = User::factory()->create(['name' => 'Анна', 'last_name' => 'Волкова']);
        $regulator = Equipment::factory()->at($pool)->assignedTo($instructor)->create([
            'name' => 'Регулятор',
            'inventory_number' => 'R-001',
            'size' => null,
            'status' => EquipmentStatus::Repair,
        ]);
        Equipment::factory()->create(['name' => 'Ласты']);

        $this->actingAs(User::factory()->admin()->create())
            ->get('/equipment')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('equipment/Index')
                ->has('equipment', 2)
                ->where('equipment.0.name', 'Ласты')
                ->where('equipment.0.locationName', null)
                ->where('equipment.0.instructorName', null)
                ->where('equipment.1', [
                    'id' => $regulator->id,
                    'name' => 'Регулятор',
                    'categoryId' => null,
                    'categoryName' => null,
                    'inventoryNumber' => 'R-001',
                    'size' => null,
                    'status' => 'repair',
                    'statusLabel' => 'В ремонте',
                    'locationId' => $pool->id,
                    'locationName' => 'Дельфин',
                    'instructorId' => $instructor->id,
                    'instructorName' => 'Анна Волкова',
                ])
                ->where('statuses', [
                    ['value' => 'in_use', 'label' => 'В работе'],
                    ['value' => 'repair', 'label' => 'В ремонте'],
                    ['value' => 'written_off', 'label' => 'Списано'],
                ]));
    }

    public function test_form_offers_every_location_and_instructor_marking_hidden_ones(): void
    {
        Location::factory()->hidden()->create(['name' => 'Аквапарк']);
        Location::factory()->create(['name' => 'Дельфин']);
        User::factory()->inactive()->create(['name' => 'Ольга']);
        User::factory()->create(['name' => 'Борис']);

        $this->actingAs(User::factory()->admin()->create())
            ->get('/equipment/create')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('equipment/Form')
                ->where('item', null)
                ->where('locations.0.name', 'Дельфин')
                ->where('locations.1', fn ($location) => $location['name'] === 'Аквапарк' && $location['isActive'] === false)
                ->has('instructors', 2)
                ->where('instructors.0.name', 'Борис')
                ->where('instructors.1.isActive', false));
    }

    public function test_admin_adds_equipment_at_a_location_for_an_instructor(): void
    {
        $pool = Location::factory()->create();
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->post('/equipment', [
                'name' => ' Регулятор ',
                'inventory_number' => ' R-001 ',
                'size' => '',
                'status' => 'in_use',
                'location_id' => $pool->id,
                'instructor_id' => $instructor->id,
                'notes' => 'Обслужен в октябре',
            ])
            ->assertRedirect('/equipment')
            ->assertSessionHas('status', 'Снаряжение «Регулятор» добавлено в реестр.');

        $this->assertDatabaseHas('equipment', [
            'name' => 'Регулятор',
            'inventory_number' => 'R-001',
            'size' => null,
            'status' => 'in_use',
            'location_id' => $pool->id,
            'instructor_id' => $instructor->id,
            'notes' => 'Обслужен в октябре',
        ]);
    }

    public function test_equipment_may_have_no_location_and_no_instructor(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/equipment', ['name' => 'Ласты', 'status' => 'in_use', 'location_id' => '', 'instructor_id' => ''])
            ->assertSessionHasNoErrors();

        $this->assertDatabaseHas('equipment', ['name' => 'Ласты', 'inventory_number' => null, 'location_id' => null, 'instructor_id' => null]);
    }

    public function test_name_and_a_known_status_are_required(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/equipment', ['name' => ' ', 'status' => 'lost'])
            ->assertSessionHasErrors(['name' => 'Поле «Название» обязательно для заполнения.', 'status' => 'Выбрано недопустимое значение поля «Состояние».']);

        $this->assertDatabaseCount('equipment', 0);
    }

    public function test_inventory_number_is_unique(): void
    {
        Equipment::factory()->create(['inventory_number' => 'R-001']);
        $other = Equipment::factory()->create(['inventory_number' => 'R-002']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->post('/equipment', ['name' => 'Регулятор', 'inventory_number' => 'R-001', 'status' => 'in_use'])
            ->assertSessionHasErrors(['inventory_number' => 'Снаряжение с таким инвентарным номером уже есть.']);
        $this->actingAs($admin)
            ->put("/equipment/{$other->id}", ['name' => 'Регулятор', 'inventory_number' => 'R-001', 'status' => 'in_use'])
            ->assertSessionHasErrors('inventory_number');
        $this->actingAs($admin)
            ->put("/equipment/{$other->id}", ['name' => 'Регулятор', 'inventory_number' => 'R-002', 'status' => 'in_use'])
            ->assertSessionHasNoErrors();

        $this->assertDatabaseCount('equipment', 2);
    }

    public function test_new_equipment_can_not_go_to_a_hidden_location_or_an_inactive_instructor(): void
    {
        $hidden = Location::factory()->hidden()->create();
        $former = User::factory()->inactive()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->post('/equipment', ['name' => 'Регулятор', 'status' => 'in_use', 'location_id' => $hidden->id, 'instructor_id' => $former->id])
            ->assertSessionHasErrors([
                'location_id' => 'Локация не найдена или скрыта.',
                'instructor_id' => 'Инструктор не найден или отключён.',
            ]);

        $this->assertDatabaseCount('equipment', 0);
    }

    public function test_equipment_can_only_be_assigned_to_an_instructor(): void
    {
        $administrator = User::factory()->admin()->create();

        $this->actingAs($administrator)
            ->post('/equipment', ['name' => 'Регулятор', 'status' => 'in_use', 'instructor_id' => $administrator->id])
            ->assertSessionHasErrors('instructor_id');
    }

    public function test_edited_equipment_keeps_its_hidden_location_and_inactive_instructor(): void
    {
        $hidden = Location::factory()->hidden()->create();
        $former = User::factory()->inactive()->create();
        $item = Equipment::factory()->at($hidden)->assignedTo($former)->create(['name' => 'Регулятор']);

        $this->actingAs(User::factory()->admin()->create())
            ->put("/equipment/{$item->id}", [
                'name' => 'Регулятор',
                'status' => 'written_off',
                'location_id' => $hidden->id,
                'instructor_id' => $former->id,
            ])
            ->assertRedirect('/equipment')
            ->assertSessionHas('status', 'Изменения сохранены: Регулятор.');

        $item->refresh();
        $this->assertSame(EquipmentStatus::WrittenOff, $item->status);
        $this->assertTrue($item->location->is($hidden));
        $this->assertTrue($item->instructor->is($former));
    }

    public function test_admin_opens_equipment_for_editing(): void
    {
        $pool = Location::factory()->create();
        $item = Equipment::factory()->at($pool)->create(['name' => 'Регулятор', 'inventory_number' => 'R-001', 'notes' => 'Обслужен']);

        $this->actingAs(User::factory()->admin()->create())
            ->get("/equipment/{$item->id}/edit")
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('equipment/Form')
                ->where('item.name', 'Регулятор')
                ->where('item.inventoryNumber', 'R-001')
                ->where('item.locationId', $pool->id)
                ->where('item.instructorId', null)
                ->where('item.notes', 'Обслужен'));
    }

    public function test_instructor_can_not_open_add_or_change_equipment(): void
    {
        $item = Equipment::factory()->create(['name' => 'Регулятор']);
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->get('/equipment')->assertForbidden();
        $this->actingAs($instructor)->get('/equipment/create')->assertForbidden();
        $this->actingAs($instructor)->get("/equipment/{$item->id}/edit")->assertForbidden();
        $this->actingAs($instructor)->post('/equipment', ['name' => 'Ласты', 'status' => 'in_use'])->assertForbidden();
        $this->actingAs($instructor)->put("/equipment/{$item->id}", ['name' => 'Ласты', 'status' => 'in_use'])->assertForbidden();

        $this->assertDatabaseCount('equipment', 1);
        $this->assertSame('Регулятор', $item->fresh()->name);
    }

    public function test_guest_is_redirected_to_login(): void
    {
        $this->get('/equipment')->assertRedirect('/login');
    }

    public function test_instructor_page_shows_how_much_equipment_is_assigned(): void
    {
        $instructor = User::factory()->create();
        Equipment::factory()->count(2)->assignedTo($instructor)->create();
        Equipment::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->get("/instructors/{$instructor->id}")
            ->assertInertia(fn (Assert $page) => $page->where('instructor.equipmentCount', 2));
    }
}
