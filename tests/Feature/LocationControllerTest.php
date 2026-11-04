<?php

namespace Tests\Feature;

use App\Models\Equipment;
use App\Models\Location;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class LocationControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_sees_active_locations_first_with_their_equipment_count(): void
    {
        Location::factory()->hidden()->create(['name' => 'Аквапарк']);
        $pool = Location::factory()->create(['name' => 'Дельфин', 'address' => 'ул. Гагарина, 12']);
        Equipment::factory()->count(2)->at($pool)->create();

        $this->actingAs(User::factory()->admin()->create())
            ->get('/locations')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('locations/Index')
                ->has('locations', 2)
                ->where('locations.0', ['id' => $pool->id, 'name' => 'Дельфин', 'address' => 'ул. Гагарина, 12', 'isActive' => true, 'equipmentCount' => 2])
                ->where('locations.1.name', 'Аквапарк')
                ->where('locations.1.isActive', false));
    }

    public function test_admin_adds_location(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/locations', ['name' => '  Дельфин  ', 'address' => ' '])
            ->assertSessionHas('status', 'Локация «Дельфин» добавлена.');

        $this->assertDatabaseHas('locations', ['name' => 'Дельфин', 'address' => null, 'is_active' => true]);
    }

    public function test_location_name_is_required_and_unique(): void
    {
        Location::factory()->create(['name' => 'Дельфин']);
        $other = Location::factory()->create(['name' => 'Озеро']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->post('/locations', ['name' => ' '])->assertSessionHasErrors(['name' => 'Поле «Название» обязательно для заполнения.']);
        $this->actingAs($admin)->post('/locations', ['name' => 'Дельфин'])->assertSessionHasErrors('name');
        $this->actingAs($admin)->patch("/locations/{$other->id}", ['name' => 'Дельфин'])->assertSessionHasErrors('name');

        $this->assertDatabaseCount('locations', 2);
        $this->assertSame('Озеро', $other->fresh()->name);
    }

    public function test_admin_edits_hides_and_returns_location(): void
    {
        $location = Location::factory()->create(['name' => 'Старое']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->patch("/locations/{$location->id}", ['name' => 'Дельфин', 'address' => 'ул. Гагарина, 12'])
            ->assertSessionHas('status', 'Локация «Дельфин» сохранена.');
        $this->assertDatabaseHas('locations', ['id' => $location->id, 'name' => 'Дельфин', 'address' => 'ул. Гагарина, 12']);

        $this->actingAs($admin)
            ->patch("/locations/{$location->id}", ['is_active' => false])
            ->assertSessionHas('status', 'Локация «Дельфин» скрыта: в занятиях она больше не предлагается.');
        $this->assertFalse($location->fresh()->is_active);

        $this->actingAs($admin)
            ->patch("/locations/{$location->id}", ['is_active' => true])
            ->assertSessionHas('status', 'Локация «Дельфин» снова предлагается в занятиях.');
        $this->assertTrue($location->fresh()->is_active);
    }

    public function test_instructor_can_not_open_add_or_change_locations(): void
    {
        $location = Location::factory()->create();
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->get('/locations')->assertForbidden();
        $this->actingAs($instructor)->post('/locations', ['name' => 'Новая'])->assertForbidden();
        $this->actingAs($instructor)->patch("/locations/{$location->id}", ['is_active' => false])->assertForbidden();

        $this->assertDatabaseCount('locations', 1);
        $this->assertTrue($location->fresh()->is_active);
    }

    public function test_guest_is_redirected_to_login(): void
    {
        $this->get('/locations')->assertRedirect('/login');
    }

    public function test_calendar_suggests_only_active_locations_by_name(): void
    {
        Location::factory()->create(['name' => 'Озеро', 'address' => null]);
        Location::factory()->create(['name' => 'Дельфин', 'address' => 'ул. Гагарина, 12']);
        Location::factory()->hidden()->create(['name' => 'Аквапарк']);

        $this->actingAs(User::factory()->create())
            ->get('/calendar')
            ->assertInertia(fn (Assert $page) => $page
                ->where('locations', [
                    ['name' => 'Дельфин', 'address' => 'ул. Гагарина, 12'],
                    ['name' => 'Озеро', 'address' => null],
                ]));
    }
}
