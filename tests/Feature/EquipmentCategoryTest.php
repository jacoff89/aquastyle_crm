<?php

namespace Tests\Feature;

use App\Models\Equipment;
use App\Models\EquipmentCategory;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class EquipmentCategoryTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_adds_category_from_the_equipment_page(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->from('/equipment')
            ->post('/equipment-categories', ['name' => '  Регуляторы  '])
            ->assertRedirect('/equipment')
            ->assertSessionHas('status', 'Категория «Регуляторы» добавлена.');

        $this->assertDatabaseHas('equipment_categories', ['name' => 'Регуляторы']);
    }

    public function test_category_name_is_required_and_unique(): void
    {
        EquipmentCategory::factory()->create(['name' => 'Регуляторы']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->post('/equipment-categories', ['name' => ' '])->assertSessionHasErrors(['name' => 'Поле «Название» обязательно для заполнения.']);
        $this->actingAs($admin)->post('/equipment-categories', ['name' => 'Регуляторы'])->assertSessionHasErrors(['name' => 'Такая категория уже есть.']);

        $this->assertDatabaseCount('equipment_categories', 1);
    }

    public function test_instructor_can_not_add_category(): void
    {
        $this->actingAs(User::factory()->create())
            ->post('/equipment-categories', ['name' => 'Регуляторы'])
            ->assertForbidden();

        $this->assertDatabaseCount('equipment_categories', 0);
    }

    public function test_admin_renames_category_and_its_equipment_stays_in_it(): void
    {
        $category = EquipmentCategory::factory()->create(['name' => 'Регуляторы']);
        $item = Equipment::factory()->inCategory($category)->create();

        $this->actingAs(User::factory()->admin()->create())
            ->from('/equipment')
            ->patch("/equipment-categories/{$category->id}", ['name' => '  Регуляторы и октопусы  '])
            ->assertRedirect('/equipment')
            ->assertSessionHas('status', 'Категория переименована в «Регуляторы и октопусы».');

        $this->assertSame('Регуляторы и октопусы', $category->fresh()->name);
        $this->assertTrue($item->fresh()->category->is($category));
    }

    public function test_category_can_not_be_renamed_to_an_empty_or_taken_name(): void
    {
        EquipmentCategory::factory()->create(['name' => 'Маски']);
        $category = EquipmentCategory::factory()->create(['name' => 'Регуляторы']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->patch("/equipment-categories/{$category->id}", ['name' => ' '])->assertSessionHasErrors(['name' => 'Поле «Название» обязательно для заполнения.']);
        $this->actingAs($admin)->patch("/equipment-categories/{$category->id}", ['name' => 'Маски'])->assertSessionHasErrors(['name' => 'Такая категория уже есть.']);
        $this->actingAs($admin)->patch("/equipment-categories/{$category->id}", ['name' => 'Регуляторы'])->assertSessionHasNoErrors();

        $this->assertSame('Регуляторы', $category->fresh()->name);
    }

    public function test_instructor_can_not_rename_category(): void
    {
        $category = EquipmentCategory::factory()->create(['name' => 'Регуляторы']);

        $this->actingAs(User::factory()->create())
            ->patch("/equipment-categories/{$category->id}", ['name' => 'Маски'])
            ->assertForbidden();

        $this->assertSame('Регуляторы', $category->fresh()->name);
    }

    public function test_equipment_page_lists_categories_and_the_category_of_each_item(): void
    {
        $suits = EquipmentCategory::factory()->create(['name' => 'Гидрокостюмы']);
        $regulators = EquipmentCategory::factory()->create(['name' => 'Регуляторы']);
        Equipment::factory()->inCategory($suits)->create(['name' => 'Гидрокостюм 7 мм']);
        Equipment::factory()->create(['name' => 'Ласты']);

        $this->actingAs(User::factory()->admin()->create())
            ->get('/equipment')
            ->assertInertia(fn (Assert $page) => $page
                ->where('categories', [
                    ['id' => $suits->id, 'name' => 'Гидрокостюмы'],
                    ['id' => $regulators->id, 'name' => 'Регуляторы'],
                ])
                ->where('equipment.0.categoryId', $suits->id)
                ->where('equipment.0.categoryName', 'Гидрокостюмы')
                ->where('equipment.1.name', 'Ласты')
                ->where('equipment.1.categoryId', null)
                ->where('equipment.1.categoryName', null));
    }

    public function test_admin_puts_equipment_in_a_category_and_takes_it_out(): void
    {
        $regulators = EquipmentCategory::factory()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->post('/equipment', ['name' => 'Регулятор', 'category_id' => $regulators->id, 'status' => 'in_use'])
            ->assertSessionHasNoErrors();
        $item = Equipment::query()->sole();
        $this->assertTrue($item->category->is($regulators));

        $this->actingAs($admin)
            ->put("/equipment/{$item->id}", ['name' => 'Регулятор', 'category_id' => '', 'status' => 'in_use'])
            ->assertSessionHasNoErrors();
        $this->assertNull($item->fresh()->category_id);
    }

    public function test_unknown_category_is_refused(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/equipment', ['name' => 'Регулятор', 'category_id' => 999, 'status' => 'in_use'])
            ->assertSessionHasErrors(['category_id' => 'Категория не найдена.']);

        $this->assertDatabaseCount('equipment', 0);
    }
}
