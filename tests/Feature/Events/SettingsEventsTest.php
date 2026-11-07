<?php

namespace Tests\Feature\Events;

use App\Enums\EquipmentStatus;
use App\Events\Equipment\EquipmentAssigned;
use App\Events\Equipment\EquipmentCategoryCreated;
use App\Events\Equipment\EquipmentCategoryUpdated;
use App\Events\Equipment\EquipmentCreated;
use App\Events\Equipment\EquipmentStatusChanged;
use App\Events\Equipment\EquipmentUpdated;
use App\Events\Settings\EventTypeCreated;
use App\Events\Settings\EventTypesReordered;
use App\Events\Settings\EventTypeUpdated;
use App\Events\Settings\ExerciseCreated;
use App\Events\Settings\ExerciseEventTypesChanged;
use App\Events\Settings\ExercisesReordered;
use App\Events\Settings\ExerciseUpdated;
use App\Events\Settings\LocationCreated;
use App\Events\Settings\LocationUpdated;
use App\Models\Equipment;
use App\Models\EquipmentCategory;
use App\Models\EventType;
use App\Models\Exercise;
use App\Models\Location;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Event;
use Tests\TestCase;

/**
 * Changes to the reference lists (event types, exercises, locations) and to the equipment
 * registry announce domain events.
 */
class SettingsEventsTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_event_types_announce_adding_and_editing(): void
    {
        $admin = User::factory()->admin()->create();
        Event::fake([EventTypeCreated::class, EventTypeUpdated::class]);

        $this->actingAs($admin)->post('/settings/event-types', ['name' => 'Фридайвинг'])->assertSessionHasNoErrors();
        $type = EventType::where('name', 'Фридайвинг')->sole();
        $this->patch("/settings/event-types/{$type->id}", ['is_active' => false])->assertSessionHasNoErrors();

        Event::assertDispatched(EventTypeCreated::class, fn (EventTypeCreated $event): bool => $event->eventType->is($type) && $event->actor->is($admin));
        Event::assertDispatched(EventTypeUpdated::class, fn (EventTypeUpdated $event): bool => $event->changes->toArray() === ['is_active' => ['old' => true, 'new' => false]]);
    }

    public function test_moving_an_event_type_is_announced_only_when_it_moves(): void
    {
        $admin = User::factory()->admin()->create();
        $first = EventType::query()->ordered()->firstOrFail();
        Event::fake([EventTypesReordered::class]);

        $this->actingAs($admin)->patch("/settings/event-types/{$first->id}/position", ['direction' => 'up'])->assertRedirect();
        Event::assertNotDispatched(EventTypesReordered::class);

        $this->patch("/settings/event-types/{$first->id}/position", ['direction' => 'down'])->assertRedirect();
        Event::assertDispatched(EventTypesReordered::class, fn (EventTypesReordered $event): bool => $event->eventType->is($first)
            && $event->direction === 'down'
            && $event->actor->is($admin));
    }

    public function test_exercises_announce_adding_editing_moving_and_their_event_types(): void
    {
        $admin = User::factory()->admin()->create();
        $pool = EventType::factory()->create();
        $sea = EventType::factory()->create();
        Exercise::factory()->create(['name' => 'Всплытие']);
        Event::fake([ExerciseCreated::class, ExerciseUpdated::class, ExerciseEventTypesChanged::class, ExercisesReordered::class]);

        $this->actingAs($admin)->post('/settings/exercises', ['name' => 'Снятие маски'])->assertSessionHasNoErrors();
        $exercise = Exercise::where('name', 'Снятие маски')->sole();
        $exercise->eventTypes()->attach($pool);
        $this->patch("/settings/exercises/{$exercise->id}", ['name' => 'Снятие и надевание маски', 'event_type_ids' => [$sea->id]])->assertSessionHasNoErrors();
        $this->patch("/settings/exercises/{$exercise->id}/position", ['direction' => 'up'])->assertRedirect();

        Event::assertDispatched(ExerciseCreated::class, fn (ExerciseCreated $event): bool => $event->exercise->is($exercise) && $event->actor->is($admin));
        Event::assertDispatched(ExerciseUpdated::class, fn (ExerciseUpdated $event): bool => $event->changes->attributes() === ['name']);
        Event::assertDispatched(ExerciseEventTypesChanged::class, fn (ExerciseEventTypesChanged $event): bool => $event->attachedEventTypeIds === [$sea->id]
            && $event->detachedEventTypeIds === [$pool->id]);
        Event::assertDispatched(ExercisesReordered::class, fn (ExercisesReordered $event): bool => $event->exercise->is($exercise) && $event->direction === 'up');
    }

    public function test_saving_the_same_event_types_of_an_exercise_is_not_announced(): void
    {
        $admin = User::factory()->admin()->create();
        $pool = EventType::factory()->create();
        $exercise = Exercise::factory()->offeredFor($pool)->create();
        Event::fake([ExerciseUpdated::class, ExerciseEventTypesChanged::class]);

        $this->actingAs($admin)->patch("/settings/exercises/{$exercise->id}", ['event_type_ids' => [$pool->id]])->assertSessionHasNoErrors();

        Event::assertNotDispatched(ExerciseUpdated::class);
        Event::assertNotDispatched(ExerciseEventTypesChanged::class);
    }

    public function test_locations_announce_adding_and_editing(): void
    {
        $admin = User::factory()->admin()->create();
        Event::fake([LocationCreated::class, LocationUpdated::class]);

        $this->actingAs($admin)->post('/locations', ['name' => 'Дельфин'])->assertSessionHasNoErrors();
        $location = Location::sole();
        $this->patch("/locations/{$location->id}", ['name' => 'Дельфин', 'address' => 'ул. Труда, 1'])->assertSessionHasNoErrors();

        Event::assertDispatched(LocationCreated::class, fn (LocationCreated $event): bool => $event->location->is($location) && $event->actor->is($admin));
        Event::assertDispatched(LocationUpdated::class, fn (LocationUpdated $event): bool => $event->changes->toArray() === ['address' => ['old' => null, 'new' => 'ул. Труда, 1']]);
    }

    public function test_equipment_added_with_an_instructor_is_announced_as_assigned_too(): void
    {
        $admin = User::factory()->admin()->create();
        $instructor = User::factory()->create();
        Event::fake([EquipmentCreated::class, EquipmentAssigned::class]);

        $this->actingAs($admin)->post('/equipment', ['name' => 'Регулятор', 'status' => 'in_use', 'instructor_id' => $instructor->id])->assertSessionHasNoErrors();
        $item = Equipment::sole();

        Event::assertDispatched(EquipmentCreated::class, fn (EquipmentCreated $event): bool => $event->equipment->is($item) && $event->actor->is($admin));
        Event::assertDispatched(EquipmentAssigned::class, fn (EquipmentAssigned $event): bool => $event->equipment->is($item) && $event->previousInstructorId === null);
    }

    public function test_equipment_added_without_an_instructor_is_not_announced_as_assigned(): void
    {
        Event::fake([EquipmentCreated::class, EquipmentAssigned::class]);

        $this->actingAs(User::factory()->admin()->create())->post('/equipment', ['name' => 'Ласты', 'status' => 'in_use'])->assertSessionHasNoErrors();

        Event::assertDispatchedTimes(EquipmentCreated::class, 1);
        Event::assertNotDispatched(EquipmentAssigned::class);
    }

    public function test_editing_equipment_announces_a_new_instructor_and_a_new_status(): void
    {
        $previous = User::factory()->create();
        $next = User::factory()->create();
        $item = Equipment::factory()->create(['name' => 'Регулятор', 'status' => EquipmentStatus::InUse, 'instructor_id' => $previous->id]);
        Event::fake([EquipmentUpdated::class, EquipmentAssigned::class, EquipmentStatusChanged::class]);

        $this->actingAs(User::factory()->admin()->create())
            ->put("/equipment/{$item->id}", ['name' => 'Регулятор', 'category_id' => $item->category_id, 'inventory_number' => $item->inventory_number, 'size' => $item->size, 'location_id' => $item->location_id, 'notes' => $item->notes, 'status' => 'repair', 'instructor_id' => $next->id])
            ->assertSessionHasNoErrors();

        Event::assertDispatched(EquipmentUpdated::class, fn (EquipmentUpdated $event): bool => $event->changes->attributes() === ['status', 'instructor_id']);
        Event::assertDispatched(EquipmentAssigned::class, fn (EquipmentAssigned $event): bool => $event->equipment->instructor_id === $next->id
            && $event->previousInstructorId === $previous->id);
        Event::assertDispatched(EquipmentStatusChanged::class, fn (EquipmentStatusChanged $event): bool => $event->equipment->status === EquipmentStatus::Repair
            && $event->previousStatus === EquipmentStatus::InUse);
    }

    public function test_equipment_categories_announce_adding_and_renaming(): void
    {
        $admin = User::factory()->admin()->create();
        Event::fake([EquipmentCategoryCreated::class, EquipmentCategoryUpdated::class]);

        $this->actingAs($admin)->post('/equipment-categories', ['name' => 'Регуляторы'])->assertSessionHasNoErrors();
        $category = EquipmentCategory::sole();
        $this->patch("/equipment-categories/{$category->id}", ['name' => 'Регуляторы и октопусы'])->assertSessionHasNoErrors();

        Event::assertDispatched(EquipmentCategoryCreated::class, fn (EquipmentCategoryCreated $event): bool => $event->category->is($category) && $event->actor->is($admin));
        Event::assertDispatched(EquipmentCategoryUpdated::class, fn (EquipmentCategoryUpdated $event): bool => $event->changes->toArray() === ['name' => ['old' => 'Регуляторы', 'new' => 'Регуляторы и октопусы']]);
    }
}
