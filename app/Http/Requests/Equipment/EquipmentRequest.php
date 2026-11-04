<?php

namespace App\Http\Requests\Equipment;

use App\Enums\EquipmentStatus;
use App\Enums\Role;
use App\Models\Equipment;
use App\Models\EquipmentCategory;
use App\Models\Location;
use App\Models\User;
use Illuminate\Database\Query\Builder;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Exists;

/**
 * Fields shared by adding and editing an item of equipment. Hidden locations and
 * deactivated instructors are not offered for new assignments, but an item that
 * already has them keeps them.
 */
abstract class EquipmentRequest extends FormRequest
{
    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:150'],
            'category_id' => ['nullable', 'integer', Rule::exists(EquipmentCategory::class, 'id')],
            'inventory_number' => ['nullable', 'string', 'max:50', Rule::unique(Equipment::class)->ignore($this->editedEquipment())],
            'size' => ['nullable', 'string', 'max:30'],
            'status' => ['required', Rule::enum(EquipmentStatus::class)],
            'location_id' => ['nullable', 'integer', $this->locationRule()],
            'instructor_id' => ['nullable', 'integer', $this->instructorRule()],
            'notes' => ['nullable', 'string', 'max:2000'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function attributes(): array
    {
        return [
            'name' => 'Название',
            'inventory_number' => 'Инвентарный номер',
            'size' => 'Размер',
            'status' => 'Состояние',
            'notes' => 'Заметки',
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'category_id.exists' => 'Категория не найдена.',
            'inventory_number.unique' => 'Снаряжение с таким инвентарным номером уже есть.',
            'location_id.exists' => 'Локация не найдена или скрыта.',
            'instructor_id.exists' => 'Инструктор не найден или отключён.',
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'name' => trim((string) $this->input('name')),
            'inventory_number' => $this->trimmedOrNull('inventory_number'),
            'size' => $this->trimmedOrNull('size'),
            'category_id' => $this->filled('category_id') ? $this->input('category_id') : null,
            'location_id' => $this->filled('location_id') ? $this->input('location_id') : null,
            'instructor_id' => $this->filled('instructor_id') ? $this->input('instructor_id') : null,
        ]);
    }

    /**
     * The item being edited, whose current location and instructor stay allowed.
     */
    protected function editedEquipment(): ?Equipment
    {
        return null;
    }

    private function locationRule(): Exists
    {
        $currentId = $this->editedEquipment()?->location_id;

        return Rule::exists(Location::class, 'id')->where(fn (Builder $query) => $query->where(fn (Builder $query) => $query
            ->where('is_active', true)
            ->when($currentId, fn (Builder $query, int $id) => $query->orWhere('id', $id))));
    }

    private function instructorRule(): Exists
    {
        $currentId = $this->editedEquipment()?->instructor_id;

        return Rule::exists(User::class, 'id')->where(fn (Builder $query) => $query
            ->whereJsonContains('roles', Role::Instructor->value)
            ->where(fn (Builder $query) => $query
                ->where('is_active', true)
                ->when($currentId, fn (Builder $query, int $id) => $query->orWhere('id', $id))));
    }

    private function trimmedOrNull(string $key): ?string
    {
        $value = trim((string) $this->input($key));

        return $value === '' ? null : $value;
    }
}
