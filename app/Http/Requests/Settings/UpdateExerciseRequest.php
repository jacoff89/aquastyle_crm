<?php

namespace App\Http\Requests\Settings;

use App\Models\EventType;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Renaming an exercise, hiding it or showing it again, choosing the event types it is offered for.
 * Any field may be sent alone; `event_type_ids` replaces the whole list of types.
 */
class UpdateExerciseRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->route('exercise'));
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'name' => ['sometimes', 'required', 'string', 'max:150', Rule::unique('exercises')->ignore($this->route('exercise'))],
            'is_active' => ['sometimes', 'boolean'],
            'event_type_ids' => ['sometimes', 'array'],
            'event_type_ids.*' => ['integer', 'distinct', Rule::exists(EventType::class, 'id')],
        ];
    }

    /**
     * @return list<int>
     */
    public function eventTypeIds(): array
    {
        return array_map('intval', $this->validated('event_type_ids', []));
    }

    /**
     * @return array<string, string>
     */
    public function attributes(): array
    {
        return ['name' => 'Название'];
    }

    protected function prepareForValidation(): void
    {
        if ($this->has('name')) {
            $this->merge(['name' => trim((string) $this->input('name'))]);
        }
    }
}
