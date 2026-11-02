<?php

namespace App\Http\Requests\Settings;

use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Renaming a type, moving it under another parent, hiding it or showing it again.
 * Any field may be sent alone. A type that has children can not become a child itself.
 */
class UpdateEventTypeRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->route('eventType'));
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'name' => ['sometimes', 'required', 'string', 'max:100', Rule::unique('event_types')->ignore($this->route('eventType'))],
            'parent_id' => ['sometimes', 'nullable', 'integer', Rule::notIn([$this->route('eventType')->id]), Rule::exists('event_types', 'id')->whereNull('parent_id'), $this->childlessRule()],
            'is_active' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function attributes(): array
    {
        return ['name' => 'Название', 'parent_id' => 'Родительский тип'];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'parent_id.exists' => 'Выберите родительский тип из списка: у дочернего типа не может быть своих дочерних.',
            'parent_id.not_in' => 'Тип не может быть дочерним к самому себе.',
        ];
    }

    private function childlessRule(): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail): void {
            if ($value !== null && $this->route('eventType')->children()->exists()) {
                $fail('У этого типа есть дочерние, поэтому он не может стать дочерним.');
            }
        };
    }

    protected function prepareForValidation(): void
    {
        if ($this->has('name')) {
            $this->merge(['name' => trim((string) $this->input('name'))]);
        }
    }
}
