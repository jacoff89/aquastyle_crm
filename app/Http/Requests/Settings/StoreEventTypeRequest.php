<?php

namespace App\Http\Requests\Settings;

use App\Models\EventType;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreEventTypeRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', EventType::class);
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:100', Rule::unique(EventType::class)],
            'parent_id' => ['nullable', 'integer', Rule::exists(EventType::class, 'id')->whereNull('parent_id')],
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
        return ['parent_id.exists' => 'Выберите родительский тип из списка: у дочернего типа не может быть своих дочерних.'];
    }

    protected function prepareForValidation(): void
    {
        $this->merge(['name' => trim((string) $this->input('name'))]);
    }
}
