<?php

namespace App\Http\Requests\Locations;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Renaming a location, changing its address, hiding it or showing it again.
 * Any field may be sent alone.
 */
class UpdateLocationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->route('location'));
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'name' => ['sometimes', 'required', 'string', 'max:150', Rule::unique('locations')->ignore($this->route('location'))],
            'address' => ['sometimes', 'nullable', 'string', 'max:255'],
            'is_active' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function attributes(): array
    {
        return ['name' => 'Название', 'address' => 'Адрес'];
    }

    protected function prepareForValidation(): void
    {
        if ($this->has('name')) {
            $this->merge(['name' => trim((string) $this->input('name'))]);
        }

        if ($this->has('address')) {
            $address = trim((string) $this->input('address'));
            $this->merge(['address' => $address === '' ? null : $address]);
        }
    }
}
