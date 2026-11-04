<?php

namespace App\Http\Requests\Locations;

use App\Models\Location;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreLocationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', Location::class);
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:150', Rule::unique(Location::class)],
            'address' => ['nullable', 'string', 'max:255'],
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
        $address = trim((string) $this->input('address'));

        $this->merge([
            'name' => trim((string) $this->input('name')),
            'address' => $address === '' ? null : $address,
        ]);
    }
}
