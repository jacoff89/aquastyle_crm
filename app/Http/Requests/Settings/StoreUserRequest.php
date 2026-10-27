<?php

namespace App\Http\Requests\Settings;

use App\Enums\Role;
use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Arr;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;

class StoreUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', User::class);
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', Rule::unique(User::class)],
            'phone' => ['nullable', 'string', 'max:32'],
            'roles' => ['required', 'array', 'min:1'],
            'roles.*' => ['distinct', Rule::enum(Role::class)],
            'color' => [Rule::requiredIf($this->hasInstructorRole()), 'nullable', 'string', 'regex:/^#[0-9a-f]{6}$/'],
            'is_active' => ['boolean'],
            'notes' => ['nullable', 'string', 'max:2000'],
            'password' => ['required', 'confirmed', Password::defaults()],
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'email' => mb_strtolower(trim((string) $this->input('email'))),
            'color' => filled($this->input('color')) ? mb_strtolower(trim((string) $this->input('color'))) : null,
        ]);
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'roles.required' => 'Выберите хотя бы одну роль.',
            'roles.min' => 'Выберите хотя бы одну роль.',
            'color.required' => 'Выберите цвет: он нужен инструктору для календаря.',
        ];
    }

    /**
     * Columns of the `users` table filled from the request. Only instructors keep a calendar colour.
     *
     * @return array<string, mixed>
     */
    public function userAttributes(): array
    {
        return [
            ...Arr::except($this->validated(), ['password', 'password_confirmation']),
            'color' => $this->hasInstructorRole() ? $this->validated('color') : null,
        ];
    }

    private function hasInstructorRole(): bool
    {
        return in_array(Role::Instructor->value, (array) $this->input('roles', []), true);
    }
}
