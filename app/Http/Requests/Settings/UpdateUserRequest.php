<?php

namespace App\Http\Requests\Settings;

use App\Enums\Role;
use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Arr;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\Validator;

/**
 * Editing an account. The password is optional: an empty field keeps the old one.
 */
class UpdateUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->editedUser());
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', Rule::unique(User::class)->ignore($this->editedUser())],
            'phone' => ['nullable', 'string', 'max:32'],
            'roles' => ['required', 'array', 'min:1'],
            'roles.*' => ['distinct', Rule::enum(Role::class)],
            'color' => [Rule::requiredIf($this->hasInstructorRole()), 'nullable', 'string', 'regex:/^#[0-9a-f]{6}$/'],
            'is_active' => ['boolean'],
            'notes' => ['nullable', 'string', 'max:2000'],
            'password' => ['nullable', 'confirmed', Password::defaults()],
        ];
    }

    /**
     * An administrator can't lock themselves out by giving up their own administrator role
     * or deactivating their own account. Taking on the instructor role is fine.
     *
     * @return array<int, callable(Validator): void>
     */
    public function after(): array
    {
        return [
            function (Validator $validator): void {
                if (! $this->user()->is($this->editedUser())) {
                    return;
                }

                if (! in_array(Role::Admin->value, (array) $this->input('roles', []), true)) {
                    $validator->errors()->add('roles', 'Свою роль администратора снять нельзя.');
                }

                if (! $this->boolean('is_active')) {
                    $validator->errors()->add('is_active', 'Свою учётную запись отключить нельзя.');
                }
            },
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

    private function editedUser(): User
    {
        return $this->route('user');
    }
}
