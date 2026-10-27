<?php

namespace App\Http\Requests\Settings;

use App\Enums\Role;
use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;
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
            'role' => ['required', Rule::enum(Role::class)],
            'is_active' => ['boolean'],
            'notes' => ['nullable', 'string', 'max:2000'],
            'password' => ['nullable', 'confirmed', Password::defaults()],
        ];
    }

    /**
     * An administrator can't lock themselves out by changing their own role
     * or deactivating their own account.
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

                if ($this->input('role') !== $this->user()->role->value) {
                    $validator->errors()->add('role', 'Свою роль изменить нельзя.');
                }

                if (! $this->boolean('is_active')) {
                    $validator->errors()->add('is_active', 'Свою учётную запись отключить нельзя.');
                }
            },
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge(['email' => mb_strtolower(trim((string) $this->input('email')))]);
    }

    private function editedUser(): User
    {
        return $this->route('user');
    }
}
