<?php

namespace App\Http\Requests\Instructors;

use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;

/**
 * Editing an instructor. The password is optional: an empty field keeps the old one.
 * The role is not editable here, so a submitted role is ignored.
 */
class UpdateInstructorRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->instructor());
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', Rule::unique(User::class)->ignore($this->instructor())],
            'phone' => ['nullable', 'string', 'max:32'],
            'color' => ['required', 'string', 'regex:/^#[0-9a-f]{6}$/'],
            'is_active' => ['boolean'],
            'notes' => ['nullable', 'string', 'max:2000'],
            'password' => ['nullable', 'confirmed', Password::defaults()],
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'email' => mb_strtolower(trim((string) $this->input('email'))),
            'color' => mb_strtolower(trim((string) $this->input('color'))),
        ]);
    }

    private function instructor(): User
    {
        return $this->route('instructor');
    }
}
