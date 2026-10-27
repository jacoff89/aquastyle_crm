<?php

namespace App\Http\Requests\Clients;

use App\Models\Client;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Validator;

/**
 * Fields shared by adding and editing a client. Only the last name, first name
 * and phone are required. A phone that already belongs to another client is
 * accepted only when `confirm_duplicate` is sent, i.e. after the person
 * was shown the existing card and said it is a different client.
 */
abstract class ClientRequest extends FormRequest
{
    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'last_name' => ['required', 'string', 'max:100'],
            'first_name' => ['required', 'string', 'max:100'],
            'middle_name' => ['nullable', 'string', 'max:100'],
            'phone' => ['required', 'string', 'max:32', 'regex:/^\+?[0-9\s().\-]+$/'],
            'email' => ['nullable', 'string', 'lowercase', 'email', 'max:255'],
            'birth_date' => ['nullable', 'date_format:Y-m-d', 'after:1900-01-01', 'before_or_equal:today'],
            'notes' => ['nullable', 'string', 'max:2000'],
            'confirm_duplicate' => ['boolean'],
        ];
    }

    /**
     * @return array<int, callable(Validator): void>
     */
    public function after(): array
    {
        return [
            function (Validator $validator): void {
                if ($validator->errors()->has('phone')) {
                    return;
                }

                $digits = Client::normalizePhone($this->string('phone')->toString());

                if (strlen($digits) < 7 || strlen($digits) > 15) {
                    $validator->errors()->add('phone', 'Телефон должен содержать от 7 до 15 цифр.');

                    return;
                }

                if ($this->boolean('confirm_duplicate')) {
                    return;
                }

                $duplicates = Client::query()->samePhoneAs($this->string('phone')->toString());

                if ($this->ignoredClient() !== null) {
                    $duplicates->whereKeyNot($this->ignoredClient()->getKey());
                }

                if ($duplicates->exists()) {
                    $validator->errors()->add('phone', 'Клиент с таким телефоном уже есть. Проверьте, что это не дубль.');
                }
            },
        ];
    }

    protected function prepareForValidation(): void
    {
        if (filled($this->input('email'))) {
            $this->merge(['email' => mb_strtolower(trim((string) $this->input('email')))]);
        }
    }

    /**
     * The client being edited, which does not count as a duplicate of itself.
     */
    protected function ignoredClient(): ?Client
    {
        return null;
    }
}
