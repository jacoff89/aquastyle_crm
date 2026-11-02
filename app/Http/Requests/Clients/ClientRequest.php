<?php

namespace App\Http\Requests\Clients;

use App\Models\Client;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;

/**
 * Fields shared by adding and editing a client. The last name and first name are
 * always required; the phone is required unless the client has a parent. A phone that already belongs to another client is
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
            'parent_id' => ['nullable', 'integer', Rule::exists('clients', 'id')->whereNull('parent_id')->whereNull('deleted_at'), Rule::notIn([$this->ignoredClient()?->getKey()])],
            'phone' => [Rule::requiredIf(! $this->filled('parent_id')), 'nullable', 'string', 'max:32', 'regex:/^\+?[0-9\s().\-]+$/'],
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
                if ($this->filled('parent_id') && $this->hasChildren()) {
                    $validator->errors()->add('parent_id', 'У клиента есть дочерние клиенты, поэтому он сам не может быть дочерним.');
                }

                if ($validator->errors()->has('phone') || ! $this->filled('phone')) {
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
     * A client who has children cannot become a child themselves.
     */
    protected function hasChildren(): bool
    {
        return $this->ignoredClient()?->children()->exists() ?? false;
    }

    /**
     * The client being edited, which does not count as a duplicate of itself.
     */
    protected function ignoredClient(): ?Client
    {
        return null;
    }
}
