<?php

namespace App\Http\Requests\Clients;

use App\Models\Certification;
use App\Models\Client;
use App\Models\ClientStatus;
use App\Rules\ValidPhone;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;

/**
 * Fields shared by adding and editing a client. The last name and first name are
 * always required; the phone is required unless the client has a parent. A phone that already belongs to another client is
 * accepted only when `confirm_duplicate` is sent, i.e. after the person
 * was shown the existing card and said it is a different client.
 *
 * A hidden status or certification can not be newly chosen, but the client keeps the ones
 * they already have. `certification_ids`, when sent, replaces the whole list; the calendar
 * adds a client without it.
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
            'phone' => [Rule::requiredIf(! $this->filled('parent_id')), 'nullable', 'string', 'max:32', new ValidPhone],
            'email' => ['nullable', 'string', 'lowercase', 'email', 'max:255'],
            'birth_date' => ['nullable', 'date_format:Y-m-d', 'after:1900-01-01', 'before_or_equal:today'],
            'notes' => ['nullable', 'string', 'max:2000'],
            'client_status_id' => ['nullable', 'integer', Rule::in($this->selectableStatusIds())],
            'certification_ids' => ['sometimes', 'array'],
            'certification_ids.*' => ['integer', 'distinct', Rule::in($this->selectableCertificationIds())],
            'confirm_duplicate' => ['boolean'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'client_status_id.in' => 'Этот статус нельзя выбрать: его скрыли или удалили.',
            'certification_ids.*.in' => 'Одну из сертификаций нельзя выбрать: её скрыли или удалили.',
        ];
    }

    /**
     * @return array<string, string>
     */
    public function attributes(): array
    {
        return [
            'client_status_id' => 'Статус',
            'certification_ids' => 'Сертификации',
            'certification_ids.*' => 'Сертификация',
        ];
    }

    /**
     * @return list<int>
     */
    public function certificationIds(): array
    {
        return array_map('intval', $this->validated('certification_ids', []));
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
     * The statuses that can be chosen: the visible ones and the one the client already has.
     *
     * @return list<int>
     */
    private function selectableStatusIds(): array
    {
        return ClientStatus::query()->active()->pluck('id')
            ->push($this->ignoredClient()?->client_status_id)
            ->filter()->unique()->values()->all();
    }

    /**
     * The certifications that can be given: the visible ones and those the client already holds.
     *
     * @return list<int>
     */
    private function selectableCertificationIds(): array
    {
        return Certification::query()->active()->pluck('id')
            ->merge($this->ignoredClient()?->certifications()->pluck('certifications.id') ?? [])
            ->unique()->values()->all();
    }

    /**
     * The client being edited, which does not count as a duplicate of itself.
     */
    protected function ignoredClient(): ?Client
    {
        return null;
    }
}
