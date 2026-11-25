<?php

namespace App\Http\Requests\Clients;

use App\Models\ClientStatus;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Changing only the training status of a client, from the client list.
 * The status can be cleared, or set to a visible one or to the one the client already has.
 */
class UpdateClientStatusRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->route('client'));
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'client_status_id' => ['present', 'nullable', 'integer', Rule::in($this->selectableStatusIds())],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'client_status_id.in' => 'Этот статус нельзя выбрать: его скрыли или удалили.',
        ];
    }

    /**
     * @return array<string, string>
     */
    public function attributes(): array
    {
        return ['client_status_id' => 'Статус'];
    }

    /**
     * @return list<int>
     */
    private function selectableStatusIds(): array
    {
        return ClientStatus::query()->active()->pluck('id')
            ->push($this->route('client')->client_status_id)
            ->filter()->unique()->values()->all();
    }
}
