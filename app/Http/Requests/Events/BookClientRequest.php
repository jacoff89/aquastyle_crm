<?php

namespace App\Http\Requests\Events;

use App\Models\Client;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Books an existing client on the event from the route. A client who is already in
 * the list, a full event and a cancelled event are refused by the BookClientOnEvent action.
 */
class BookClientRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('manageClients', $this->route('event'));
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'client_id' => ['required', 'integer', Rule::exists(Client::class, 'id')->withoutTrashed()],
            'notes' => ['nullable', 'string', 'max:2000'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'client_id.required' => 'Выберите клиента.',
            'client_id.exists' => 'Клиент не найден или удалён.',
        ];
    }

    public function client(): Client
    {
        return Client::query()->findOrFail($this->integer('client_id'));
    }
}
