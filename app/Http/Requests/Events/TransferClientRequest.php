<?php

namespace App\Http\Requests\Events;

use App\Models\Event;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Moves the client from the route to another event. Here only the right to move clients
 * out of the event is checked; the right to put them on the chosen event is checked in the
 * controller, once the event is known to exist. Whether the event takes the client is up to
 * the TransferClientToEvent action.
 */
class TransferClientRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('transferClientsFrom', $this->route('event'));
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'target_event_id' => ['required', 'integer', Rule::exists(Event::class, 'id')],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'target_event_id.required' => 'Выберите занятие.',
            'target_event_id.exists' => 'Занятие не найдено.',
        ];
    }

    public function targetEvent(): Event
    {
        return Event::query()->findOrFail($this->integer('target_event_id'));
    }
}
