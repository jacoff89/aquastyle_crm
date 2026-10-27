<?php

namespace App\Http\Requests\Events;

use App\Enums\EventStatus;
use App\Models\Event;
use Illuminate\Validation\Rule;

/**
 * Editing sends the whole event, including moving and resizing it in the calendar.
 */
class UpdateEventRequest extends EventRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->editedEvent());
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            ...parent::rules(),
            'status' => ['required', Rule::enum(EventStatus::class)],
        ];
    }

    public function status(): EventStatus
    {
        return $this->enum('status', EventStatus::class);
    }

    protected function editedEvent(): Event
    {
        return $this->route('event');
    }
}
