<?php

namespace App\Http\Requests\Events;

use App\Enums\EventStatus;
use App\Models\Event;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;

/**
 * Editing sends the whole event, including moving and resizing it in the calendar.
 * The capacity cannot be set below the number of places already taken.
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

    /**
     * @return array<int, callable(Validator): void>
     */
    public function after(): array
    {
        return [
            ...parent::after(),
            function (Validator $validator): void {
                if ($validator->errors()->has('capacity') || ! $this->filled('capacity')) {
                    return;
                }

                $occupied = $this->editedEvent()->occupiedPlaces();

                if ($this->integer('capacity') < $occupied) {
                    $validator->errors()->add('capacity', "На занятие уже записано клиентов: {$occupied}. Лимит мест не может быть меньше.");
                }
            },
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
