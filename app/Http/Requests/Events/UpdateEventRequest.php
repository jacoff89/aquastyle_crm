<?php

namespace App\Http\Requests\Events;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Models\Event;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;

/**
 * Editing sends the whole event, including moving and resizing it in the calendar.
 * The capacity cannot be set below the number of places already taken. An event can be
 * marked done only once every client's attendance is marked: none is left as booked.
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
            function (Validator $validator): void {
                if ($validator->errors()->has('status') || ! $this->isBeingMarkedDone()) {
                    return;
                }

                $unmarked = $this->editedEvent()->bookings()->where('status', AttendanceStatus::Booked->value)->count();

                if ($unmarked > 0) {
                    $validator->errors()->add('status', "Посещение не отмечено у клиентов: {$unmarked}. Отметьте, пришли они или нет, прежде чем отмечать занятие проведённым.");
                }
            },
        ];
    }

    public function status(): EventStatus
    {
        return $this->enum('status', EventStatus::class);
    }

    /**
     * Whether the edit turns an event that was not done yet into a done one. An event
     * already done can still be edited without checking its clients again.
     */
    private function isBeingMarkedDone(): bool
    {
        return $this->status() === EventStatus::Done && $this->editedEvent()->status !== EventStatus::Done;
    }

    protected function editedEvent(): Event
    {
        return $this->route('event');
    }
}
