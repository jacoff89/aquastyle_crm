<?php

namespace App\Http\Requests\Events;

use App\Enums\AttendanceStatus;
use App\Models\Exercise;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Sets a client's status on the event and, when `notes` or `exercise_ids` are sent, the note
 * and the exercises on the booking. Only active exercises of the event's type (or of its parent)
 * can be newly attached; an exercise already on the booking can be kept even if it is hidden
 * or not offered for the type any more.
 * Whether the person may record who came is checked in the controller, because it depends
 * on the status the client is moved from and to.
 */
class UpdateEventClientRequest extends FormRequest
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
            'status' => ['required', Rule::enum(AttendanceStatus::class)],
            'notes' => ['nullable', 'string', 'max:2000'],
            'exercise_ids' => ['sometimes', 'array'],
            'exercise_ids.*' => ['integer', 'distinct', Rule::in($this->allowedExerciseIds())],
        ];
    }

    public function status(): AttendanceStatus
    {
        return $this->enum('status', AttendanceStatus::class);
    }

    /**
     * What to change on the booking; the note is touched only when the request has one.
     *
     * @return array{status: AttendanceStatus, notes?: ?string, exercise_ids?: list<int>}
     */
    public function changes(): array
    {
        return [
            'status' => $this->status(),
            ...($this->exists('notes') ? ['notes' => $this->validated('notes')] : []),
            ...($this->exists('exercise_ids') ? ['exercise_ids' => array_map('intval', $this->validated('exercise_ids', []))] : []),
        ];
    }

    /**
     * The exercises offered for the event and the ones already on the booking.
     *
     * @return list<int>
     */
    private function allowedExerciseIds(): array
    {
        $event = $this->route('event');

        $offered = Exercise::query()->active()->forEventType($event->type)->pluck('id')->all();
        $attached = $event->bookings()
            ->where('client_id', $this->route('client')->getKey())
            ->first()?->exercises()->pluck('exercises.id')->all() ?? [];

        return array_values(array_unique([...$offered, ...$attached]));
    }
}
