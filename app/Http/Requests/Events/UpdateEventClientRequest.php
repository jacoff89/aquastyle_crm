<?php

namespace App\Http\Requests\Events;

use App\Enums\AttendanceStatus;
use App\Models\Exercise;
use Illuminate\Database\Query\Builder;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Sets a client's status on the event and, when `notes` or `exercise_ids` are sent, the note
 * and the exercises on the booking. A hidden exercise can be kept but not newly attached.
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
            'exercise_ids.*' => ['integer', 'distinct', Rule::exists(Exercise::class, 'id')->where(
                fn (Builder $query) => $query->where('is_active', true)->orWhereIn('id', $this->attachedExerciseIds()),
            )],
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
     * @return list<int>
     */
    private function attachedExerciseIds(): array
    {
        return $this->route('event')->bookings()
            ->where('client_id', $this->route('client')->getKey())
            ->first()?->exercises()->pluck('exercises.id')->all() ?? [];
    }
}
