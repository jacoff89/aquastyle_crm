<?php

namespace App\Http\Requests\Events;

use App\Enums\AttendanceStatus;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Sets a client's status on the event and, when `notes` is sent, the note on the booking.
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
        ];
    }

    public function status(): AttendanceStatus
    {
        return $this->enum('status', AttendanceStatus::class);
    }

    /**
     * What to change on the booking; the note is touched only when the request has one.
     *
     * @return array{status: AttendanceStatus, notes?: ?string}
     */
    public function changes(): array
    {
        return [
            'status' => $this->status(),
            ...($this->exists('notes') ? ['notes' => $this->validated('notes')] : []),
        ];
    }
}
