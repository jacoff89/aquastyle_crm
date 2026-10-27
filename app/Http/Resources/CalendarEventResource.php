<?php

namespace App\Http\Resources;

use App\Enums\EventStatus;
use App\Enums\InstructorRole;
use App\Http\Requests\Events\EventRequest;
use App\Models\Event;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * An event as the calendar shows and edits it. Expects `type` and `instructors` to be loaded.
 *
 * `isMine` tells whether the current user takes part in the event, as lead or assistant:
 * everyone sees the whole calendar, and the user's own events are marked in it.
 *
 * @mixin Event
 */
class CalendarEventResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $lead = $this->leadInstructor();

        return [
            'id' => $this->id,
            'title' => $this->displayTitle(),
            'customTitle' => $this->title,
            'eventTypeId' => $this->event_type_id,
            'typeName' => $this->type?->name,
            'start' => $this->starts_at->format(EventRequest::DATETIME_FORMAT),
            'end' => $this->ends_at->format(EventRequest::DATETIME_FORMAT),
            'location' => $this->location,
            'capacity' => $this->capacity,
            'status' => $this->status->value,
            'statusLabel' => $this->status->label(),
            'isCancelled' => $this->status === EventStatus::Cancelled,
            'notes' => $this->notes,
            'color' => $lead?->color,
            'leadInstructorId' => $lead?->id,
            'assistantIds' => $this->instructors
                ->filter(fn (User $instructor): bool => $instructor->pivot->role === InstructorRole::Assistant)
                ->pluck('id')
                ->values(),
            'instructors' => $this->instructors
                ->sortBy(fn (User $instructor): string => ($instructor->pivot->role === InstructorRole::Lead ? '0' : '1').$instructor->name)
                ->map(fn (User $instructor): array => [
                    'id' => $instructor->id,
                    'name' => $instructor->name,
                    'color' => $instructor->color,
                    'role' => $instructor->pivot->role->value,
                    'roleLabel' => $instructor->pivot->role->label(),
                ])
                ->values(),
            'isMine' => $this->instructors->contains('id', $request->user()?->id),
            'canUpdate' => $request->user()?->can('update', $this->resource) ?? false,
        ];
    }
}
